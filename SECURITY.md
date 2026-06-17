# SITBank Security Operations

## Reporting

Do not open a public issue containing credentials, personal data, exploit
details, session identifiers, or production logs. Notify the repository owner
and deployment administrator privately, preserve timestamps and affected
commit/digest identifiers, and record the response in the project security
log.

## Secret Rotation

1. Revoke the exposed credential at its source.
2. Create a replacement using a cryptographically secure generator.
3. Install it into the appropriate root-owned environment directory:
   `/etc/sitbank/secrets` for production or
   `/etc/sitbank-staging/secrets` for staging.
4. Restart through the restricted deployment/runtime command and run
   `production-check`.
5. Revoke active sessions when rotating session-signing, Flask, CSRF, MFA
   encryption, database, or Redis credentials as required by the incident.
6. Remove the secret from Git history with a coordinated history rewrite when
   it was pushed. Treat the old value as compromised even after cleanup.

Session HMAC rotation must keep the old key in
`session_hmac_keys_json` only for the approved overlap period, set the new
`SESSION_HMAC_ACTIVE_KEY_ID`, then remove the previous key after all sessions
signed by it have expired.

MFA/TOTP seed encryption uses envelope encryption. Keep old KEKs in
`mfa_kek_keys_json` until `rewrap-mfa-deks` or `rotate-mfa-encryption` has
removed their use from stored records, then update `MFA_KEK_ACTIVE_ID` and the
root-managed keyring together. `MFA_AES256_GCM_KEY_B64` is retained for legacy
record decryption and must not be removed until production checks and rotation
reports confirm no legacy records remain.

Redis session payloads are HMAC-wrapped with the session HMAC keyring before
they are written to Redis. Tamper failures, missing signatures, unknown key
IDs, malformed payloads, or unsupported legacy formats are logged as
`session_integrity` security events and force a fresh unauthenticated session.
Do not log or paste raw Redis session values during investigation.

PostgreSQL uses separate `sitbank_owner` and `sitbank_app` roles in staging
and production. `sitbank_owner` is only for Alembic migrations and ownership;
`sitbank_app` is the Flask runtime role and must not own schema objects or have
DDL privileges. Rotate `database_url` and `database_migration_url` separately.

Staging secrets must never be copied from production. The staging deployment
wrapper rejects identical application secret files when production secrets are
present and requires database and Redis URLs to resolve only to the staging
Compose service names.

## Dependency Response

Dependabot pull requests are never auto-merged. Review release notes and
transitive changes, update the reviewed manifest, regenerate the applicable
hash-locked files, and require the full test, SAST, dependency review,
container smoke, Compose validation, and image scan checks. Full authenticated
DAST is intentionally reserved for scheduled scans and release verification;
ordinary pull requests skip it to keep feedback timely without weakening the
release gate.

Critical advisories require immediate triage. High advisories require an owner
and target date. A runtime upgrade is kept separate from ordinary package
updates.

## Vulnerability Exceptions

An exception must be approved in the pull request and record:

- package, image component, CVE or alert identifier, and affected digest;
- why exploitation is not currently reachable or why no safe fix exists;
- compensating controls and monitoring;
- accountable owner;
- approval date and an expiry no more than 30 days later.

Expired exceptions block release. Critical image vulnerabilities are not
ignored by default, including vulnerabilities without a vendor fix.

The temporary `.trivyignore` exception for `CVE-2026-42496` and
`CVE-2026-8376` applies only to inherited Debian Trixie `perl-base` findings
from the official `python:3.12.13-slim-trixie` base image. The application does
not install or invoke Perl and does not process attacker-controlled tar
archives with Perl. `perl-base` is an essential Debian package, so removal or
mixing sid packages into Trixie is not an approved mitigation. Review and
remove this exception by 2026-06-26, or sooner when Debian or the official
Python image publishes a fixed package or fixed digest. The full Critical
Trivy report and the fixable High/Critical gate must continue to run without
that ignore file.

## Deployment and Rollback

Only a protected `main` workflow may produce a trusted production signature.
Manual staging also runs the trusted workflow from `main`; its `source_ref`
input is resolved to an immutable candidate commit without executing
feature-branch workflow or deployment scripts with environment secrets.
Staging and production both trust only the exact `refs/heads/main` workflow
identity. The tested, scanned, signed, and deployed image digest must be
identical. Deployment accepts only the configured GHCR repository, exact
workflow identity, a 40-character candidate commit SHA, and an immutable
SHA-256 digest.

Root-owned EC2 deployment files are refreshed only through the manual
`bootstrap-ec2.yml` workflow selected from protected `main`. Its archive is
bound to `github.workflow_sha`, signed with GitHub OIDC, uploaded with strict
SSH host-key verification, and verified by the restricted root bootstrap
wrapper against the exact
`bootstrap-ec2.yml@refs/heads/main` certificate identity. The deploy account
has no general sudo or Docker access. Environment approval and separate
staging/production SSH credentials remain mandatory. This workflow installs
deployment files only; it cannot publish or deploy an application image.

Production deployment is automatic on a protected `main` push only. It must
not run unless staging succeeded in the same workflow; disabled, skipped, or
failed staging blocks production.

Migrations must remain backward-compatible with the previous image. If
readiness fails, the wrapper restores the previous digest and non-secret
configuration. Database rollback follows the documented cutover procedure and
must not be improvised during an incident.

## Production Edge and WAF Checklist

Before exposing production, the administrator must verify the edge/network
controls below. Some controls are represented by repository files; Cloudflare
or AWS WAF and security-group settings remain infrastructure state and must be
checked manually.

- Run production bootstrap from reviewed `main` so it installs
  `ops/nginx/sitbank-production.conf`,
  `ops/nginx/sitbank-production-rate-limits.conf`, and
  `ops/nginx-proxy-headers.conf`, validates Nginx, and reloads only after
  `nginx -t` succeeds.
- Issue production Certbot files under
  `/etc/letsencrypt/live/sitbank.duckdns.org/` before bootstrap.
- Allow public inbound TCP `80` and `443` only.
- Restrict SSH to an administrator IP allowlist, AWS Systems Manager, a
  bastion, or VPN; never allow TCP `22` from `0.0.0.0/0` or `::/0`.
- Do not expose Gunicorn, PostgreSQL, or Redis directly to the internet.
- Keep Gunicorn bound to `127.0.0.1:5000` and keep `compose.prod.yml` free of
  published app ports.
- Restrict `/health/ready` to loopback and allow public `/health/live` only.
- Enable WAF managed common, SQL injection, XSS, bot, and protocol anomaly
  rules.
- Add WAF rate-based rules for `/login`, `/register`, `/mfa/verify`,
  `/auth/`, `/auth/webauthn/`, `/password/`, `/sessions/`, `/security-keys/`,
  `/profile`, and `/account/`.
- Block TRACE at the edge and preserve only the expected proxy headers:
  `Host`, `X-Real-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto`.
- If a CDN or WAF forwards traffic to Nginx, configure the trusted real-client
  IP source ranges deliberately before basing rate limits on client IPs.

Verification commands:

```bash
sudo nginx -t
sudo ss -ltnp | grep -E ':(80|443|5000)([[:space:]]|$)'
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-app
sudo docker inspect --format '{{json .HostConfig.PortBindings}}' sitbank-app
curl --fail https://sitbank.duckdns.org/health/live
curl -I https://sitbank.duckdns.org/health/ready
curl --fail -H 'X-Forwarded-Proto: https' \
  http://127.0.0.1:5000/health/ready
```

Expected results: only `80` and `443` are publicly reachable, Gunicorn is
loopback-only, Docker publishes no app ports, external readiness is denied,
and local readiness succeeds.

## Monitoring

Forward these sources to a protected centralized log destination:

- journald events tagged `sitbank-deploy`;
- `sitbank-container.service` and Docker container logs;
- Nginx access/error and TLS events;
- application security audit events;
- PostgreSQL and Redis authentication/availability events.

Alert on failed deployments, signature or revision mismatches, unexpected
image digests, repeated authentication lockouts, security-key counter
anomalies, and changes to root-managed secret or FIDO policy files.

## AWS OIDC and Systems Manager

The current restricted SSH deployment remains supported. The preferred next
step is GitHub OIDC federation to a narrowly scoped AWS IAM role and Systems
Manager Run Command:

- trust only `repo:WenJiangggg/SITBank:environment:production`;
- require the GitHub OIDC audience `sts.amazonaws.com`;
- allow commands only on the tagged SITBank instance and approved SSM
  document;
- do not grant general EC2, IAM, Secrets Manager, or S3 administration;
- retain the same root deployment wrapper, Cosign checks, and environment
  approval.

Remove the Base64-encoded EC2 SSH private-key secrets only after the OIDC/SSM
path has passed rollback and incident-response testing.
