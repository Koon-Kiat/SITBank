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
5. Revoke active sessions when rotating session-signing, session-lookup HMAC,
   Flask, CSRF, MFA KEK, or database credentials as required by the incident.
6. Remove the secret from Git history with a coordinated history rewrite when
   it was pushed. Treat the old value as compromised even after cleanup.

Session HMAC rotation must keep the old key in
`session_hmac_keys_json` only for the approved overlap period, set the new
`SESSION_HMAC_ACTIVE_KEY_ID`, then remove the previous key after all sessions
signed by it have expired.

MFA/TOTP seed encryption uses envelope encryption only. Keep old KEKs in
`mfa_kek_keys_json` until `rewrap-mfa-deks` has removed their use from stored
records, then update `MFA_KEK_ACTIVE_ID` and the root-managed keyring together.
Non-envelope legacy MFA ciphertext is unsupported and fails closed.

Database session payloads are HMAC-wrapped with the session HMAC keyring before
they are written to PostgreSQL. Browser cookies carry only opaque session IDs;
database lookup hashes are HMAC-derived with `SESSION_LOOKUP_HMAC_KEY` or
`ADMIN_SESSION_LOOKUP_HMAC_KEY`. Tamper failures, missing signatures, unknown
key IDs, malformed payloads, or unsupported legacy formats are logged as
`session_integrity` security events and force a fresh unauthenticated session.
Do not log or paste raw session IDs or stored session payloads during
investigation.

PostgreSQL uses separate `sitbank_owner` and `sitbank_app` roles in staging
and production. `sitbank_owner` is only for Alembic migrations and ownership;
`sitbank_app` is the Flask runtime role and must not own schema objects or have
DDL privileges. The runtime role keeps `SELECT` and `INSERT` on
`security_audit_events`, but `UPDATE` and `DELETE` are revoked after migrations
so audit records are append-only to the running app. Rotate `database_url` and
`database_migration_url` separately.

Production admin runtime uses a separate Flask app, Docker Compose service,
session cookie, session-signing material, session-lookup HMAC key, and database
runtime role. The admin role must be distinct from both `sitbank_app` and
`sitbank_owner`; it must not use migration/schema-owner credentials. Admin MFA,
administrator step-up, VPN, Tailscale, WireGuard, and administrator IP allowlist
setup are Phase 2 items pending an approved design. Until those controls exist,
`admin-sitbank.duckdns.org` is fail-closed at Nginx with `deny all` and the
Flask admin login route returns failure without creating a session.

Staging secrets must never be copied from production. The staging deployment
wrapper rejects identical application secret files when production secrets are
present and requires runtime database URLs to resolve only to the staging
Compose service name. Customer and admin session lookup HMAC keys must be
distinct.

## Audit Logs

Security audit events are written to `security_audit_events` and emitted as
sanitized structured application log lines for container and journald
forwarding. Audit records must capture who, what, where, and when without
storing plaintext passwords, TOTP codes, CSRF tokens, legacy WebAuthn challenge
material, private keys, bearer tokens, MFA secrets, ciphertext, nonces, raw
session payloads, raw session IDs, raw attempted login identifiers, or full
account numbers.

New audit rows are chained with `previous_event_hash`, `event_hash`, and
`hash_algorithm` using deterministic canonical JSON over stable audit fields.
The current hash chain uses keyed stdlib HMAC-SHA256 (`hmac-sha256-v1`) with
`SECURITY_AUDIT_HMAC_KEY`, which is a production secret file and is not stored
in the database. Legacy `sha256-v1` rows remain verifiable so existing audit
history can be read. Operators must protect and rotate the audit HMAC key under
change control, then verify the chain and export anchors on a schedule:

```bash
python -m flask --app wsgi:app verify-audit-log-chain
python -m flask --app wsgi:app verify-audit-log-chain --anchor /var/lib/sitbank/security-audit.anchor
python -m flask --app wsgi:app export-audit-log-anchor
```

Ship the sanitized anchor JSON to immutable storage, WORM object storage,
signed release artifacts, or a separate SIEM/log archive. Production must set
`SECURITY_AUDIT_ANCHOR_PATH=/var/lib/sitbank/security-audit.anchor` for the
one-EC2 deployment. `verify-audit-log-chain` and `check-security-alerts` verify
the audit hash chain against the configured anchor automatically; missing,
unsafe, unreadable, or mismatched anchors fail closed or emit critical alerts.
Do not store real cloud credentials, webhook URLs, signing keys, or audit
anchors in the repository.

Retain security audit records for 7 years. Do not silently auto-delete audit
records from application code or scheduled jobs. Disposal after the retention
period requires an operator-reviewed change record, a scoped deletion approved
by the deployment administrator, and a retained summary of the deleted date
range and approval. Keep Docker `local` log rotation in Compose and forward
application audit logs to protected centralized storage before host-local logs
rotate out.

After each migration, run the runtime privilege commands through the deployment
wrapper or migration container:

```bash
python -m flask --app wsgi:app apply-runtime-db-privileges
python -m flask --app wsgi:app verify-runtime-db-privileges
```

The expected result is that `sitbank_app` can insert and select audit rows but
cannot update, delete, or truncate rows from `security_audit_events`.
PostgreSQL also installs append-only triggers that reject `UPDATE`, `DELETE`,
and `TRUNCATE` with SQLSTATE `42501`, so owner-role verification detects
missing trigger protection before runtime privilege checks pass.

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
- Issue admin Certbot files under
  `/etc/letsencrypt/live/admin-sitbank.duckdns.org/` before bootstrap.
- Allow public inbound TCP `80` and `443` only.
- Restrict SSH to an administrator IP allowlist, AWS Systems Manager, a
  bastion, or VPN; never allow TCP `22` from `0.0.0.0/0` or `::/0`.
- Do not expose Gunicorn or PostgreSQL directly to the internet.
- Keep customer Gunicorn bound to `127.0.0.1:5000`, admin Gunicorn bound to
  `127.0.0.1:5002`, and keep `compose.prod.yml` free of published app ports.
- Restrict `/health/ready` to loopback and allow public `/health/live` only.
- Keep admin routes denied by default. Do not make
  `admin-sitbank.duckdns.org` usable until a reviewed admin MFA design and VPN
  or explicit IP allowlist controls are implemented.
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
sudo ss -ltnp | grep -E ':(80|443|5000|5002)([[:space:]]|$)'
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-app
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-admin
sudo docker inspect --format '{{json .HostConfig.PortBindings}}' sitbank-app
sudo docker inspect --format '{{json .HostConfig.PortBindings}}' sitbank-admin
curl --fail https://sitbank.duckdns.org/health/live
curl -I https://sitbank.duckdns.org/health/ready
curl -I https://admin-sitbank.duckdns.org/login
curl --fail -H 'X-Forwarded-Proto: https' \
  http://127.0.0.1:5000/health/ready
curl --fail -H 'Host: admin-sitbank.duckdns.org' \
  -H 'X-Forwarded-Proto: https' \
  http://127.0.0.1:5002/health/ready
```

Expected results: only `80` and `443` are publicly reachable, Gunicorn is
loopback-only on `5000` and `5002`, Docker publishes no app ports, external
customer readiness is denied, admin routes are denied, and local readiness
succeeds.
In short, external readiness is denied.

## Monitoring

Forward these sources to a protected centralized log destination:

- journald events tagged `sitbank-deploy`;
- `sitbank-container.service` and Docker container logs;
- `sitbank-admin` container logs after the admin boundary is enabled;
- Nginx access/error and TLS events;
- application security audit events;
- PostgreSQL authentication/availability events.

Operator verification commands:

```bash
psql "$DATABASE_MIGRATION_URL" --no-psqlrc --command \
  "SELECT event_type, outcome, count(*) FROM security_audit_events GROUP BY 1,2 ORDER BY 3 DESC LIMIT 20;"
psql "$DATABASE_MIGRATION_URL" --no-psqlrc --command \
  "SELECT created_at, ip_address, event_metadata->>'principal_ref' AS principal_ref FROM security_audit_events WHERE event_type = 'login' AND outcome = 'failure' ORDER BY created_at DESC LIMIT 20;"
psql "$DATABASE_MIGRATION_URL" --no-psqlrc --command \
  "SELECT created_at, user_id, event_metadata->>'reason' AS reason FROM security_audit_events WHERE event_type = 'account_lock' ORDER BY created_at DESC LIMIT 20;"
psql "$DATABASE_MIGRATION_URL" --no-psqlrc --command \
  "SELECT created_at, user_id, event_metadata->>'credential_id' AS credential_ref FROM security_audit_events WHERE event_type = 'webauthn_clone_detected' ORDER BY created_at DESC LIMIT 20;"
psql "$DATABASE_MIGRATION_URL" --no-psqlrc --command \
  "SELECT created_at, ip_address, session_ref, event_metadata->>'reason' AS reason FROM security_audit_events WHERE event_type = 'session_integrity' AND outcome = 'failure' ORDER BY created_at DESC LIMIT 20;"
journalctl -u sitbank-container.service --since -15m | grep security_audit_write_failed
python -m flask --app wsgi:app check-security-alerts --report-only
```

`check-security-alerts` emits sanitized JSON and returns non-zero when active
alerts are found unless `--report-only` is used. Production must keep
`SECURITY_ALERT_ENABLED=true`, set `SECURITY_ALERT_MIN_SEVERITY`, and provide
`SECURITY_ALERT_WEBHOOK_URL_FILE` as an operator-managed secret file outside the
repository. Discord incoming webhook URLs are supported directly and are sent
Discord-compatible JSON with mention parsing disabled. The webhook URL itself
is a secret and must be regenerated if exposed.
`SECURITY_ALERT_TIMEOUT_SECONDS` bounds webhook delivery, and
`SECURITY_ALERT_DEDUPE_TTL_SECONDS` uses PostgreSQL alert-dedupe state to
suppress repeated deliveries of the same alert while preserving the alert in
reports. Delivery failures are
reported by type only and must not include webhook URLs, tokens, headers,
request bodies, raw identifiers, passwords, session IDs, or full account
numbers. Immediately before webhook delivery, both generic JSON payloads and
Discord-formatted payloads pass through a final sanitizer that redacts
sensitive keys, bearer/basic credentials, session or cookie values, database URLs with
credentials, legacy Redis URLs with credentials, webhook URLs, API keys,
private-key-like values, and long token-like strings. Set
`SECURITY_ALERT_STATE_PATH=/run/state/security-alert-state.json` on the
host-mounted alert state directory so `check-security-alerts` can compare
current `users` and `security_audit_events` metrics against a baseline outside
the application database and alert on `database_table_regression` after a table
rewind or wipe. Keep `SECURITY_AUDIT_ANCHOR_PATH` set to the protected local anchor path
to make `check-security-alerts` alert on anchor mismatch, chain rewind, or tail
deletion detectable from the anchor. On mismatch, treat the database and host
as incident evidence, stop routine anchor rotation, preserve the mismatched
anchor, run `verify-audit-log-chain --anchor`, and investigate before resuming
normal deployments.

Alert immediately on any `security_audit_write_failed`, `account_lock`,
`session_integrity` failure, `audit_chain_verification_failed`,
`audit_anchor_mismatch`, `audit_append_only_protection_failed`, or
`runtime_db_privilege_verification_failed`. Password recovery monitoring also
alerts on `password_reset_token_reused`, `manual_recovery_requested`, 5 or more
password reset or manual recovery requests from one source in 10 minutes, or 3
or more reset failures from one source in 10 minutes. Alert when there are
10 or more `login` failures for the same `principal_ref` or IP in 5 minutes, 5
or more `auth_backoff` or `rate_limit` events from the same source in 10
minutes, 3 or more transaction failures for the same user/ref in 15 minutes, or
10 transaction failures globally in 15 minutes. Also alert on failed
deployments, signature or revision mismatches, unexpected image digests, and
database table regression. Historical WebAuthn/passkey alert names such as
`webauthn_clone_detected` and `password_reset_webauthn_failed` remain queryable
for legacy audit context, but active passkey ceremonies are retired because
instructor review disallowed the high-level `webauthn` library.

Production installs `sitbank-security-alerts.service` and
`sitbank-security-alerts.timer` through the EC2 bootstrap path. The timer runs
`check-security-alerts` through the container runtime wrapper every 5 minutes,
so anchor mismatch and alert delivery failures are visible without waiting for
a manual audit.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sitbank-security-alerts.timer
sudo systemctl status sitbank-security-alerts.timer
journalctl -u sitbank-security-alerts.service
```

## Customer Password Reset and Recovery

The customer-domain forgot-password flow is deliberately separate from admin
account recovery. Admin reset routes, templates, APIs, and customer-domain
fallback behavior are out of scope; admin recovery belongs only in the future
admin-sitbank domain.

Customer reset links are short-lived one-time `selector.verifier` URLs. The raw
verifier is never stored. On first use the token is atomically exchanged for a
short-lived server-side reset transaction, the browser continues at
`/reset-password/continue`, and the original URL token is no longer accepted.
The transaction is not an authenticated login session and cannot access
dashboard or banking routes.

Reset MFA policy:

- TOTP customers must verify TOTP after the reset transaction is active.
  Recovery codes are accepted only as TOTP recovery factors.
- Passkeys do not replace TOTP recovery. A legacy passkey-only account cannot
  use an email-link-only reset fallback and must complete manual customer
  recovery before password reset or MFA re-enrollment.
- No-MFA customers can set a new password but remain incomplete-security-state
  users and hit MFA onboarding on next login.
- Recovery codes are stored HMACed, shown only by trusted authenticated
  generation paths, consumed once, and do not disable MFA.
- Customers who lost password, MFA, and recovery codes can only create a
  pending manual customer recovery request. That unauthenticated request does
  not freeze, unlock, or otherwise change the account.

Production must use SMTP-backed reset email delivery with
`PASSWORD_RESET_EMAIL_BACKEND=smtp`, an HTTPS `PASSWORD_RESET_BASE_URL`,
`PASSWORD_RESET_EMAIL_FROM`, `SMTP_HOST`, `SMTP_USE_TLS=true`, and root-managed
`SMTP_USERNAME_FILE` / `SMTP_PASSWORD_FILE` secrets. Console reset email is
allowed only outside production, and plaintext SMTP delivery is rejected in
production. Security alert webhooks are never used to deliver password reset
links.

## AWS OIDC and Systems Manager

The current restricted SSH deployment remains supported. The preferred next
step is GitHub OIDC federation to a narrowly scoped AWS IAM role and Systems
Manager Run Command:

- trust only `repo:hetp88/SITBank:environment:production`;
- require the GitHub OIDC audience `sts.amazonaws.com`;
- allow commands only on the tagged SITBank instance and approved SSM
  document;
- do not grant general EC2, IAM, Secrets Manager, or S3 administration;
- retain the same root deployment wrapper, Cosign checks, and environment
  approval.

Remove the Base64-encoded EC2 SSH private-key secrets only after the OIDC/SSM
path has passed rollback and incident-response testing.
