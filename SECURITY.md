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

Production deployment is automatic on a protected `main` push only. It must
not run unless staging succeeded in the same workflow; disabled, skipped, or
failed staging blocks production.

Migrations must remain backward-compatible with the previous image. If
readiness fails, the wrapper restores the previous digest and non-secret
configuration. Database rollback follows the documented cutover procedure and
must not be improvised during an incident.

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
