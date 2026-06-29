# SITBank

Secure Internet Banking Application for O$P$ Bank.

SITBank is a student cybersecurity project and demonstration site. Do not enter real banking credentials, card numbers, phone numbers, or personal financial information.

## Overview

SITBank is a Flask/Gunicorn application deployed as hardened Docker containers behind host-managed Nginx, TLS, and PostgreSQL. Production customer traffic runs at `https://sitbank.duckdns.org`; operators use the private Tailscale Serve URL `https://admin-sitbank.tailca101b.ts.net/` with a separate admin app, browser login at `/login`, cookie, session keys, database role, manual root-admin bootstrap, root-admin-controlled staff invites, and mandatory TOTP. Staging runs separately at `https://staging-sitbank.pp.ua`.

Private admin reachability is checked only by the manual, protected
`.github/workflows/tailscale-private-admin-verify.yml` workflow and by the same
protected reusable workflow as a required gate after production deployment and
public production TLS verification. Normal PR and public TLS CI do not join
the tailnet and do not scan the private hostname.

Production bootstrap installs the non-mutating
`/usr/local/sbin/verify-tailscale-admin-access` host preflight. Operators run
it on EC2 with `--mode serve` to verify the local Tailscale state, Funnel
disablement, loopback-only admin listener, private Serve mapping, private
HTTPS entrypoint, and absence of an admin upstream in Nginx. This host evidence
complements the protected GitHub reachability gate; live tailnet policy,
device approval, and operator membership remain externally managed.

Security-critical state is stored in application-owned PostgreSQL tables. Server-side sessions, authentication failure counters, TOTP replay markers, registration OTP challenges, password-reset transactions, security-alert dedupe windows, and breached-password circuit-breaker state are stored in dedicated tables. Browser cookies keep only opaque identifiers; lookup hashes are HMAC-derived with `SESSION_LOOKUP_HMAC_KEY` or `ADMIN_SESSION_LOOKUP_HMAC_KEY`, and stored session payloads remain signed with the session HMAC keyring.

The app keeps password hashing PBKDF2+pepper only and MFA/TOTP seed encryption envelope-only using `MFA_KEK_ACTIVE_ID` plus `MFA_KEK_KEYS_JSON`. The current MFA baseline is authenticator TOTP with recovery-code support for reset flows. Legacy one-key MFA AES compatibility and direct non-PBKDF2 password hash compatibility are intentionally removed because current users are test-only and environments must be reset before this change is deployed.

Security governance, role-based ownership, review cadence, accepted-risk
handling, and stale-documentation prevention are documented in
`docs/security/security-governance.md`. Current gaps live in
`docs/security/security-gap-register.md`, and framework evidence is mapped in
`docs/security/framework-control-matrix.md`.

## Local Development

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pytest -q -n auto
.\.venv\Scripts\python.exe -m compileall app config.py wsgi.py admin_wsgi.py
```

Common local test commands:

```powershell
# Fast parallel full suite
.\.venv\Scripts\python.exe -m pytest -q -n auto

# Lower-resource parallel run
.\.venv\Scripts\python.exe -m pytest -q -n 4

# Show the slowest tests for optimization work
.\.venv\Scripts\python.exe -m pytest -q --durations=30 --durations-min=0.5

# Re-run only the last failures
.\.venv\Scripts\python.exe -m pytest -q --lf

# Focused groups
.\.venv\Scripts\python.exe -m pytest -q -m security
.\.venv\Scripts\python.exe -m pytest -q -m deployment
.\.venv\Scripts\python.exe -m pytest -q -m "not slow"
```

The `not slow` and focused marker commands are for local iteration only. Pull requests and protected CI still run the full pytest suite, including security, deployment, database session integrity, CSRF, MFA, compatibility-route regression checks, route inventory, production guard, dependency lock, and secret-scanning checks.

For a fuller local check, run `scripts/ci-local`. It runs the full pytest suite in parallel with timing output, then Python/package/security checks, Git Bash syntax checks, Docker/Compose checks when Docker is available, and contract checks around `ops/runtime_contract.py`. A Docker-less result is explicitly partial; use `scripts/ci-local --require-docker` before deployment-related changes to fail closed unless Docker/Compose validation runs.

## Required Configuration

Production/staging secrets should be installed as root-managed files and consumed with `_FILE` settings wherever possible.

Current required settings include:

- `APP_ENV`
- `SECRET_KEY` or `SECRET_KEY_FILE`
- `WTF_CSRF_SECRET_KEY` or `WTF_CSRF_SECRET_KEY_FILE`
- `SESSION_HMAC_ACTIVE_KEY_ID`
- `SESSION_HMAC_KEYS_JSON` or `SESSION_HMAC_KEYS_JSON_FILE`
- `SESSION_LOOKUP_HMAC_KEY` or `SESSION_LOOKUP_HMAC_KEY_FILE`
- `DATABASE_URL` or `DATABASE_URL_FILE`
- `DATABASE_MIGRATION_URL` or `DATABASE_MIGRATION_URL_FILE`
- `ADMIN_SECRET_KEY` or `ADMIN_SECRET_KEY_FILE`
- `ADMIN_WTF_CSRF_SECRET_KEY` or `ADMIN_WTF_CSRF_SECRET_KEY_FILE`
- `ADMIN_SESSION_HMAC_ACTIVE_KEY_ID`
- `ADMIN_SESSION_HMAC_KEYS_JSON` or `ADMIN_SESSION_HMAC_KEYS_JSON_FILE`
- `ADMIN_SESSION_LOOKUP_HMAC_KEY` or `ADMIN_SESSION_LOOKUP_HMAC_KEY_FILE`
- `ADMIN_DATABASE_URL` or `ADMIN_DATABASE_URL_FILE`
- `ADMIN_PASSWORD_PEPPER_B64` or `ADMIN_PASSWORD_PEPPER_B64_FILE`
- `ADMIN_SESSION_KEY_PREFIX`
- `ADMIN_RATELIMIT_KEY_PREFIX`
- `MFA_KEK_ACTIVE_ID`
- `MFA_KEK_KEYS_JSON` or `MFA_KEK_KEYS_JSON_FILE`
- `PASSWORD_PEPPER_B64` or `PASSWORD_PEPPER_B64_FILE`
- `PASSWORD_PBKDF2_ITERATIONS`
- `PAYEE_COOLDOWN_SECONDS`
- `ROOT_ADMIN_EMAILS`
- `SECURITY_AUDIT_HMAC_KEY` or `SECURITY_AUDIT_HMAC_KEY_FILE`
- `SECURITY_AUDIT_ANCHOR_PATH`
- `PASSWORD_RESET_ENABLED`
- `PASSWORD_RESET_TOKEN_TTL_SECONDS`
- `PASSWORD_RESET_TRANSACTION_TTL_SECONDS`
- `PASSWORD_RESET_EMAIL_BACKEND`
- `PASSWORD_RESET_EMAIL_FROM`
- `PASSWORD_RESET_BASE_URL`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USE_TLS`
- `SMTP_USERNAME` or `SMTP_USERNAME_FILE`
- `SMTP_PASSWORD` or `SMTP_PASSWORD_FILE`
- `SECURITY_ALERT_ENABLED`
- `SECURITY_ALERT_WEBHOOK_URL` or `SECURITY_ALERT_WEBHOOK_URL_FILE`
- `SECURITY_ALERT_MIN_SEVERITY`
- `SECURITY_ALERT_TIMEOUT_SECONDS`
- `SECURITY_ALERT_DEDUPE_TTL_SECONDS`
- `SECURITY_ALERT_STATE_PATH`
- `HIBP_CIRCUIT_FAILURE_THRESHOLD`
- `HIBP_CIRCUIT_OPEN_SECONDS`
- `COMMON_PASSWORDS_PATH`

See `ops/production-env.required` for the machine-readable checklist.

## Customer Password Reset

Customer forgot-password requests use generic responses and do not reveal
whether an account exists. A reset email contains a short-lived one-time
`selector.verifier` link. The server immediately exchanges that URL token for a
tokenless PostgreSQL-backed reset transaction, then rejects replay of the original URL
token.

Password reset changes only the password. It does not disable MFA, does not
create a login session, and revokes active sessions after completion. Customers
with TOTP must verify TOTP or a recovery code. Accounts that cannot complete
the supported reset verification flow must use manual account recovery before
password reset or MFA re-enrollment. Customers without MFA can reset but are
sent through the existing MFA onboarding gate on next login. Admin-account
recovery belongs to the isolated admin/manual-recovery boundary, not the
customer domain.

## Documentation

- [Contributing](docs/CONTRIBUTING.md)
- [Deployment](docs/DEPLOYMENT.md)
- [GitHub Actions](docs/GITHUB_ACTIONS.md)
- [SonarQube Cloud analysis and PR summary policy](docs/security/sonarqube.md)
- [Operations](docs/OPERATIONS.md)
- [Security](SECURITY.md)
- [Audit and alerting](docs/security/audit-and-alerting.md)
- [Framework control matrix](docs/security/framework-control-matrix.md)
- [Privacy and PDPA](docs/security/privacy-and-pdpa.md)
- [Data retention and deactivation](docs/security/data-retention-and-deactivation.md)
- [Incident response](docs/security/incident-response.md)
- [Threat model](docs/security/threat-model.md)
- [Design risk register](docs/security/design-risk-register.md)
- [Security gap register](docs/security/security-gap-register.md)
- [Legacy and out-of-scope technology notes](docs/security/legacy-and-out-of-scope-technology.md)
- [Archived EC2 transition notes](docs/archive/EC2_TRANSITION.md)

## Deployment Snapshot

Images are published as immutable signed digests under `ghcr.io/wenjiangg/sitbank@sha256:<digest>` from the `WenJiangg/SITBank` repository. The workflow derives the package path from `GITHUB_REPOSITORY` so future owner changes need only docs, CODEOWNERS, EC2 deploy config, and bootstrap inputs updated. Production uses `/etc/sitbank`, `/opt/sitbank`, `sitbank-container.service`, `sitbank_db`, `sitbank_owner`, `sitbank_app`, and a distinct admin runtime DB role such as `sitbank_admin`. Staging uses separate `/etc/sitbank-staging`, `/opt/sitbank-staging`, isolated Compose services, and isolated Docker volumes.

Database migrations use Alembic. Existing databases that predate Alembic must first pass `verify-migration-baseline`, then be stamped with `db stamp 20260610_0001`. Do not run `db.create_all()` in deployment.

In production, both WSGI entrypoints validate the same security prerequisites as `flask production-check` before accepting traffic, and `/health/ready` repeats that validation before reporting ready. The guard applies to WSGI server startup only; Flask CLI invocations (including Alembic migration/bootstrap commands) remain outside that narrow startup hook and must use `flask production-check` explicitly when appropriate.
