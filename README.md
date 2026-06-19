# SITBank

Secure Internet Banking Application for O$P$ Bank.

SITBank is a student cybersecurity project and demonstration site. Do not enter real banking credentials, card numbers, phone numbers, or personal financial information.

## Overview

SITBank is a Flask/Gunicorn application deployed as hardened Docker containers behind host-managed Nginx, TLS, PostgreSQL, and Redis. Production customer traffic runs at `https://sitbank.duckdns.org`; the isolated production admin boundary is reserved at `https://admin-sitbank.duckdns.org` and is fail-closed until future WebAuthn/passkey and network allowlist controls are implemented. Staging runs separately at `https://staging-sitbank.duckdns.org` and does not include an admin service in this phase.

The app keeps password hashing PBKDF2+pepper only and MFA/TOTP seed encryption envelope-only using `MFA_KEK_ACTIVE_ID` plus `MFA_KEK_KEYS_JSON`. Legacy one-key MFA AES compatibility and direct non-PBKDF2 password hash compatibility are intentionally removed because current users are test-only and environments must be reset before this change is deployed.

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

The `not slow` and focused marker commands are for local iteration only. Pull requests and protected CI still run the full pytest suite, including security, deployment, Redis session integrity, CSRF, MFA, WebAuthn, route inventory, production guard, dependency lock, and secret-scanning checks.

For a fuller local check, run `scripts/ci-local`. It runs the full pytest suite in parallel with timing output, then Python/package/security checks, Git Bash syntax checks, Docker/Compose checks when Docker is available, and contract checks around `ops/runtime_contract.py`.

## Required Configuration

Production/staging secrets should be installed as root-managed files and consumed with `_FILE` settings wherever possible.

Current required settings include:

- `APP_ENV`
- `SECRET_KEY` or `SECRET_KEY_FILE`
- `WTF_CSRF_SECRET_KEY` or `WTF_CSRF_SECRET_KEY_FILE`
- `SESSION_HMAC_ACTIVE_KEY_ID`
- `SESSION_HMAC_KEYS_JSON` or `SESSION_HMAC_KEYS_JSON_FILE`
- `DATABASE_URL` or `DATABASE_URL_FILE`
- `DATABASE_MIGRATION_URL` or `DATABASE_MIGRATION_URL_FILE`
- `REDIS_URL` or `REDIS_URL_FILE`
- `ADMIN_SECRET_KEY` or `ADMIN_SECRET_KEY_FILE`
- `ADMIN_WTF_CSRF_SECRET_KEY` or `ADMIN_WTF_CSRF_SECRET_KEY_FILE`
- `ADMIN_SESSION_HMAC_ACTIVE_KEY_ID`
- `ADMIN_SESSION_HMAC_KEYS_JSON` or `ADMIN_SESSION_HMAC_KEYS_JSON_FILE`
- `ADMIN_DATABASE_URL` or `ADMIN_DATABASE_URL_FILE`
- `ADMIN_REDIS_URL` or `ADMIN_REDIS_URL_FILE`
- `ADMIN_PASSWORD_PEPPER_B64` or `ADMIN_PASSWORD_PEPPER_B64_FILE`
- `ADMIN_SESSION_KEY_PREFIX`
- `ADMIN_RATELIMIT_KEY_PREFIX`
- `MFA_KEK_ACTIVE_ID`
- `MFA_KEK_KEYS_JSON` or `MFA_KEK_KEYS_JSON_FILE`
- `PASSWORD_PEPPER_B64` or `PASSWORD_PEPPER_B64_FILE`
- `PASSWORD_PBKDF2_ITERATIONS`
- `SECURITY_ALERT_ENABLED`
- `SECURITY_ALERT_WEBHOOK_URL` or `SECURITY_ALERT_WEBHOOK_URL_FILE`
- `SECURITY_ALERT_MIN_SEVERITY`
- `SECURITY_ALERT_TIMEOUT_SECONDS`
- `SECURITY_ALERT_DEDUPE_TTL_SECONDS`
- `HIBP_CIRCUIT_FAILURE_THRESHOLD`
- `HIBP_CIRCUIT_OPEN_SECONDS`
- `WEBAUTHN_RP_ID`
- `WEBAUTHN_RP_ORIGIN`
- `WEBAUTHN_APPROVED_AAGUIDS_PATH`
- `WEBAUTHN_MDS_CACHE_PATH`
- `COMMON_PASSWORDS_PATH`

See `ops/production-env.required` for the machine-readable checklist.

## Documentation

- [Deployment](docs/DEPLOYMENT.md)
- [GitHub Actions](docs/GITHUB_ACTIONS.md)
- [Operations](docs/OPERATIONS.md)
- [Security](SECURITY.md)
- [Archived EC2 transition notes](docs/archive/EC2_TRANSITION.md)

## Deployment Snapshot

Images are published as immutable signed digests under `ghcr.io/wenjiangggg/sitbank@sha256:<digest>` from the renamed `WenJiangggg/SITBank` repository. Production uses `/etc/sitbank`, `/opt/sitbank`, `sitbank-container.service`, `sitbank_db`, `sitbank_owner`, `sitbank_app`, and a distinct admin runtime DB role such as `sitbank_admin`. Staging uses separate `/etc/sitbank-staging`, `/opt/sitbank-staging`, isolated Compose services, and isolated Docker volumes.

Database migrations use Alembic. Existing databases that predate Alembic must first pass `verify-migration-baseline`, then be stamped with `db stamp 20260610_0001`. Do not run `db.create_all()` in deployment.
