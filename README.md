# SITBank

Secure Internet Banking Application for O$P$ Bank.

SITBank is a student cybersecurity project and demonstration site. Do not enter real banking credentials, card numbers, phone numbers, or personal financial information.

## Overview

SITBank is a Flask/Gunicorn application deployed as a hardened Docker container behind host-managed Nginx, TLS, PostgreSQL, and Redis. Production runs at `https://sitbank.duckdns.org`; staging runs separately at `https://staging-sitbank.duckdns.org`.

The app keeps password hashing PBKDF2+pepper only and MFA/TOTP seed encryption envelope-only using `MFA_KEK_ACTIVE_ID` plus `MFA_KEK_KEYS_JSON`. Legacy one-key MFA AES compatibility and direct non-PBKDF2 password hash compatibility are intentionally removed because current users are test-only and environments must be reset before this change is deployed.

## Local Development

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall app config.py wsgi.py
```

For a fuller local check, run `scripts/ci-local`. It includes Python/test checks, Git Bash syntax checks, Docker/Compose checks when Docker is available, and contract checks around `ops/runtime_contract.py`.

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
- `MFA_KEK_ACTIVE_ID`
- `MFA_KEK_KEYS_JSON` or `MFA_KEK_KEYS_JSON_FILE`
- `PASSWORD_PEPPER_B64` or `PASSWORD_PEPPER_B64_FILE`
- `PASSWORD_PBKDF2_ITERATIONS`
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

Images are published as immutable signed digests under `ghcr.io/wenjiangggg/sitbank@sha256:<digest>` from the renamed `WenJiangggg/SITBank` repository. Production uses `/etc/sitbank`, `/opt/sitbank`, `sitbank-container.service`, `sitbank_db`, `sitbank_owner`, and `sitbank_app`. Staging uses separate `/etc/sitbank-staging`, `/opt/sitbank-staging`, isolated Compose services, and isolated Docker volumes.

Database migrations use Alembic. Existing databases that predate Alembic must first pass `verify-migration-baseline`, then be stamped with `db stamp 20260610_0001`. Do not run `db.create_all()` in deployment.
