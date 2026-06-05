# ScamCentre

Secure Internet Banking Application for O$P$ Bank.

## Local virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m compileall app config.py wsgi.py
```

The EC2 target runtime is Python 3.12. This workstation currently created the
local `.venv` with the default registered Python runtime.

## Local security checks

Run these before packaging a release:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall app config.py wsgi.py
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt
.\.venv\Scripts\python.exe -m bandit -q -r app config.py wsgi.py
```

To refresh a hash-locked runtime dependency file after changing
`requirements.in`, run:

```powershell
.\.venv\Scripts\python.exe -m piptools compile --generate-hashes --output-file requirements.lock requirements.in
```

Install from the hash-locked file on systems that support strict hash checking:

```powershell
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock
```

## Copy this project to EC2

From Windows PowerShell in this project folder, create a deployment archive
without local virtual environments, git metadata, caches, or old archives:

```powershell
tar.exe -czf ".\scamcentre-app.tar.gz" --exclude=.git --exclude=.venv --exclude=.env --exclude=__pycache__ --exclude=.pytest_cache --exclude=*.pyc --exclude=*.tar.gz -C . .
```

Upload the archive with PuTTY `pscp`. Replace the key path with your real
`.ppk` file path:

```powershell
& "C:\Program Files\PuTTY\pscp.exe" -i "C:\Path\To\your-key.ppk" ".\scamcentre-app.tar.gz" student12@sitbank.duckdns.org:/tmp/scamcentre-app.tar.gz
```

On the EC2 server:

```bash
cd /var/www/scamcentre
tar -xzf /tmp/scamcentre-app.tar.gz
source venv/bin/activate
pip install --require-hashes -r requirements.lock
if grep -q '^TRUSTED_PROXY_COUNT=' .env; then sed -i 's/^TRUSTED_PROXY_COUNT=.*/TRUSTED_PROXY_COUNT=1/' .env; else echo 'TRUSTED_PROXY_COUNT=1' >> .env; fi
chmod 600 .env
python3.12 -c "from app import create_app; from app.extensions import db; app=create_app(); app.app_context().push(); db.create_all()"
python3.12 -c "from pathlib import Path; from app import create_app; from app.extensions import db; app=create_app(); app.app_context().push(); conn=db.engine.raw_connection(); cur=conn.cursor(); cur.execute(Path('ops/20260603_webauthn_credentials.sql').read_text()); conn.commit(); cur.close(); conn.close()"
flask --app wsgi:app production-check
sudo systemctl restart scamcentre
```

## Required production environment

This app is configured to fail closed. It does not include placeholder
connection strings, sample secrets, or fallback databases. Set the real
deployment values through the process environment or a server-local `.env`
file with `0600` permissions.

Required variables are listed in `ops/production-env.required`:

- `SECRET_KEY`
- `DATABASE_URL`
- `REDIS_URL`
- `MFA_AES256_GCM_KEY_B64`
- `COMMON_PASSWORDS_PATH`
- `COMMON_PASSWORDS_MIN_ENTRIES`
- `PASSWORD_PEPPER_B64`
- `PASSWORD_PBKDF2_ITERATIONS`
- `MFA_ISSUER_NAME`
- `TRUSTED_PROXY_COUNT`
- `WEBAUTHN_RP_ID`
- `WEBAUTHN_RP_ORIGIN`
- `WEBAUTHN_APPROVED_AAGUIDS_PATH`
- `WEBAUTHN_MDS_CACHE_PATH`

Optional hardening variables:

- `PENDING_MFA_MAX_AGE_SECONDS` defaults to `300` and must be between `60` and
  `SESSION_INACTIVITY_SECONDS`.
- `HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS` defaults to `2.0` and must be greater
  than `0` and no more than `5`. Registration falls back to the local
  blocklist with a user-visible warning when the live check is unavailable.

Generate the AES and password pepper keys with:

```powershell
.\.venv\Scripts\python.exe -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

Run the production dependency check on the server after the real environment is
present:

```powershell
.\.venv\Scripts\python.exe -m flask --app wsgi:app production-check
```

The check connects to the configured PostgreSQL and Redis services and verifies
that the common-password dictionary has at least 100,000 entries, the FIDO
metadata cache is fresh, approved AAGUIDs are present, and WebAuthn origin
settings match the public HTTPS host.

For the `sitbank.duckdns.org` deployment, `.env` must include:

```dotenv
WEBAUTHN_RP_ID=sitbank.duckdns.org
WEBAUTHN_RP_ORIGIN=https://sitbank.duckdns.org
```

## Domain changes and WebAuthn credentials

WebAuthn credentials are bound to the relying-party ID and HTTPS origin. A key
registered under `scamcentre.duckdns.org` cannot authenticate under
`sitbank.duckdns.org`.

When changing the public domain, update DuckDNS, Nginx `server_name`, the TLS
certificate, and the `.env` WebAuthn values together. The FIDO AAGUID allow-list
and MDS cache do not change because of the domain rename.

After backing up the production database, reset existing security-key
credentials so users can sign in with password plus TOTP and re-enroll keys on
the new domain:

```bash
python3.12 -c "from app import create_app; from app.extensions import db; from app.models import WebAuthnCredential; app=create_app(); app.app_context().push(); db.session.query(WebAuthnCredential).delete(); db.session.commit()"
```

Then run `flask --app wsgi:app production-check` and restart the app.

## FIDO metadata allow-list

Production requires a non-empty hardware-security-key allow-list and matching
FIDO metadata. The checked-in `ops/fido-approved-aaguids.json` and
`ops/fido-mds-cache.json` files are a curated starter snapshot from the FIDO
MDS3 blob. The list includes common Yubico/YubiKey, YubiKey FIPS, Feitian,
Thales, and TOKEN2 hardware authenticators that already meet this app's L2+
certification and attestation-root policy. Preview devices, not-certified
devices, and L1-only devices are intentionally excluded.

The checked-in policy contains one explicit legacy Level 1 lab exception for
YubiKey 5 NFC firmware 5.2/5.4
(`2fc0579f-8113-47ea-b116-bb5a8db9202a`) because this deployment's test
hardware uses that model. Remove this exception for stricter production or
banking deployments and use an L2+/FIPS key instead.

Review the checked-in list against the actual hardware you intend to support,
then store production copies outside the release archive.

Store production copies outside the release archive, for example:

```bash
# Use the group of the Unix user that runs Flask/Gunicorn. On the EC2 lab
# deployment this is usually student12; if systemd uses a different user/group,
# check it with: systemctl show -p User -p Group scamcentre
APP_GROUP=student12
sudo install -d -m 0750 -o root -g "$APP_GROUP" /etc/scamcentre
sudo nano /etc/scamcentre/fido-approved-aaguids.json
sudo nano /etc/scamcentre/fido-mds-cache.json
sudo chown root:"$APP_GROUP" /etc/scamcentre/fido-approved-aaguids.json /etc/scamcentre/fido-mds-cache.json
sudo chmod 0640 /etc/scamcentre/fido-approved-aaguids.json /etc/scamcentre/fido-mds-cache.json
```

Point `.env` at those files:

```dotenv
WEBAUTHN_APPROVED_AAGUIDS_PATH=/etc/scamcentre/fido-approved-aaguids.json
WEBAUTHN_MDS_CACHE_PATH=/etc/scamcentre/fido-mds-cache.json
```

The approved AAGUID file must contain at least one real hardware-key AAGUID:

```json
{
  "approved_aaguids": [
    "00000000-0000-0000-0000-000000000000"
  ]
}
```

The MDS cache must include a fresh `nextUpdate` and one entry for each approved
AAGUID with a trusted FIDO certification status and attestation root
certificate. Refresh this from FIDO MDS3 before `nextUpdate`; stale metadata
intentionally fails `flask --app wsgi:app production-check`.

```json
{
  "nextUpdate": "2026-12-31",
  "entries": [
    {
      "aaguid": "00000000-0000-0000-0000-000000000000",
      "statusReports": [
        {"status": "FIDO_CERTIFIED_L2"}
      ],
      "metadataStatement": {
        "attestationRootCertificates": [
          "<base64 DER attestation root certificate>"
        ]
      }
    }
  ]
}
```

## Banking API guardrails

The current banking blueprint intentionally exposes no transfer, payment, or
open-banking aggregation endpoints. Before any such endpoint is added, the
server must create the transaction record and bind all high-risk fields
server-side. Public request payloads must not accept account ownership,
approval state, KYC state, credit limits, risk scores, transaction status, or
other privileged fields, and every mutation must require an idempotency key.

## Proxy Boundary

Gunicorn should stay bound to `127.0.0.1`, with Nginx as the single trusted proxy.
Set `TRUSTED_PROXY_COUNT=1` and make sure Nginx overwrites forwarded headers
using the example in `ops/nginx-proxy-headers.conf`. The app uses
`request.remote_addr` only after Werkzeug `ProxyFix` normalizes the request.

To apply the Nginx proxy-header rule on EC2, first find the active Nginx site
file if you are not sure where it is:

```bash
sudo nginx -T | grep -n "server_name\|proxy_pass\|sitbank\|scamcentre"
```

Open the site file that contains the `proxy_pass http://127.0.0.1:5000;` rule,
usually one of these:

```bash
sudo nano /etc/nginx/sites-available/scamcentre
sudo nano /etc/nginx/sites-available/default
```

Inside the `location / { ... }` block that forwards traffic to Gunicorn, make
sure the block contains these exact headers:

```nginx
proxy_pass http://127.0.0.1:5000;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
```

Then validate and reload Nginx:

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl restart scamcentre
```

## MFA Key Rotation

If `MFA_AES256_GCM_KEY_B64` is exposed, existing encrypted TOTP seeds cannot be
decrypted after simply replacing the key. The safe recovery flow is:

1. Freeze or otherwise protect affected accounts.
2. Generate a new 32-byte AES-GCM key.
3. Clear existing MFA seeds for affected users.
4. Require those users to re-enroll MFA after password login.
5. Record the incident and re-enrollment in security audit logs.

## Implemented security modules

- Registration/login with NIST-length password policy, local common-password rejection, PBKDF2-HMAC-SHA256 password hashing with a deployment pepper, generic login errors, and Redis-backed non-blocking failure throttling.
- TOTP MFA setup/verification with encrypted AES-256-GCM secret storage and Redis anti-replay cache for the exact current 30-second window.
- Redis-backed server-side sessions with UUIDv4 session IDs, session rotation, 15-minute inactivity expiry, 5-minute pending-MFA absolute expiry, secure cookie flags, active-session listing, and explicit revocation.
- Self-service account freeze protected by CSRF and security-key step-up; unfreeze is intentionally not exposed.
- Reusable frozen-account guards for outbound transfers, scheduled transfer execution, and sensitive profile changes.
