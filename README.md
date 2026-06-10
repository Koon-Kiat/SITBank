# ScamCentre

Secure Internet Banking Application for O$P$ Bank.

## Local virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
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
.\.venv\Scripts\python.exe -m pip_audit --require-hashes -r requirements.lock
.\.venv\Scripts\python.exe -m bandit -q -ll -r app config.py wsgi.py
```

To refresh a hash-locked runtime dependency file after changing
`requirements.in`, run:

```powershell
.\.venv\Scripts\python.exe -m piptools compile --generate-hashes --output-file requirements.lock requirements.in
.\.venv\Scripts\python.exe -m piptools compile --generate-hashes --output-file requirements-dev.lock requirements-dev.txt
```

Install from the hash-locked file on systems that support strict hash checking:

```powershell
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock
```

## Temporary manual EC2 deployment

Use this path while repository-owner access is unavailable for configuring the
GitHub `production` environment. It keeps the existing flat EC2 deployment
working, but the GitHub Actions release process below remains the preferred
long-term method. Commit and review the intended release first: `git archive`
packages tracked files from `HEAD` and cannot accidentally include ignored
`.env`, private-key, backup, or editor files.

Create and upload the archive from Windows PowerShell:

```powershell
$Ec2User = "replace-with-existing-ec2-user"
git archive --format=tar.gz --output=".\scamcentre-app.tar.gz" HEAD
$hash = (Get-FileHash ".\scamcentre-app.tar.gz" -Algorithm SHA256).Hash.ToLower()
"$hash  scamcentre-app.tar.gz" | Set-Content ".\scamcentre-app.sha256" -Encoding ascii
& "C:\Program Files\PuTTY\pscp.exe" -i "C:\Path\To\your-key.ppk" ".\scamcentre-app.tar.gz" ".\scamcentre-app.sha256" "$Ec2User@sitbank.duckdns.org:/tmp/"
```

On EC2, verify the upload and make protected backups:

```bash
cd /tmp
sha256sum -c scamcentre-app.sha256

cd /var/www/scamcentre
backup_timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -m 0700 /var/backups/scamcentre
sudo install -o root -g root -m 0600 .env \
  "/var/backups/scamcentre/env-${backup_timestamp}"
sudo tar --exclude='./venv' --exclude='./.venv' --exclude='./.env*' \
  -czf "/var/backups/scamcentre/app-${backup_timestamp}.tar.gz" .
sudo -u postgres pg_dump -Fc -f "/tmp/db-${backup_timestamp}.dump" scamcentre_db
sudo install -o root -g root -m 0600 "/tmp/db-${backup_timestamp}.dump" \
  "/var/backups/scamcentre/db-${backup_timestamp}.dump"
sudo rm -f "/tmp/db-${backup_timestamp}.dump"
```

Before the first deployment of this hardened configuration, add the new
production values without displaying any secret:

```bash
cd /var/www/scamcentre
umask 077

if grep -q '^APP_ENV=' .env; then
    sed -i 's/^APP_ENV=.*/APP_ENV=production/' .env
else
    printf '\nAPP_ENV=production\n' >> .env
fi

if grep -q '^TRUSTED_PROXY_COUNT=' .env; then
    sed -i 's/^TRUSTED_PROXY_COUNT=.*/TRUSTED_PROXY_COUNT=1/' .env
else
    printf 'TRUSTED_PROXY_COUNT=1\n' >> .env
fi

if ! grep -q '^WTF_CSRF_SECRET_KEY=' .env; then
    printf 'WTF_CSRF_SECRET_KEY=%s\n' \
      "$(python3.12 -c 'import secrets; print(secrets.token_urlsafe(48))')" >> .env
fi

has_hmac_id=0
has_hmac_ring=0
grep -q '^SESSION_HMAC_ACTIVE_KEY_ID=' .env && has_hmac_id=1
grep -q '^SESSION_HMAC_KEYS_JSON=' .env && has_hmac_ring=1
if [[ "$has_hmac_id" -ne "$has_hmac_ring" ]]; then
    echo "Incomplete session HMAC configuration; restore the backup and repair the pair." >&2
    exit 1
fi
if [[ "$has_hmac_id" -eq 0 ]]; then
    session_hmac_key="$(
      python3.12 -c 'import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())'
    )"
    printf 'SESSION_HMAC_ACTIVE_KEY_ID=2026-06-initial\n' >> .env
    printf "SESSION_HMAC_KEYS_JSON='{\"2026-06-initial\":\"%s\"}'\n" \
      "$session_hmac_key" >> .env
    unset session_hmac_key
fi
chmod 0600 .env
```

Confirm that the required names exist without printing their values:

```bash
for name in APP_ENV TRUSTED_PROXY_COUNT WTF_CSRF_SECRET_KEY \
  SESSION_HMAC_ACTIVE_KEY_ID SESSION_HMAC_KEYS_JSON; do
    grep -q "^${name}=" .env &&
      echo "${name}: configured" ||
      echo "${name}: MISSING"
done
```

Confirm that the existing systemd unit loads
`EnvironmentFile=/var/www/scamcentre/.env`. If it does not, add that line in a
systemd drop-in with `sudo systemctl edit scamcentre`, then run
`sudo systemctl daemon-reload`.

Deploy and validate:

```bash
cd /var/www/scamcentre
tar -xzf /tmp/scamcentre-app.tar.gz
source venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m dotenv run -- python -m flask --app wsgi:app production-check
```

Choose exactly one database path before restarting the service.

For the first Alembic-enabled deployment of an existing database, compare the
existing schema directly to the application models. Stamp only when the
baseline verifier succeeds:

```bash
python -m dotenv run -- python -m flask --app wsgi:app verify-migration-baseline
python -m dotenv run -- python -m flask --app wsgi:app db stamp 20260610_0001
python -m dotenv run -- python -m flask --app wsgi:app db current
python -m dotenv run -- python -m flask --app wsgi:app db upgrade
```

If the verifier reports differences, stop and resolve them before stamping.
For a new empty database, or every deployment after the baseline is already
stamped, run only:

```bash
python -m dotenv run -- python -m flask --app wsgi:app db upgrade
```

Finish the deployment:

```bash
sudo systemctl restart scamcentre
sudo systemctl --no-pager --full status scamcentre
curl -I https://sitbank.duckdns.org
rm -f /tmp/scamcentre-app.tar.gz /tmp/scamcentre-app.sha256
```

Do not run `db.create_all()` or `ops/20260603_webauthn_credentials.sql` again.

## GitHub Actions deployment

`.github/workflows/ci-deploy.yml` runs tests, compilation, package validation,
Bandit, and dependency auditing. A successful push to `main` produces one
checksum-verified release archive. The `deploy` job targets the protected
GitHub `production` environment. Deployment remains disabled until the
repository variable `PROD_DEPLOY_ENABLED` is set to the exact value `true`.
Configure the environment, EC2 bootstrap, and database baseline before enabling
it.

The EC2 deploy uses SHA-named release directories under
`/var/www/scamcentre/releases`, runs production checks and Alembic migrations,
switches `/var/www/scamcentre/current`, restarts Gunicorn, and verifies
`/health/ready` through local Nginx/TLS. If readiness fails, the application
symlink is switched back to the previous release. Database migrations must
therefore remain backward compatible with the previous application release.

### GitHub production secrets

Add these as environment secrets under `production`:

- `EC2_SSH_PRIVATE_KEY`
- `EC2_KNOWN_HOSTS`
- `PROD_SECRET_KEY`
- `PROD_WTF_CSRF_SECRET_KEY`
- `PROD_SESSION_HMAC_ACTIVE_KEY_B64`
- `PROD_SESSION_HMAC_PREVIOUS_KEY_B64` (optional during rotation)
- `PROD_DATABASE_URL`
- `PROD_REDIS_URL`
- `PROD_MFA_AES256_GCM_KEY_B64`
- `PROD_PASSWORD_PEPPER_B64`

Add these as environment variables:

- `EC2_HOST`
- `EC2_PORT` (defaults to `22`)
- `EC2_DEPLOY_USER` (defaults to `scamcentre-deploy`)
- `PROD_PUBLIC_HOST` (`sitbank.duckdns.org`)
- `PROD_SESSION_HMAC_ACTIVE_KEY_ID`
- `PROD_SESSION_HMAC_PREVIOUS_KEY_ID` (optional during rotation)
- `PROD_COMMON_PASSWORDS_PATH`
- `PROD_WEBAUTHN_APPROVED_AAGUIDS_PATH`
- `PROD_WEBAUTHN_MDS_CACHE_PATH`
- `PROD_PASSWORD_PBKDF2_ITERATIONS` (defaults to `600000`)
- `PROD_MFA_ISSUER_NAME`

Set `PROD_DEPLOY_ENABLED=false` as a repository Actions variable while setting
up the server. Change it to `true` only after the one-time bootstrap and
database baseline steps below succeed.

`EC2_KNOWN_HOSTS` must contain the verified SSH host key, not an unverified
first-use key. Compare the EC2 host fingerprint through the AWS console or
another trusted channel before storing it.

### One-time EC2 bootstrap

The existing EC2 deployment runs from `/var/www/scamcentre` and is not a Git
working tree. Back up PostgreSQL, the current app, and its local environment
before changing the service:

```bash
sudo install -d -m 0700 /var/backups/scamcentre
sudo -u postgres pg_dump -Fc -f /tmp/scamcentre-pre-actions.dump scamcentre_db
sudo mv /tmp/scamcentre-pre-actions.dump /var/backups/scamcentre/
sudo tar -C /var/www -czf /var/backups/scamcentre/app-pre-actions.tar.gz scamcentre
sudo cp -a /etc/systemd/system/scamcentre.service \
  /var/backups/scamcentre/scamcentre.service.pre-actions
```

Upload a trusted archive of this repository once using the existing EC2
administrator SSH access, extract it outside the live app directory, then run:

```powershell
$Ec2User = "replace-with-existing-ec2-user"
git archive --format=tar.gz --output=".\scamcentre-bootstrap.tar.gz" HEAD
scp -i "C:\path\to\existing-ec2-key.pem" ".\scamcentre-bootstrap.tar.gz" "$Ec2User@sitbank.duckdns.org:/tmp/"
```

```bash
sudo install -d -m 0755 /opt/scamcentre-bootstrap
sudo tar -xzf /tmp/scamcentre-bootstrap.tar.gz -C /opt/scamcentre-bootstrap
cd /opt/scamcentre-bootstrap
sudo bash ops/deploy/bootstrap-ec2
```

This creates separate `scamcentre` service and `scamcentre-deploy` SSH users,
installs the hardened systemd units and restricted sudo rule, and creates the
release directories. It preserves the current flat deployment as a
`legacy-*` release and creates `/var/www/scamcentre/current` as a rollback
target. The bootstrap does not restart the running service.

Create a dedicated deployment key on an administrator workstation. Do not
reuse a personal EC2 key:

```powershell
ssh-keygen -t ed25519 -a 100 -f "$HOME\.ssh\scamcentre_github_actions" -C "github-actions-scamcentre"
```

Add its public half to:

```text
/home/scamcentre-deploy/.ssh/authorized_keys
```

Prefix the authorized-key line with `restrict` to disable port forwarding,
agent forwarding, X11 forwarding, and PTY allocation:

```text
restrict ssh-ed25519 AAAA... github-actions-scamcentre
```

Store the private half only as `EC2_SSH_PRIVATE_KEY` in the GitHub `production`
environment. The deployment user can upload only into its private
`/home/scamcentre-deploy/incoming` directory and can run only the validated
deployment script through `sudo`.

From the already trusted administrator connection, record the server's
Ed25519 SSH fingerprint:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Compare it with the fingerprint returned locally by `ssh-keyscan` before
storing the complete `ssh-keyscan -H -t ed25519 sitbank.duckdns.org` output as
`EC2_KNOWN_HOSTS`. Do not accept a changed host key only because an Actions run
reports a mismatch.

Copy the common-password dictionary and reviewed FIDO policy files from their
current locations into `/etc/scamcentre`, owned by `root:scamcentre` with mode
`0640`:

```bash
sudo install -o root -g scamcentre -m 0640 \
  /var/www/scamcentre/ops/fido-approved-aaguids.json \
  /etc/scamcentre/fido-approved-aaguids.json
sudo install -o root -g scamcentre -m 0640 \
  /var/www/scamcentre/ops/fido-mds-cache.json \
  /etc/scamcentre/fido-mds-cache.json
```

Copy the existing common-password file to
`/etc/scamcentre/common-passwords.txt`. Its current source path is the
`COMMON_PASSWORDS_PATH` value in the old `/var/www/scamcentre/.env`; do not
print the rest of that file. Update only these path entries in
`/etc/scamcentre/runtime.env`:

```dotenv
COMMON_PASSWORDS_PATH=/etc/scamcentre/common-passwords.txt
WEBAUTHN_APPROVED_AAGUIDS_PATH=/etc/scamcentre/fido-approved-aaguids.json
WEBAUTHN_MDS_CACHE_PATH=/etc/scamcentre/fido-mds-cache.json
```

Verify that the new service account can read all three files, then restart the
preserved release:

```bash
sudo -u scamcentre test -r /etc/scamcentre/common-passwords.txt
sudo -u scamcentre test -r /etc/scamcentre/fido-approved-aaguids.json
sudo -u scamcentre test -r /etc/scamcentre/fido-mds-cache.json
sudo systemctl restart scamcentre
sudo systemctl --no-pager --full status scamcentre
curl -I https://sitbank.duckdns.org
```

For an existing database that already matches the models in migration
`20260610_0001`, back it up and verify its tables/indexes, then stamp the
baseline exactly once before the first automated deployment:

```bash
flask --app wsgi:app db stamp 20260610_0001
```

New databases should use `flask --app wsgi:app db upgrade`. Do not use
`db.create_all()` in production.

Finally, add the GitHub environment secrets and variables, restrict the
`production` environment to the `main` branch, enable required reviewers when
the repository plan supports them, and set the repository variable
`PROD_DEPLOY_ENABLED=true`. Trigger the first deployment with the Actions
`workflow_dispatch` button and watch the test, package, and deploy jobs.

Protect `main` with pull-request reviews, required passing Actions checks, and
disabled force pushes. Treat edits to `.github/workflows`, `ops/deploy`,
`ops/systemd`, and `ops/sudoers` as security-sensitive because code merged into
`main` can influence a production deployment.

## Required production environment

This app is configured to fail closed. Production does not load a project
`.env` file when `APP_ENV=production`. GitHub environment secrets are rendered
during deployment into `/etc/scamcentre/runtime.env`, owned by
`root:scamcentre` with mode `0640`, because systemd must provide the values to
the running process. The file is outside every release archive and is replaced
atomically on deployment.

Required variables are listed in `ops/production-env.required`:

- `APP_ENV`
- `SECRET_KEY`
- `WTF_CSRF_SECRET_KEY`
- `SESSION_HMAC_ACTIVE_KEY_ID`
- `SESSION_HMAC_KEYS_JSON`
- `DATABASE_URL`
- `REDIS_URL`
- `MFA_AES256_GCM_KEY_B64`
- `COMMON_PASSWORDS_PATH`
- `COMMON_PASSWORDS_MIN_ENTRIES`
- `PASSWORD_PEPPER_B64`
- `PASSWORD_PBKDF2_ITERATIONS`
- `HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS`
- `HIBP_CIRCUIT_FAILURE_THRESHOLD`
- `HIBP_CIRCUIT_OPEN_SECONDS`
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
- `HIBP_CIRCUIT_FAILURE_THRESHOLD` defaults to `3`; after that many consecutive
  availability failures, live checks are skipped temporarily.
- `HIBP_CIRCUIT_OPEN_SECONDS` defaults to `300`.

Generate the AES and password pepper keys with:

```powershell
.\.venv\Scripts\python.exe -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

The deploy workflow runs `flask --app wsgi:app production-check` before each
migration. The check connects to PostgreSQL and Redis and verifies the common
password dictionary, password hashing configuration, session HMAC key ring,
cookie/CSRF/proxy settings, FIDO metadata freshness, approved AAGUIDs, and the
public HTTPS WebAuthn origin.

## Session HMAC key rotation

GitHub stores the active and optional previous HMAC keys as separate secrets.
The deployment renderer validates that each key is base64 for exactly 32 bytes
and builds `SESSION_HMAC_KEYS_JSON` only inside the ephemeral Actions runner.
`PROD_SESSION_HMAC_ACTIVE_KEY_ID` selects the key used for new public session
references and risk fingerprints.

To rotate, move the current active ID/key into the two `PREVIOUS` values,
generate a new active ID/key, and deploy. Keep the previous key for at least 24
hours so active Redis sessions and references can age out, then remove both
previous values in a later approved deployment. Rotating `SECRET_KEY` alone no
longer changes session-reference or risk-fingerprint HMACs. On the first
deployment of this key ring, sessions created by older code stay logged in,
but a sensitive action may require one fresh sign-in because its legacy risk
fingerprint is intentionally not trusted.

## Domain changes and WebAuthn credentials

WebAuthn credentials are bound to the relying-party ID and HTTPS origin. A key
registered under `scamcentre.duckdns.org` cannot authenticate under
`sitbank.duckdns.org`.

When changing the public domain, update DuckDNS, Nginx `server_name`, the TLS
certificate, `PROD_PUBLIC_HOST`, and the WebAuthn GitHub environment values
together. The FIDO AAGUID allow-list and MDS cache do not change because of the
domain rename.

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
APP_GROUP=scamcentre
sudo install -d -m 0750 -o root -g "$APP_GROUP" /etc/scamcentre
sudo nano /etc/scamcentre/fido-approved-aaguids.json
sudo nano /etc/scamcentre/fido-mds-cache.json
sudo chown root:"$APP_GROUP" /etc/scamcentre/fido-approved-aaguids.json /etc/scamcentre/fido-mds-cache.json
sudo chmod 0640 /etc/scamcentre/fido-approved-aaguids.json /etc/scamcentre/fido-mds-cache.json
```

Set `PROD_WEBAUTHN_APPROVED_AAGUIDS_PATH` and
`PROD_WEBAUTHN_MDS_CACHE_PATH` in the GitHub `production` environment to those
paths.

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
