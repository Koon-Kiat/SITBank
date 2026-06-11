# SITBank

Secure Internet Banking Application for SITBank.

Production runs Flask and Gunicorn in a hardened Docker container. Nginx,
Certbot, PostgreSQL, Redis, backups, and FIDO policy files remain on the EC2
host.

## Local Development

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall app config.py wsgi.py
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pip_audit --require-hashes -r requirements.lock
.\.venv\Scripts\python.exe -m bandit -q -ll -r app config.py wsgi.py
```

Refresh lock files only after reviewing dependency changes:

```powershell
.\.venv\Scripts\python.exe -m piptools compile --generate-hashes --output-file requirements.lock requirements.in
.\.venv\Scripts\python.exe -m piptools compile --generate-hashes --output-file requirements-dev.lock requirements-dev.txt
```

## Production Architecture

- Nginx terminates TLS and proxies to `127.0.0.1:5000`.
- The application container uses host networking to reach the existing
  localhost-only PostgreSQL and Redis services.
- Gunicorn binds only to `127.0.0.1:5000`; Compose publishes no ports.
- The application runs as UID/GID `10001`, with a read-only root filesystem,
  a size-limited `/tmp`, all Linux capabilities dropped, and
  `no-new-privileges`.
- Production images are private GHCR images addressed by immutable digest.
- Images are scanned, receive SBOM and provenance attestations, and are signed
  with GitHub OIDC through Cosign.
- Secrets are mounted under `/run/secrets`; they are not stored in image
  layers, labels, or the container environment.
- The SSH deployment user is not a member of the `docker` group and can run
  only the validated root deployment wrapper.

The active deployment uses:

- `/opt/sitbank` for the root-owned Compose definition and import helper.
- `/etc/sitbank` for non-secret configuration, policy files, and protected
  secret sources.
- `/var/lib/sitbank-container` for deployment and rollback state.
- `/var/backups/sitbank` for protected database and transition backups.

Docker does not need an application directory under `/var/www`. A pre-container
installation may be supplied to the bootstrap as a temporary legacy path. It
is removed only after the first SITBank container passes direct and public
readiness checks.

## Secret Configuration

Sensitive settings accept either `NAME` or `NAME_FILE`, never both:

- `SECRET_KEY_FILE`
- `WTF_CSRF_SECRET_KEY_FILE`
- `SESSION_HMAC_KEYS_JSON_FILE`
- `DATABASE_URL_FILE`
- `REDIS_URL_FILE`
- `MFA_AES256_GCM_KEY_B64_FILE`
- `PASSWORD_PEPPER_B64_FILE`

Direct values remain supported for local development and tests. In production,
secret files must resolve beneath `/run/secrets`, must not be symlinks, and
must contain one non-empty UTF-8 line without NUL, CR, or embedded LF
characters.

Root-owned host copies live under `/etc/sitbank/secrets`. The deployment
wrapper reads them into its private process environment only long enough for
Compose to create service secrets owned by UID/GID `10001` with mode `0400`.
Non-secret settings live in `/etc/sitbank/container.env`. The container does
not load a production `.env` file.

The complete production configuration surface is:

- `APP_ENV`
- `SECRET_KEY_FILE`
- `WTF_CSRF_SECRET_KEY_FILE`
- `SESSION_HMAC_ACTIVE_KEY_ID`
- `SESSION_HMAC_KEYS_JSON_FILE`
- `DATABASE_URL_FILE`
- `REDIS_URL_FILE`
- `MFA_AES256_GCM_KEY_B64_FILE`
- `PASSWORD_PEPPER_B64_FILE`
- `PASSWORD_PBKDF2_ITERATIONS`
- `COMMON_PASSWORDS_PATH`
- `COMMON_PASSWORDS_MIN_ENTRIES`
- `HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS`
- `HIBP_CIRCUIT_FAILURE_THRESHOLD`
- `HIBP_CIRCUIT_OPEN_SECONDS`
- `MFA_ISSUER_NAME`
- `TRUSTED_PROXY_COUNT`
- `WEBAUTHN_RP_ID`
- `WEBAUTHN_RP_ORIGIN`
- `WEBAUTHN_APPROVED_AAGUIDS_PATH`
- `WEBAUTHN_MDS_CACHE_PATH`

The direct names `SECRET_KEY`, `WTF_CSRF_SECRET_KEY`,
`SESSION_HMAC_KEYS_JSON`, `DATABASE_URL`, `REDIS_URL`,
`MFA_AES256_GCM_KEY_B64`, and `PASSWORD_PEPPER_B64` remain available for local
development, tests, and the one-time protected legacy import only.

## GitHub Actions Pipeline

`.github/workflows/ci-deploy.yml`:

1. Pull requests run workflow security checks, pytest, compilation, package
   checks, Bandit, dependency auditing, repository secret scanning, local image
   build, smoke tests, authenticated DAST smoke crawl, Compose validation, and
   both Trivy gates. Pull requests do not publish, sign, or deploy release
   images, and they do not reference staging or production secrets.
2. Manual `workflow_dispatch` runs can publish and verify an immutable release
   candidate digest. Use `target_environment=staging` and `deploy=false` for
   a staging release verification only run.
3. Manual staging deployment requires `target_environment=staging`,
   `deploy=true`, and `STAGING_DEPLOY_ENABLED=true`.
4. Pushes to `main` publish one immutable GHCR image, verify the exact digest,
   and deploy to staging only when `STAGING_DEPLOY_ENABLED=true`.
5. Production deployment is restricted to `main`, uses the `production`
   environment, and runs only when `PROD_DEPLOY_ENABLED=true`. On automatic
   `main` runs, production waits for staging when staging deployment is enabled.
6. Release verification validates the exact digest from `publish`, checks the
   image revision label, validates the Compose model against that digest, runs
   smoke and DAST checks, keeps both Trivy gates, and signs/verifies the digest
   with Cosign keyless GitHub OIDC.
7. Deployment passes only the commit SHA and verified `sha256:` digest to the
   protected EC2 wrapper. It never deploys `latest` and never rebuilds for
   staging or production.

Every third-party action is pinned to a full commit SHA. Publishing remains
available while deployment is disabled, allowing the same signed digest to be
verified without changing EC2.

### GitHub Environments

Create separate `staging` and `production` environments. Restrict production
deployment branches to `main`, add required reviewers, prevent self-review
where supported, and protect `main` with pull-request approval, required CI
checks, and disabled force pushes.

Set these repository Actions variables before the first merge:

- `STAGING_DEPLOY_ENABLED=false`
- `PROD_DEPLOY_ENABLED=false`

The enable flags are repository variables because the workflow evaluates them
before environment-scoped variables are loaded. With both disabled, a `main`
run still builds, scans, signs, and release-verifies the digest, then skips
deployment clearly.

#### Staging Environment

Add these staging environment secrets:

- `STAGING_EC2_KNOWN_HOSTS`
- `STAGING_EC2_SSH_PRIVATE_KEY`
- `STAGING_DATABASE_URL`
- `STAGING_MFA_AES256_GCM_KEY_B64`
- `STAGING_PASSWORD_PEPPER_B64`
- `STAGING_REDIS_URL`
- `STAGING_SECRET_KEY`
- `STAGING_SESSION_HMAC_ACTIVE_KEY_B64`
- `STAGING_WTF_CSRF_SECRET_KEY`

Add these staging environment variables:

- `STAGING_EC2_DEPLOY_USER`
- `STAGING_EC2_HOST`
- `STAGING_EC2_PORT`
- `STAGING_MFA_ISSUER_NAME`
- `STAGING_PASSWORD_PBKDF2_ITERATIONS`
- `STAGING_PUBLIC_HOST`
- `STAGING_SESSION_HMAC_ACTIVE_KEY_ID`

#### Production Environment

Add these production environment secrets:

- `PROD_EC2_KNOWN_HOSTS`
- `PROD_EC2_SSH_PRIVATE_KEY`
- `PROD_DATABASE_URL`
- `PROD_MFA_AES256_GCM_KEY_B64`
- `PROD_PASSWORD_PEPPER_B64`
- `PROD_REDIS_URL`
- `PROD_SECRET_KEY`
- `PROD_SESSION_HMAC_ACTIVE_KEY_B64`
- `PROD_WTF_CSRF_SECRET_KEY`

Add these production environment variables:

- `PROD_EC2_DEPLOY_USER`
- `PROD_EC2_HOST`
- `PROD_EC2_PORT`
- `PROD_MFA_ISSUER_NAME`
- `PROD_PASSWORD_PBKDF2_ITERATIONS`
- `PROD_PUBLIC_HOST`, currently `sitbank.duckdns.org`
- `PROD_SESSION_HMAC_ACTIVE_KEY_ID`

The optional rotation settings are `PROD_SESSION_HMAC_PREVIOUS_KEY_ID` and
`PROD_SESSION_HMAC_PREVIOUS_KEY_B64`; configure both together only during a
session HMAC key rotation.

#### Production EC2 Name Migration

Existing unprefixed production deployment names are deprecated and are not used
by the workflow. Rename them before enabling production deployment:

| Old name | New canonical name |
| --- | --- |
| `EC2_KNOWN_HOSTS` | `PROD_EC2_KNOWN_HOSTS` |
| `EC2_SSH_PRIVATE_KEY` | `PROD_EC2_SSH_PRIVATE_KEY` |
| `EC2_DEPLOY_USER` | `PROD_EC2_DEPLOY_USER` |
| `EC2_HOST` | `PROD_EC2_HOST` |
| `EC2_PORT` | `PROD_EC2_PORT` |

Configuration names and non-secret defaults are safe to document. Their values
must never be committed. Verify known hosts through a trusted channel; never
accept an unexpected SSH host-key change merely to make deployment pass.

The production database and Redis URLs must use `127.0.0.1`, because both
services remain bound to EC2 loopback and the app uses host networking.

The active production runtime is Docker Compose under
`sitbank-container.service`, using `/opt/sitbank/compose.yml`. The legacy
`sitbank.service`, old service names, and `/var/www` application directories
are not the active runtime.

## One-Time EC2 Transition

Use a maintenance window. Replace the angle-bracket placeholders with the
existing server values without committing them to the repository.

### 1. Back Up the Existing Database and Application

```bash
sudo install -d -o root -g root -m 0700 /var/backups/sitbank
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
sudo -u postgres pg_dump -Fc \
  -f "/tmp/legacy-${timestamp}.dump" <current-database>
sudo install -o root -g root -m 0600 \
  "/tmp/legacy-${timestamp}.dump" \
  "/var/backups/sitbank/database-${timestamp}.dump"
sudo rm -f "/tmp/legacy-${timestamp}.dump"
sudo tar -C "$(dirname <current-app-root>)" -czf \
  "/var/backups/sitbank/application-${timestamp}.tar.gz" \
  "$(basename <current-app-root>)"
sudo cp -a "/etc/systemd/system/<current-service>" \
  "/var/backups/sitbank/service-${timestamp}"
```

### 2. Verify the Existing Migration Baseline

Run these commands from the existing application installation:

```bash
cd <current-app-root>
source venv/bin/activate
python -m dotenv run -- python -m flask --app wsgi:app verify-migration-baseline
python -m dotenv run -- python -m flask --app wsgi:app db stamp 20260610_0001
python -m dotenv run -- python -m flask --app wsgi:app db current
```

Stamp only when the verifier reports:

```text
Database schema matches migration baseline 20260610_0001
```

For an empty database, use `db upgrade` instead. Do not run `db.create_all()`
or a standalone WebAuthn SQL script in production.

### 3. Upload and Run the Bootstrap

This archive installs root-owned deployment assets. It is not an application
release:

```powershell
git archive --format=tar.gz --output=".\sitbank-bootstrap.tar.gz" HEAD
scp -i "C:\path\to\existing-ec2-key.pem" `
  ".\sitbank-bootstrap.tar.gz" `
  "student12@sitbank.duckdns.org:/tmp/"
```

On EC2:

```bash
sudo install -d -m 0755 /opt/sitbank-bootstrap
sudo tar -xzf /tmp/sitbank-bootstrap.tar.gz -C /opt/sitbank-bootstrap
cd /opt/sitbank-bootstrap
sudo bash ops/deploy/bootstrap-container-ec2 \
  WenJiangg/SITBank \
  sitbank.duckdns.org \
  <current-service> \
  <current-app-root>
```

Use `-` for either legacy argument when no old service or directory exists.
The bootstrap installs Docker Engine and Compose, checksum-verified Cosign,
the SITBank service and restricted wrappers, and the root-owned deployment
configuration. It does not add `sitbank-deploy` to the Docker group.

Review `/etc/sitbank/deploy.conf`. It must contain the expected GHCR repository,
workflow identity, public host, and exact legacy service/path supplied above.

### 4. Prepare Host Policy Files

Keep reviewed production copies outside the image:

```bash
sudo install -o root -g 10001 -m 0640 \
  <current-common-passwords-path> \
  /etc/sitbank/common-passwords.txt
sudo install -o root -g 10001 -m 0640 \
  <current-approved-aaguids-path> \
  /etc/sitbank/fido-approved-aaguids.json
sudo install -o root -g 10001 -m 0640 \
  <current-mds-cache-path> \
  /etc/sitbank/fido-mds-cache.json
sudo -u sitbank-container test -r /etc/sitbank/common-passwords.txt
sudo -u sitbank-container test -r /etc/sitbank/fido-approved-aaguids.json
sudo -u sitbank-container test -r /etc/sitbank/fido-mds-cache.json
```

Do not replace production FIDO policy files with checked-in fail-closed
placeholders.

### 5. Configure the Restricted Deployment Key

Generate a dedicated Ed25519 key. Do not reuse a personal EC2 key:

```powershell
ssh-keygen -t ed25519 -a 100 `
  -f "$HOME\.ssh\sitbank_github_actions" `
  -C "github-actions-sitbank"
```

Add the public key to `/home/sitbank-deploy/.ssh/authorized_keys`, prefixed
with:

```text
restrict ssh-ed25519 AAAA... github-actions-sitbank
```

Store the private key only as `PROD_EC2_SSH_PRIVATE_KEY` in the `production`
environment. Verify the server host-key fingerprint through the EC2 console or
another trusted channel:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Store the verified complete `ssh-keyscan -H -t ed25519
sitbank.duckdns.org` result as `PROD_EC2_KNOWN_HOSTS`.

### 6. Seed Container Secrets for a Manual First Deployment

Skip this when GitHub will provide the first protected runtime bundle.

```bash
sudo install -d -o root -g root -m 0700 /etc/sitbank/runtime-import
sudo <current-app-root>/venv/bin/python \
  /opt/sitbank/import_legacy_env.py \
  --source <current-app-root>/.env \
  --destination /etc/sitbank/runtime-import \
  --public-host sitbank.duckdns.org
sudo install -o root -g root -m 0600 \
  /etc/sitbank/runtime-import/container.env \
  /etc/sitbank/container.env
sudo cp -a /etc/sitbank/runtime-import/secrets/. /etc/sitbank/secrets/
sudo chown -R root:root /etc/sitbank/secrets
sudo chmod 0700 /etc/sitbank/secrets
sudo chmod 0400 /etc/sitbank/secrets/*
sudo rm -rf /etc/sitbank/runtime-import
```

The importer refuses symlinked sources, multiline values, missing secrets, and
non-empty output directories.

### 7. Rename the PostgreSQL Database and Role

Generate a new URL-safe password on an administrator workstation, write the
complete URL to the GitHub environment secret through standard input, and send
the same password to a root-only EC2 file without placing it on a command
line:

```powershell
$bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(36)
$dbPassword = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$dbUrl = "postgresql+psycopg2://sitbank_user:$dbPassword@127.0.0.1:5432/sitbank_db"
$dbUrl | gh secret set PROD_DATABASE_URL --env production
$dbPassword | ssh -i "C:\path\to\existing-ec2-key.pem" `
  "student12@sitbank.duckdns.org" `
  "sudo install -o root -g root -m 0600 /dev/stdin /root/sitbank-db-password"
Remove-Variable dbPassword, dbUrl, bytes
```

The resulting `PROD_DATABASE_URL` is:

```text
postgresql+psycopg2://sitbank_user:<new-password>@127.0.0.1:5432/sitbank_db
```

For a manual deployment without GitHub environment access, also pipe `$dbUrl`
to `/etc/sitbank/secrets/database_url` using the same `ssh` and
`sudo install ... /dev/stdin` pattern before removing the PowerShell
variables.

Prepare the cutover:

```bash
sudo /usr/local/sbin/sitbank-database-cutover prepare \
  <current-database> \
  <current-role> \
  /root/sitbank-db-password
```

The helper:

- creates a fresh protected PostgreSQL backup;
- stops the configured legacy service;
- creates `sitbank_user`;
- renames the database to `sitbank_db`;
- transfers database, schema, and object ownership;
- records rollback state without storing the password;
- deletes the temporary password file.

If deployment fails before readiness, the deploy wrapper calls:

```bash
sudo /usr/local/sbin/sitbank-database-cutover rollback
```

After successful readiness it removes the former role with:

```bash
sudo /usr/local/sbin/sitbank-database-cutover finalize
```

### 8. Deploy and Verify

Set all GitHub production secrets and variables, then set
`PROD_DEPLOY_ENABLED=true` and run the workflow from `main`.

The deployment wrapper verifies the private input bundle, Cosign identity,
immutable digest, image revision label, production configuration, migrations,
direct readiness, and Nginx/TLS readiness. On first-cutover failure it restores
the database identity and restarts the configured legacy service.

After readiness succeeds, it disables and removes the configured legacy unit
and application directory. There is no new active `/var/www` application
directory.

Validate:

```bash
sudo systemctl --no-pager --full status sitbank-container
sudo docker inspect --format '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}}' \
  sitbank-app
sudo docker inspect --format '{{json .Config.Env}}' sitbank-app
sudo -u postgres psql -tAc \
  "SELECT datname, pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'sitbank_db';"
curl --fail https://sitbank.duckdns.org/health/ready
```

The container user must be `10001:10001`, the root filesystem must be
read-only, `sitbank_db` must be owned by `sitbank_user`, and container
environment output must contain only non-secret settings and `_FILE` paths.

## Later Deployments and Rollback

Later deployments preserve the current digest and runtime bundle before
replacement. Failed direct or public readiness restores the previous secrets
and image automatically.

Database migrations are not reversed during application rollback. Every
migration must remain backward-compatible with the previously deployed image.

Useful commands:

```bash
sudo systemctl status sitbank-container
sudo docker logs --tail 200 sitbank-app
sudo docker inspect --format '{{.State.Health.Status}}' sitbank-app
sudo cat /var/lib/sitbank-container/current
curl --fail -H 'X-Forwarded-Proto: https' \
  http://127.0.0.1:5000/health/ready
curl --fail https://sitbank.duckdns.org/health/ready
```

## Secure Manual Deployment

When GitHub environment deployment is unavailable, leave
`PROD_DEPLOY_ENABLED=false`. The `publish` job still builds, scans, signs, and
publishes the private immutable digest.

Obtain the successful workflow commit SHA and digest. Use a temporary GHCR
token with read-only package access:

```bash
sudo -iu sitbank-deploy
umask 077
read -r -p "GHCR username: " ghcr_user
read -r -s -p "Temporary GHCR read token: " ghcr_token
printf '\n'
printf '%s\n%s\n' "$ghcr_user" "$ghcr_token" \
  > "incoming/registry-COMMIT_SHA.credentials"
unset ghcr_token
exit
```

Then run the same root wrapper:

```bash
sudo /usr/local/sbin/sitbank-container-deploy \
  COMMIT_SHA \
  ghcr.io/wenjiangg/sitbank@sha256:<digest>
```

The wrapper removes the credential file and applies the same signature,
revision, migration, readiness, cleanup, and rollback checks as GitHub
Actions. Do not deploy unsigned locally built production images.

## Security-Sensitive Files

Treat changes to these paths as production-security changes:

- `.github/workflows/`
- `Dockerfile`
- `compose.prod.yml`
- `ops/container/`
- `ops/deploy/`
- `ops/systemd/`
- `ops/sudoers/`
- `config.py`

Never commit `.env` files, private keys, GHCR tokens, database or Redis
credentials, password peppers, MFA encryption keys, session HMAC keys, FIDO
private material, database dumps, cookies, CSRF tokens, or session IDs.

## References

- [Docker Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/)
- [GitHub container publishing](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)
- [Sigstore keyless signing](https://docs.sigstore.dev/cosign/signing/signing_with_containers/)
- [Docker Engine security](https://docs.docker.com/engine/security/)
