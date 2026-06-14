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
.\.venv\Scripts\python.exe -m pip_audit --disable-pip --require-hashes -r requirements.lock
.\.venv\Scripts\python.exe -m pip_audit --disable-pip --require-hashes -r requirements-dev.lock
.\.venv\Scripts\python.exe -m bandit -q -ll -r app ops config.py wsgi.py
.\.venv\Scripts\python.exe ops/security/scan_repository_secrets.py --history
```

Refresh lock files only after reviewing dependency changes:

```powershell
.\.venv\Scripts\python.exe -m piptools compile --generate-hashes --output-file requirements.lock requirements.in
.\.venv\Scripts\python.exe -m piptools compile --allow-unsafe --generate-hashes --output-file requirements-dev.lock requirements-dev.in
.\.venv\Scripts\python.exe ops/security/check_dependency_locks.py
```

`requirements.in` and `requirements-dev.in` are the reviewed manifests.
`requirements.lock` and `requirements-dev.lock` are the only files installed
by CI and the production image. Every dependency change must regenerate and
commit both affected hashed lockfiles.

Dependabot updates are review-only. Do not auto-merge them. Rebase or recreate
stale dependency branches before review, and reject any PR that changes a
manifest without updating the corresponding hashed lockfiles. The production
image remains on Python 3.12; Docker updates to Python 3.13 or newer are
ignored until a deliberate runtime migration is approved.

Docker base images remain pinned by digest in the Dockerfile. Dependabot is
configured to propose Dockerfile base-image updates as pull requests, and those
PRs must run the same tests, Trivy scans, container smoke test, Compose
validation, actionlint, zizmor, and shellcheck checks as application changes.
Ordinary pull requests skip the full authenticated DAST crawl; scheduled scans
and release verification retain that coverage.
Base-image updates must not be auto-merged.

Docker Desktop is optional for ordinary Python development. Install it with
the WSL2 Linux-container backend when changing the Dockerfile, Compose model,
or container deployment scripts. GitHub Actions remains the authoritative
`linux/amd64` build and security test environment.

## Production and Staging Architecture

- Nginx terminates TLS and proxies to `127.0.0.1:5000`.
- The application container uses host networking to reach the existing
  localhost-only PostgreSQL and Redis services.
- Gunicorn binds only to `127.0.0.1:5000`; Compose publishes no ports.
- The application runs as UID/GID `10001`, with a read-only root filesystem,
  a size-limited `/tmp`, all Linux capabilities dropped, and
  `no-new-privileges`.
- Production images are private GHCR images addressed by immutable digest.
- The production image reference is
  `ghcr.io/wenjiangggg/sitbank@sha256:<digest>`.
- Images are scanned, receive SBOM and provenance attestations, and are signed
  with GitHub OIDC through Cosign.
- Secrets are mounted under `/run/secrets`; they are not stored in image
  layers, labels, or the container environment.
- The SSH deployment user is not a member of the `docker` group and can run
  only the validated root deployment wrapper.

Staging runs beside production without sharing its Compose project, paths,
containers, secrets, or data:

- `staging-sitbank.duckdns.org` proxies to `127.0.0.1:5001`.
- The staging Compose project is `sitbank-staging`.
- Its app, PostgreSQL, and Redis containers are `sitbank-staging-app`,
  `sitbank-staging-postgres`, and `sitbank-staging-redis`.
- Its named data volumes are `sitbank-staging-postgres-data` and
  `sitbank-staging-redis-data`.
- Its configuration and state live under `/etc/sitbank-staging`,
  `/opt/sitbank-staging`, and `/var/lib/sitbank-staging-container`.
- Only the staging app publishes a loopback host port. PostgreSQL and Redis
  remain on the private staging Docker network.

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
- `DATABASE_MIGRATION_URL_FILE`
- `REDIS_URL_FILE`
- `MFA_AES256_GCM_KEY_B64_FILE`
- `PASSWORD_PEPPER_B64_FILE`

Direct values remain supported for local development and tests. In production,
secret files must resolve beneath `/run/secrets`, must not be symlinks, and
must contain one non-empty UTF-8 line without NUL, CR, or embedded LF
characters.

Root-owned production copies live under `/etc/sitbank/secrets`; staging uses
the separate `/etc/sitbank-staging/secrets` directory. Compose mounts runtime
application secrets directly beneath `/run/secrets`; the deployment and
runtime helpers do not copy their values into process environment variables.
Non-secret settings live in each environment's `container.env`. Containers do
not load a production `.env` file.

Docker Compose implements local file-backed secrets as bind mounts, so Compose
does not apply service-level `uid`, `gid`, or `mode` attributes. The host files
are therefore the authority: application secrets must be root-owned, grouped
to GID `10001`, and mode `0440`; staging PostgreSQL and Redis bootstrap files
are root-owned mode `0444`. The deployment wrapper verifies readability before
starting containers. Each environment's `secrets` directory is
`root:sitbank-container` mode `0750`, allowing the locked container account to
traverse the directory without granting access to the SSH deployment user.

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
`SESSION_HMAC_KEYS_JSON`, `DATABASE_URL`, `DATABASE_MIGRATION_URL`, `REDIS_URL`,
`MFA_AES256_GCM_KEY_B64`, and `PASSWORD_PEPPER_B64` remain available for local
development, tests, and the one-time protected legacy import only.

`DATABASE_URL` is always the Flask runtime URL and must use the non-owner
`sitbank_app` role in staging and production. `DATABASE_MIGRATION_URL` is only
for Alembic migrations and database privilege verification, and must use the
`sitbank_owner` role. The long-running app service does not receive
`DATABASE_MIGRATION_URL_FILE`; the deployment wrapper bind-mounts it only for
`flask db upgrade` and `flask verify-runtime-db-privileges`.

Both staging and production deployments require the root-managed
`database_migration_url` file before deployment begins. A missing file is not
generated or copied from `database_url`: doing so would silently give the
long-running application role schema-owner privileges. The one-shot migration
and privilege-check containers receive the owner URL through an explicit
read-only bind mount; the long-running application container never receives
it.

PostgreSQL ownership is split by role:

- `sitbank_owner` owns `sitbank_db`/`sitbank_staging`, the `public` schema, and
  migration-created schema objects.
- `sitbank_app` is used by Flask during normal runtime and receives only
  `SELECT`, `INSERT`, `UPDATE`, `DELETE` on tables plus `USAGE`/`SELECT` on
  sequences.
- Default privileges for objects created by `sitbank_owner` grant the same DML
  privileges to `sitbank_app`.
- `sitbank_app` must not own schema objects and must not be able to create,
  alter, drop, or create extensions.

Redis session data is stored as a versioned HMAC envelope around the
Flask-Session serialized payload. `SESSION_HMAC_ACTIVE_KEY_ID` chooses the key
used for new writes, while every key in `SESSION_HMAC_KEYS_JSON` can verify
existing sessions during rotation. Missing signatures, invalid signatures,
unknown key IDs, malformed payloads, and unsupported legacy payload formats are
deleted, logged as `session_integrity` security events, and treated as a fresh
unauthenticated session without exposing raw session contents.

## GitHub Actions Pipeline

`.github/workflows/ci-deploy.yml`:

1. Pull requests run workflow security checks, pytest, compilation, package
   checks, Bandit, both dependency-lock audits, dependency review, current-tree
   and Git-history secret scanning, actionlint, zizmor, local image build,
   smoke tests, authenticated OWASP ZAP DAST, Compose validation, a visible
   non-blocking Critical Trivy report, a strict unexpected-Critical Trivy gate,
   and a blocking fixable High/Critical Trivy gate. Pull requests do not
   publish, sign, or deploy release images, and they do not reference staging
   or production secrets.
2. Manual `workflow_dispatch` staging runs must be started from `main`. Set
   `source_ref` to the candidate branch, tag, or commit SHA. The trusted
   workflow resolves it to an immutable `source_sha`, then tests, builds,
   scans, signs, and verifies that candidate digest.
3. Manual pre-merge staging deployment requires the workflow ref `main`,
   `target_environment=staging`, `deploy=true`, and
   `STAGING_DEPLOY_ENABLED=true`. It deploys only the exact digest emitted by
   `publish`; it cannot trigger production. Use `deploy=false` for candidate
   verification without deployment.
4. Pushes to `main` publish one immutable GHCR image with SBOM and provenance
   attestations, verify the exact digest, and deploy to staging only when
   `STAGING_DEPLOY_ENABLED=true`.
5. Production deployment is restricted to `main`, uses the `production`
   environment, and runs automatically only on a push when
   `PROD_DEPLOY_ENABLED=true` and staging succeeded in the same workflow.
   Production never skips disabled, skipped, or failed staging.
6. Release verification validates the exact digest from `publish`, checks the
   image revision label, validates the Compose model against that digest, runs
   migrations, `production-check`, Redis compatibility checks, `/health/ready`,
   authenticated ZAP DAST unless a manual run disables it, and both Trivy
   gates.
7. The tested digest is signed and verified with Cosign keyless GitHub OIDC.
   Each deployment also signs the non-secret runtime configuration bundle.
8. Deployment passes only the commit SHA and verified `sha256:` image digest to
   the protected EC2 wrapper. It never deploys `latest` and never rebuilds for
   staging or production.

Scheduled CI runs weekly on `main` and rebuilds the local image with `--pull`
and no cache before running the same smoke, authenticated DAST, Compose
validation, and Trivy checks. This keeps the pinned Debian/Python base image
under regular review and makes fixed upstream base digests or fixed Debian
packages visible without permitting scheduled publish or deployment.

Normal pull requests run the container smoke test, Compose validation, and
both Trivy gates without pulling the ZAP image. This keeps feedback fast while
preserving the full Python, SAST, dependency, secret, container, and image
security checks. Authenticated DAST still runs during `release-verify` for
every push to `main`. For manual staging, maintainers control it with the
`run_dast` input; `true` runs DAST before staging deployment and `false` is the
only manual opt-out. Scheduled runs continue to execute authenticated DAST for
regular deeper coverage.

Every third-party action is pinned to a full commit SHA. Publishing remains
available while deployment is disabled, allowing the same signed digest to be
verified without changing EC2.

The release flows are:

```text
Pull request:
  tests, container smoke, Compose validation, and Trivy; no full ZAP DAST

Manual pre-merge staging:
  run trusted workflow from main
  -> source_ref = candidate branch, tag, or SHA
  -> resolve immutable source_sha
  -> test/build/publish candidate source_sha
  -> release-verify exact digest using trusted main scripts
  -> deploy staging using trusted main scripts
  -> manual verification
  -> merge pull request

Automatic main release:
  main push -> publish -> release-verify -> staging -> production
```

Manual production deployment is disabled. A production deployment requires
the protected `main` push path and a successful staging deployment in that
same workflow run.

Candidate code is checked out only in jobs that test or build the candidate.
Jobs that render signed runtime bundles, access staging or production
environment secrets, upload over SSH, or invoke the EC2 deployment wrapper
explicitly check out `github.workflow_sha`, the trusted commit containing the
workflow selected from `main`. Feature-branch workflow and deployment scripts
therefore do not execute with staging or production secrets. The candidate
application itself receives only the isolated staging application secrets when
it is intentionally deployed to staging.

Before uploading a runtime bundle, each deployment job compares the SHA-256 of
the trusted checked-out `sitbank-container-deploy` wrapper with the root-owned
copy installed at `/usr/local/sbin/sitbank-container-deploy`. A mismatch fails
closed. After any reviewed change to the wrapper, rerun the matching EC2
bootstrap as an administrator before enabling that environment's next
deployment.

### Trusted EC2 Bootstrap Workflow

The separate **Bootstrap EC2 from trusted main** workflow refreshes root-owned
deployment files without building or deploying an application image. It is
manual-only and accepts one target: `staging` or `production`. Always select
`main` under **Use workflow from**. The workflow checks out
`github.workflow_sha`, creates an archive containing that exact trusted main
commit, signs the archive with GitHub OIDC, uploads it with strict SSH host-key
checking, and invokes the restricted root bootstrap wrapper. The EC2 wrapper
verifies the exact workflow identity and commit marker before running any
archive content, then the workflow confirms that the installed deployment
wrapper hash matches trusted main.

The selected GitHub Environment still applies its reviewers and branch
restrictions. Staging and production continue to use separate environment
variables, SSH keys, known-hosts entries, configuration roots, and application
secrets. The bootstrap workflow never transmits long-lived application
secrets and never deploys an image.

Use the workflows as follows:

```text
Pull request validation:
  PR -> tests, image checks, security gates

Normal application-only release:
  PR -> checks -> merge -> deploy staging -> deploy production

Reviewed EC2 deployment/runtime change:
  PR -> checks -> merge -> Bootstrap EC2 from trusted main
  -> deploy staging -> deploy production
```

EC2 bootstrap content is always taken from merged, protected `main`; an
unmerged branch can never replace root-owned deployment files. The existing
manual candidate-staging path may deploy a candidate application image to the
isolated staging runtime, but it still uses deployment and bootstrap logic
from trusted `main`. Ordinary pull requests remain validation-only unless a
maintainer explicitly starts that protected staging path. Do not use the
bootstrap workflow to work around a failed application test, image scan,
signature check, or deployment approval.

Run the bootstrap workflow after reviewed changes to root-installed deployment
assets, including:

- `ops/deploy/sitbank-container-bootstrap`
- `ops/deploy/sitbank-container-deploy`
- `ops/deploy/bootstrap-container-ec2`
- `ops/deploy/sitbank-container-runtime`
- `ops/deploy/sitbank-database-cutover`
- `ops/deploy/render_container_bundle.py`
- Compose, systemd, sudoers, Nginx, or other runtime files installed by the
  bootstrap

Bootstrap is normally unnecessary for Flask application code, templates,
static assets, tests, or Docker image-only changes unless the same change also
modifies a root-installed deployment/runtime file.

The first release containing `sitbank-container-bootstrap` is the one
exception: perform one final administrator-run bootstrap from reviewed
`main` to install `/usr/local/sbin/sitbank-container-bootstrap` and its narrow
sudoers entry. After that one-time installation, future trusted bootstrap
refreshes can use the manual workflow.

If the manual workflow reports that `sudo` requires a terminal or password,
the one-time installation has not been completed on EC2. Create and upload an
archive from the merged `main` branch using the administrator procedure in
**One-Time EC2 Transition**, then run:

```bash
cd /opt/sitbank-bootstrap
sudo bash ops/deploy/bootstrap-container-ec2 \
  staging WenJiangggg/SITBank staging-sitbank.duckdns.org
sudo test -x /usr/local/sbin/sitbank-container-bootstrap
sudo visudo -cf /etc/sudoers.d/sitbank-container-deploy
sudo -u sitbank-deploy sudo -n -l \
  /usr/local/sbin/sitbank-container-bootstrap
```

Only the first command requires the EC2 administrator account. A successful
staging bootstrap installs the shared restricted wrapper and sudoers rule, so
the protected workflow can perform later staging or production refreshes.

### Temporary Trivy Exception

`.trivyignore` contains a narrow temporary exception for only
`CVE-2026-42496` and `CVE-2026-8376`. Both findings are inherited from the
official `python:3.12.13-slim-trixie` Debian Trixie base image through
`perl-base`; the Dockerfile does not install Perl directly. Debian marks
`perl-base` as an essential package. Removing `perl-base` or mixing Debian sid packages into Trixie is riskier
than a narrow, documented exception while no safe Trixie fix exists.

The SITBank application does not invoke Perl and does not process
attacker-controlled tar archives with Perl. The exception does not apply to
application dependency vulnerabilities and must be reviewed and removed by
2026-06-26, or sooner when Debian or the official Python image publishes a
fixed package or fixed digest. Until removal, CI still prints the full Critical Trivy report with no ignore file,
blocks any new unexpected Critical finding through the strict `.trivyignore`
gate, and blocks fixable High/Critical findings with no ignore file.

### GitHub Environments

Create separate `staging` and `production` environments. Restrict both
environment deployment branches to `main`; manual staging still tests a
feature branch because the candidate is supplied through `source_ref`, while
the secret-bearing job runs trusted workflow code from `main`. Add required
reviewers, prevent self-review where supported, and protect `main` with
pull-request approval, required CI checks, and disabled force pushes.

Set these repository Actions variables before the first merge:

- Restrict production deployment branches to `main`.
- Add required production reviewers and prevent self-review where supported.
- Protect `main` with pull-request approval, required CI and CodeQL checks,
  required CODEOWNERS review for security-sensitive paths, stale-review
  dismissal, and disabled force pushes.
- Enable the dependency graph, Dependabot alerts, secret scanning, and push
  protection. CodeQL on a private repository requires GitHub Code Security.

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
- `STAGING_EC2_SSH_PRIVATE_KEY_B64`

Add these staging environment variables:

- `STAGING_EC2_DEPLOY_USER`
- `STAGING_EC2_HOST`
- `STAGING_EC2_PORT`
- `STAGING_MFA_ISSUER_NAME`
- `STAGING_PASSWORD_PBKDF2_ITERATIONS`
- `STAGING_PUBLIC_HOST`
- `STAGING_SESSION_HMAC_ACTIVE_KEY_ID`

Staging application runtime secrets remain root-managed under
`/etc/sitbank-staging/secrets`. They must be generated independently and must
not reuse production values. Do not copy database URLs, Redis URLs, Flask keys,
password peppers, MFA encryption keys, or session HMAC key material into
GitHub Actions secrets.

To test a candidate before merge, open **Actions**, select the CI workflow,
choose **Run workflow**, and set:

```text
Use workflow from: main
source_ref: <feature branch, tag, or full/short commit SHA>
target_environment: staging
deploy: true
run_dast: true
```

#### Production Environment

Add these production environment secrets:

- `PROD_EC2_KNOWN_HOSTS`
- `PROD_EC2_SSH_PRIVATE_KEY_B64`

Add these production environment variables:

- `PROD_EC2_DEPLOY_USER`
- `PROD_EC2_HOST`
- `PROD_EC2_PORT`
- `PROD_MFA_ISSUER_NAME`
- `PROD_PASSWORD_PBKDF2_ITERATIONS`
- `PROD_PUBLIC_HOST`, currently `sitbank.duckdns.org`
- `PROD_SESSION_HMAC_ACTIVE_KEY_ID`

Production application runtime secrets remain root-managed on the production
host under `/etc/sitbank/secrets`. Session HMAC keyring rotation is performed
by updating the protected host secret file and the non-secret active key ID
together during a controlled maintenance procedure.

#### Production EC2 Name Migration

Existing unprefixed production deployment names are deprecated and are not used
by the workflow. Rename them before enabling production deployment:

| Old name | New canonical name |
| --- | --- |
| `EC2_KNOWN_HOSTS` | `PROD_EC2_KNOWN_HOSTS` |
| `EC2_SSH_PRIVATE_KEY` | `PROD_EC2_SSH_PRIVATE_KEY_B64` |
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
git ls-files --eol -- ops/deploy ops/container ops/nginx ops/sudoers ops/systemd
git archive --format=tar.gz --output=".\sitbank-bootstrap.tar.gz" HEAD
scp -i "C:\path\to\existing-ec2-key.pem" `
  ".\sitbank-bootstrap.tar.gz" `
  "student12@sitbank.duckdns.org:/tmp/"
```

The listed Linux files must report `i/lf` and `w/lf`. Commit the reviewed
renormalization before creating the archive. On EC2, verify that the archived
Linux scripts use LF endings before running them:

```bash
tar -xOf /tmp/sitbank-bootstrap.tar.gz \
  ops/deploy/bootstrap-container-ec2 | sed -n '1,3l'
```

The displayed lines must not end in `\r$`. The bootstrap also refuses to
install CRLF-formatted Compose, systemd, sudoers, Nginx, or deployment files.

On EC2:

```bash
sudo install -d -m 0755 /opt/sitbank-bootstrap
sudo tar -xzf /tmp/sitbank-bootstrap.tar.gz -C /opt/sitbank-bootstrap
cd /opt/sitbank-bootstrap
sudo bash ops/deploy/bootstrap-container-ec2 \
  production \
  WenJiangggg/SITBank \
  sitbank.duckdns.org \
  <current-service> \
  <current-app-root>
```

Use `-` for either legacy argument when no old service or directory exists.
The bootstrap installs Docker Engine and Compose, checksum-verified Cosign,
the SITBank service and restricted wrappers, and the root-owned deployment
configuration. It does not add `sitbank-deploy` to the Docker group.

### 4. Bootstrap Isolated Staging on the Existing EC2 Host

Prepare the staging Nginx edge files on EC2 before running the reviewed
bootstrap. These files are local machine state, not repository content, and
must never be committed, copied into GitHub secrets, or included in a runtime
bundle.

Install the operator tools and create the Basic Auth file. `htpasswd` prompts
for the password without echoing it:

```bash
sudo apt-get update
sudo apt-get install -y nginx certbot python3-certbot-nginx apache2-utils

read -r -p "Staging Basic Auth username: " STAGING_BASIC_AUTH_USER
sudo htpasswd -c /etc/nginx/.htpasswd-sitbank-staging \
  "$STAGING_BASIC_AUTH_USER"
sudo chown root:www-data /etc/nginx/.htpasswd-sitbank-staging
sudo chmod 0640 /etc/nginx/.htpasswd-sitbank-staging
sudo test -s /etc/nginx/.htpasswd-sitbank-staging
unset STAGING_BASIC_AUTH_USER
```

Do not store the Basic Auth password or generated htpasswd hash in the repo.
To rotate the staging gate later, rerun `htpasswd` on EC2 and keep the same
`root:www-data` ownership and `0640` mode.

Issue the staging certificate before installing the final HTTPS server block.
If an HTTP-only staging Nginx site is already serving
`staging-sitbank.duckdns.org`, the Nginx plugin is acceptable:

```bash
sudo certbot --nginx -d staging-sitbank.duckdns.org
```

For a first-time host with no staging site yet, use an ACME-only webroot site
so production Nginx keeps running:

```bash
sudo install -d -m 0755 /var/www/certbot
sudo tee /etc/nginx/sites-available/sitbank-staging-acme >/dev/null <<'NGINX'
server {
    listen 80;
    listen [::]:80;
    server_name staging-sitbank.duckdns.org;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type "text/plain";
        try_files $uri =404;
    }

    location / {
        return 404;
    }
}
NGINX
sudo ln -sfn /etc/nginx/sites-available/sitbank-staging-acme \
  /etc/nginx/sites-enabled/sitbank-staging-acme
sudo nginx -t
# If validation succeeds:
sudo systemctl reload nginx
sudo certbot certonly --webroot \
  -w /var/www/certbot \
  -d staging-sitbank.duckdns.org
sudo rm -f /etc/nginx/sites-enabled/sitbank-staging-acme
sudo rm -f /etc/nginx/sites-available/sitbank-staging-acme
sudo nginx -t
# If validation succeeds:
sudo systemctl reload nginx
```

Check renewal without changing production or deploying the app:

```bash
sudo certbot renew --dry-run
```

Run this from the same reviewed bootstrap checkout after the htpasswd file and
certificate exist. It installs only staging Compose/config/state assets, the
Nginx proxy header snippet, the staging HTTPS server block, and the staging
rate-limit include. It backs up an existing staging site config, replaces it
from the reviewed repo files, runs `nginx -t`, and reloads Nginx only after
validation succeeds. It does not restart, migrate, publish, pull, or deploy a
SITBank application image:

```bash
cd /opt/sitbank-bootstrap
sudo bash ops/deploy/bootstrap-container-ec2 \
  staging \
  WenJiangggg/SITBank \
  staging-sitbank.duckdns.org
```

Copy the non-secret policy data into separate staging paths:

```bash
sudo install -o root -g 10001 -m 0640 \
  /etc/sitbank/common-passwords.txt \
  /etc/sitbank-staging/common-passwords.txt
sudo install -o root -g 10001 -m 0640 \
  /etc/sitbank/fido-approved-aaguids.json \
  /etc/sitbank-staging/fido-approved-aaguids.json
sudo install -o root -g 10001 -m 0640 \
  /etc/sitbank/fido-mds-cache.json \
  /etc/sitbank-staging/fido-mds-cache.json
```

Generate independent staging application and data-service secrets without
printing them. Set the same non-secret key identifier as the GitHub
`STAGING_SESSION_HMAC_ACTIVE_KEY_ID` variable:

```bash
sudo STAGING_SESSION_HMAC_ACTIVE_KEY_ID=2026-06-staging python3 - <<'PY'
import base64
import json
import os
import secrets
from pathlib import Path
from urllib.parse import quote

root = Path("/etc/sitbank-staging/secrets")
root.mkdir(mode=0o750, parents=True, exist_ok=True)
os.chown(root, 0, 10001)
os.chmod(root, 0o750)

def write(name, value, mode=0o440, gid=10001):
    path = root / name
    path.write_text(value, encoding="utf-8", newline="")
    os.chown(path, 0, gid)
    os.chmod(path, mode)

active_id = os.environ["STAGING_SESSION_HMAC_ACTIVE_KEY_ID"]
postgres_owner_password = secrets.token_urlsafe(32)
postgres_app_password = secrets.token_urlsafe(32)
redis_password = secrets.token_urlsafe(32)

write("secret_key", secrets.token_urlsafe(48))
write("wtf_csrf_secret_key", secrets.token_urlsafe(48))
write(
    "session_hmac_keys_json",
    json.dumps(
        {active_id: base64.b64encode(secrets.token_bytes(32)).decode("ascii")},
        separators=(",", ":"),
    ),
)
write("mfa_aes256_gcm_key_b64", base64.b64encode(secrets.token_bytes(32)).decode("ascii"))
write("password_pepper_b64", base64.b64encode(secrets.token_bytes(32)).decode("ascii"))
write(
    "database_url",
    "postgresql+psycopg2://sitbank_app:"
    f"{quote(postgres_app_password, safe='')}@postgres:5432/sitbank_staging",
)
write(
    "database_migration_url",
    "postgresql+psycopg2://sitbank_owner:"
    f"{quote(postgres_owner_password, safe='')}@postgres:5432/sitbank_staging",
)
write("redis_url", f"redis://:{quote(redis_password, safe='')}@redis:6379/0")
write("postgres_owner_password", postgres_owner_password, mode=0o444, gid=0)
write("postgres_app_password", postgres_app_password, mode=0o444, gid=0)
write(
    "redis.conf",
    "appendonly yes\n"
    "appendfsync everysec\n"
    "protected-mode yes\n"
    "bind 0.0.0.0\n"
    f"requirepass {redis_password}\n",
    mode=0o444,
    gid=0,
)
PY
```

If `nginx -t` fails after a reviewed Nginx change, do not reload. The bootstrap
keeps backups under `/var/backups/sitbank-staging`; restore the previous site
config, validate, and reload only after validation succeeds:

```bash
sudo install -o root -g root -m 0644 \
  /var/backups/sitbank-staging/nginx-sitbank-staging.<timestamp>.conf \
  /etc/nginx/sites-available/sitbank-staging
sudo nginx -t
# If validation succeeds:
sudo systemctl reload nginx
```

After the staging app has been deployed intentionally through the protected
staging deployment path, verify the edge behavior:

```bash
sudo nginx -t
curl -k -I https://staging-sitbank.duckdns.org/

read -r -p "Staging Basic Auth username: " STAGING_BASIC_AUTH_USER
read -r -s -p "Staging Basic Auth password: " STAGING_BASIC_AUTH_PASSWORD
printf '\n'
curl -k -I -u "$STAGING_BASIC_AUTH_USER:$STAGING_BASIC_AUTH_PASSWORD" \
  https://staging-sitbank.duckdns.org/
unset STAGING_BASIC_AUTH_USER
unset STAGING_BASIC_AUTH_PASSWORD

# Run this external check from a workstation or another non-loopback host.
curl -k -I https://staging-sitbank.duckdns.org/health/ready
curl -fsS http://127.0.0.1:5001/health/ready
```

Expected results: unauthenticated `/` returns `401`, authenticated `/` returns
`200`, external `/health/ready` returns `403`, and the local app readiness
endpoint returns the app's ready JSON body. From EC2, the deployment wrapper's
HTTPS readiness check still works through loopback because Nginx allows local
`/health/ready` requests:

```bash
curl -k -fsS \
  --resolve staging-sitbank.duckdns.org:443:127.0.0.1 \
  https://staging-sitbank.duckdns.org/health/ready
```

Staging is behind Basic Auth to keep preview traffic, scanners, and credential
stuffing away from the public banking app while testers still use normal app
authentication inside the gate. External `/health/ready` is blocked because it
reveals dependency readiness; local EC2 and deployment checks use loopback
instead. This edge setup is separate from application deployment: Certbot,
htpasswd, Nginx config replacement, rate-limit includes, `nginx -t`, and Nginx
reload do not publish or roll a container image.

Verify that staging assets are separate and production remains healthy:

```bash
sudo systemctl is-active sitbank-container.service
sudo test -r /etc/sitbank-staging/deploy.conf
sudo test -r /opt/sitbank-staging/compose.yml
sudo test -r /etc/sitbank-staging/postgres/init-sitbank-staging-roles.sh
sudo test -r /etc/nginx/.htpasswd-sitbank-staging
sudo test -r /etc/nginx/conf.d/sitbank-staging-rate-limits.conf
sudo test -r /etc/nginx/sites-available/sitbank-staging
sudo -u sitbank-container test -r /etc/sitbank-staging/secrets/database_url
sudo -u sitbank-container test -r /etc/sitbank-staging/secrets/database_migration_url
sudo -u sitbank-container test -r /etc/sitbank-staging/common-passwords.txt
curl --fail https://sitbank.duckdns.org/health/ready
```

Set `STAGING_PUBLIC_HOST=staging-sitbank.duckdns.org`,
`STAGING_EC2_HOST=sitbank.duckdns.org` or the EC2 address, and the matching
staging key identifier in the GitHub `staging` environment. Enable
`STAGING_DEPLOY_ENABLED=true` only after bootstrap, Nginx validation, Certbot,
and local asset checks pass. Run the `401`, `200`, `403`, and local ready
checks after the first intentional staging deployment before handing the URL
to testers.

The deployment workflow intentionally cannot update its own privileged EC2
validator. Use **Bootstrap EC2 from trusted main** after reviewed changes to
the deployment wrapper, Compose file, sudoers policy, systemd unit, or other
root-installed runtime assets. For the first release containing the restricted
bootstrap wrapper, use the administrator-run archive procedure above once;
subsequent refreshes use the signed manual workflow.

Review `/etc/sitbank/deploy.conf`. It must contain the expected GHCR repository,
workflow identity, public host, and exact legacy service/path supplied above.
If the server was bootstrapped before the GitHub repository rename, update the
three repository identity lines to:

```text
GITHUB_REPOSITORY=WenJiangggg/SITBank
GHCR_REPOSITORY=ghcr.io/wenjiangggg/sitbank
COSIGN_CERTIFICATE_IDENTITY=https://github.com/WenJiangggg/SITBank/.github/workflows/ci-deploy.yml@refs/heads/main
```

Staging and production both retain the exact trusted `main` workflow identity.
The candidate image revision label and deployment revision use the resolved
candidate `source_sha`, not `github.sha`.

The private GHCR package must grant Actions access to `WenJiangggg/SITBank`
before enabling production deployment.

### 5. Prepare Host Policy Files

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

### 6. Configure the Restricted Deployment Key

Generate a dedicated, unencrypted Ed25519 key for each environment. Do not
reuse a personal EC2 key or the original EC2 administrator PEM:

```powershell
ssh-keygen -t ed25519 -a 100 `
  -f "$HOME\.ssh\sitbank_github_actions_staging" `
  -C "github-actions-sitbank-staging"

ssh-keygen -t ed25519 -a 100 `
  -f "$HOME\.ssh\sitbank_github_actions_production" `
  -C "github-actions-sitbank-production"
```

When prompted, press Enter twice to leave the passphrase empty. GitHub Actions
cannot answer an interactive private-key passphrase prompt during deployment.

Add each `.pub` key to `/home/sitbank-deploy/.ssh/authorized_keys`, prefixed
with `restrict`. The staging entry, for example, is:

```text
restrict ssh-ed25519 AAAA... github-actions-sitbank-staging
```

Encode each private key as single-line Base64 and store the result as:

- `STAGING_EC2_SSH_PRIVATE_KEY_B64` in the `staging` environment.
- `PROD_EC2_SSH_PRIVATE_KEY_B64` in the `production` environment.

Base64 is transport encoding, not encryption; confidentiality still comes from
the GitHub environment secret. Encode the private file bytes directly. Do not
encode the `.pub` key, a filesystem path, or a PuTTY `.ppk`:

```powershell
$keyBytes = [System.IO.File]::ReadAllBytes(
  "$HOME\.ssh\sitbank_github_actions_staging"
)
[Convert]::ToBase64String($keyBytes) | Set-Clipboard
```

The copied value must be one uninterrupted line. Delete the obsolete raw
`STAGING_EC2_SSH_PRIVATE_KEY` or `PROD_EC2_SSH_PRIVATE_KEY` secret after the
corresponding Base64 deployment succeeds.

Verify that the corresponding public key is the one installed for
`sitbank-deploy`:

```powershell
ssh-keygen -lf "$HOME\.ssh\sitbank_github_actions_staging.pub" -E sha256
```

Verify the server host-key fingerprint through the EC2 console or another
trusted channel:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Store the verified complete `ssh-keyscan -H -t ed25519
sitbank.duckdns.org` result as `PROD_EC2_KNOWN_HOSTS`.

### 7. Seed Root-Managed Container Secrets

This step is mandatory. Automated deployments do not transmit long-lived
application secrets. Keep the root-owned files under `/etc/sitbank/secrets`
and rotate them through an administrator-controlled maintenance procedure or
AWS Secrets Manager.

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
sudo chown -R root:10001 /etc/sitbank/secrets
sudo chmod 0750 /etc/sitbank/secrets
sudo chmod 0440 /etc/sitbank/secrets/*
sudo rm -rf /etc/sitbank/runtime-import
```

The importer refuses symlinked sources, multiline values, missing secrets, and
non-empty output directories. After import, confirm that every file is
root-owned, unreadable by the SSH deploy user, and readable by container UID
`10001` only through the Compose secret mount.

### 8. Rename the PostgreSQL Database and Split Roles

Generate separate URL-safe passwords on an administrator workstation and send
the passwords plus complete database URLs directly to root-only EC2 files
without placing any secret value on a command line:

```powershell
function New-UrlSafePassword {
  $bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(36)
  [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$ownerPassword = New-UrlSafePassword
$appPassword = New-UrlSafePassword
$runtimeUrl = "postgresql+psycopg2://sitbank_app:$appPassword@127.0.0.1:5432/sitbank_db"
$migrationUrl = "postgresql+psycopg2://sitbank_owner:$ownerPassword@127.0.0.1:5432/sitbank_db"
$ownerPassword | ssh -i "C:\path\to\existing-ec2-key.pem" `
  "student12@sitbank.duckdns.org" `
  "sudo install -o root -g root -m 0600 /dev/stdin /root/sitbank-db-owner-password"
$appPassword | ssh -i "C:\path\to\existing-ec2-key.pem" `
  "student12@sitbank.duckdns.org" `
  "sudo install -o root -g root -m 0600 /dev/stdin /root/sitbank-db-app-password"
$runtimeUrl | ssh -i "C:\path\to\existing-ec2-key.pem" `
  "student12@sitbank.duckdns.org" `
  "sudo install -o root -g 10001 -m 0440 /dev/stdin /etc/sitbank/secrets/database_url"
$migrationUrl | ssh -i "C:\path\to\existing-ec2-key.pem" `
  "student12@sitbank.duckdns.org" `
  "sudo install -o root -g 10001 -m 0440 /dev/stdin /etc/sitbank/secrets/database_migration_url"
Remove-Variable ownerPassword, appPassword, runtimeUrl, migrationUrl
```

The resulting root-managed secret values are:

```text
database_url = postgresql+psycopg2://sitbank_app:<runtime-password>@127.0.0.1:5432/sitbank_db
database_migration_url = postgresql+psycopg2://sitbank_owner:<owner-password>@127.0.0.1:5432/sitbank_db
```

If the production database is already named `sitbank_db` from an earlier
container release, use the guarded in-place adoption path. First identify its
current owner:

```bash
current_owner="$(
  sudo -u postgres psql --no-psqlrc --tuples-only --no-align \
    --command "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'sitbank_db';"
)"
printf 'Current owner: %s\n' "${current_owner}"
```

After confirming that this is the role used by the current production
`database_url`, prepare the split:

```bash
sudo /usr/local/sbin/sitbank-database-cutover adopt-existing \
  "${current_owner}" \
  /root/sitbank-db-owner-password \
  /root/sitbank-db-app-password
```

This path creates a protected backup, briefly stops the current service,
transfers ownership to `sitbank_owner`, grants least-privilege runtime access
to `sitbank_app`, and restarts the previous service while deployment is
pending. The former role temporarily retains runtime DML access so production
does not remain offline while the verified deployment runs. Successful
deployment revokes that temporary access and removes the former role;
deployment failure restores its ownership automatically.

For a first cutover where the database still has its old name, use:

```bash
sudo /usr/local/sbin/sitbank-database-cutover prepare \
  <current-database> \
  <current-role> \
  /root/sitbank-db-owner-password \
  /root/sitbank-db-app-password
```

The helper:

- creates a fresh protected PostgreSQL backup;
- stops the configured legacy service;
- creates `sitbank_owner` and `sitbank_app`;
- renames the database to `sitbank_db`;
- transfers database, schema, and object ownership to `sitbank_owner`;
- grants `sitbank_app` DML on existing tables and sequence usage;
- configures default privileges so future `sitbank_owner` migrations grant
  `sitbank_app` DML and sequence usage automatically;
- revokes public schema creation and database privileges;
- records rollback state without storing passwords;
- deletes the temporary password files.

If deployment fails before readiness, the deploy wrapper calls:

```bash
sudo /usr/local/sbin/sitbank-database-cutover rollback
```

After successful readiness it removes the former role with:

```bash
sudo /usr/local/sbin/sitbank-database-cutover finalize
```

### 9. Deploy and Verify

Set the two SSH environment secrets and documented non-secret variables, then
set `PROD_DEPLOY_ENABLED=true` and run the workflow from `main`.

The deployment wrapper verifies the Sigstore-signed non-secret configuration
bundle, its checksum, Cosign workflow identity, immutable image digest, image
revision label, production configuration, runtime database least privilege,
migrations, direct readiness, and Nginx/TLS readiness. Application secrets
never pass through GitHub Actions. On first-cutover failure it restores the
database identity and restarts the configured legacy service.

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
sudo -u postgres psql -d sitbank_db -tAc \
  "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND r.rolname = 'sitbank_app';"
curl --fail https://sitbank.duckdns.org/health/ready
```

The container user must be `10001:10001`, the root filesystem must be
read-only, `sitbank_db` must be owned by `sitbank_owner`, Flask must use
`sitbank_app` through `database_url`, and container environment output must
contain only non-secret settings and runtime `_FILE` paths. The `sitbank_app`
object ownership count must be `0`. The long-running `sitbank-app` container
must not include `DATABASE_MIGRATION_URL_FILE`.

## Later Deployments and Rollback

Later deployments preserve the current digest and non-secret runtime
configuration before replacement. Failed direct or public readiness restores
the previous configuration and image automatically. Root-managed application
secrets are not replaced by ordinary deployments.

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
`PROD_DEPLOY_ENABLED=false`. The release pipeline still builds, scans, signs,
and publishes the private immutable digest.

Obtain the successful `release-verify` workflow commit SHA and signed digest.
Use a temporary GHCR token with read-only package access:

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
  sha256:<digest>
```

The wrapper removes the credential file and applies the same signature,
revision, migration, readiness, cleanup, and rollback checks as GitHub
Actions. Do not deploy unsigned locally built production images.

## Security Operations

The pipeline reduces supply-chain and common OWASP risk; it does not prove
that the application has no business-logic or authorization vulnerabilities.
Maintain a threat model and perform manual access-control and transaction-flow
testing before production use.

Operational requirements and response procedures are documented in
[`SECURITY.md`](SECURITY.md). In particular:

- Rotate any exposed credential immediately; deleting it from the latest
  commit is not sufficient.
- Review Dependabot PRs individually and regenerate both hashed lockfiles.
- Allow vulnerability exceptions only when they are documented, owned, and
  expire on a fixed date.
- Forward `sitbank-deploy` journald events, Docker logs, Nginx authentication
  events, and application audit events to centralized monitoring.
- Prefer GitHub OIDC with AWS Systems Manager over the long-lived SSH key when
  the AWS account owner can create the required IAM role and managed-instance
  permissions.

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
