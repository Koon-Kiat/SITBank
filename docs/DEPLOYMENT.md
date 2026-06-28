# Deployment

## Current Architecture

Only Flask/Gunicorn runs in the SITBank container. Nginx, TLS, PostgreSQL, and backups remain host-managed on EC2. Sessions, authentication counters, OTP/reset state, alert dedupe, and breached-password circuit state live in application-owned PostgreSQL tables.

- Production public host: `sitbank.duckdns.org`
- Production private admin URL: `https://sitbank-ec2.tailca101b.ts.net/`
- Staging public host: `staging-sitbank.pp.ua`
- Staging Cloudflare Access host: `staging-sitbank.pp.ua`
- Production customer access: public HTTPS
- Staging access boundary: Cloudflare Access plus Authenticated Origin Pull
  plus origin-side Access JWT validation
- Admin access boundary: Tailscale/private operator access only
- Production image form: `ghcr.io/wenjiangg/sitbank@sha256:<digest>`
- Repository identity: `WenJiangg/SITBank`
- Production config root: `/etc/sitbank`
- Production compose dir: `/opt/sitbank`
- Production service: `sitbank-container.service`
- Production alert timer: `sitbank-security-alerts.timer`
- Production database: `sitbank_db`
- Production owner role: `sitbank_owner`
- Production app role: `sitbank_app`
- Production admin runtime role: `sitbank_admin` or another distinct least-privilege role
- Staging config root: `/etc/sitbank-staging`
- Staging compose dir: `/opt/sitbank-staging`
- Staging service: `sitbank-staging-container.service`

## Local Deployment Validation

The normal local CI command can run without Docker:

```bash
scripts/ci-local
```

If the Docker CLI or daemon is unavailable, normal mode marks Docker/Compose
checks as `SKIPPED` and reports an overall partial pass. That result covers the
non-Docker checks but does not prove the production or staging Compose model.

Use strict mode before deployment-related pull requests:

```bash
scripts/ci-local --require-docker
```

Alternatively:

```bash
CI_LOCAL_REQUIRE_DOCKER=1 scripts/ci-local
```

Strict mode fails when Docker, the Docker daemon, or Docker Compose is
unavailable. It runs `ops/container/validate-compose.sh`, which renders and
validates both `compose.prod.yml` and `compose.staging.yml` with the local
validation override. This checks the Compose service model, including the
customer/admin separation and wiring enforced by deployment tests, without
starting containers. CI/CD remains the source of truth for deployment
validation and release evidence.

SonarQube Cloud analysis is a separate reporting workflow, not a deployment
stage or production prerequisite. It receives no EC2, SSH, AWS, database, or
application runtime credentials and does not run bootstrap, publish, or deploy
commands. A SonarQube dashboard result must not be represented as deployed
runtime evidence. See `docs/security/sonarqube.md`.

## Database Baseline

Existing databases that already have the baseline tables must be adopted into Alembic instead of recreated.

```bash
python -m flask --app wsgi:app verify-migration-baseline
python -m flask --app wsgi:app db stamp 20260610_0001
python -m flask --app wsgi:app db upgrade
```

Do not run `db.create_all()` in deployment. For role cutover use `sitbank-database-cutover prepare`, review the generated SQL, and execute it only during an approved maintenance window.

## Registration Schema Reset For Disposable Environments

The registration schema requires verified email, full name, phone number, and a
server-generated account number for new customers. Existing disposable
development, staging, or demo databases with no real users may be reset or
recreated before applying the registration migration so fake phone numbers and
predictable account numbers are not preserved as long-lived data.

Do not drop or recreate a production-like database automatically. Any reset must
be an explicit operator action after confirming the environment has no real
users and after taking any required backup. If an existing database must be
preserved, the migration leaves unknown legacy phone numbers as `NULL`, keeps
uniqueness only for real non-null phone numbers, and assigns non-enumerable
server-generated account numbers to preserved rows.

## Deployment Prerequisites

Install `/etc/sitbank/secrets/security_alert_webhook_url` or
`/etc/sitbank-staging/secrets/security_alert_webhook_url` with the
operator-managed HTTPS alert webhook for that environment. Install
`smtp_username` and `smtp_password` secret files for the reset email provider,
and set `PASSWORD_RESET_EMAIL_BACKEND=smtp`, `PASSWORD_RESET_EMAIL_FROM`,
`PASSWORD_RESET_BASE_URL`, `SMTP_HOST`, `SMTP_PORT`, and `SMTP_USE_TLS=true` in
the container runtime environment. Production rejects console reset email,
non-HTTPS reset base URLs, and plaintext SMTP delivery.

Install the host-managed backup encryption recipients file before running
database cutover or scheduled backups:

- production: `/etc/sitbank/backup-age-recipients.txt`
- staging: `/etc/sitbank-staging/backup-age-recipients.txt`

The recipients file contains age public recipients only. Decryption identities
remain outside the repository and outside application containers. Bootstrap
installs `age`, `/usr/local/sbin/sitbank-backup-encrypted`, and
`/usr/local/sbin/sitbank-restore-preflight`; encrypted backups are stored under
`/var/backups/sitbank` or `/var/backups/sitbank-staging` as root-owned mode
`0600` `.pgdump.age` files. Restore checks are explicit operator preflights,
not Flask routes or deployment defaults.

Deploy the signed image through the restricted wrapper so it runs
`production-check`, `db upgrade`, `apply-runtime-db-privileges`,
`verify-runtime-db-privileges`, and readiness checks before declaring success.

Production deployment runs from the trusted `main` workflow only after release
verification, staging deployment, and the post-deployment staging TLS scan all
succeed. Leave the repository variable `PROD_DEPLOY_ENABLED` unset or false
until the production admin secret files and matching
`PROD_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID` are ready; when the flag is not
explicitly true, production deployment is skipped.

### GitHub Actions Variables

Configure these non-secret repository variables under **Settings > Secrets and
variables > Actions > Variables** when their reviewed defaults are not
appropriate:

| Variable | Safe behavior when unset | Workflow consumer |
| --- | --- | --- |
| `ENABLE_GITHUB_CODE_SECURITY` | Defaults to `false`; private-repository dependency review runs only when the value is exactly `true` | `dependency-review` in `.github/workflows/ci-deploy.yml` |
| `STAGING_PUBLIC_HOST` | Defaults to the reviewed staging hostname `staging-sitbank.pp.ua` | Staging deployment URL/configuration and post-deployment staging TLS verification |
| `PROD_PUBLIC_HOST` | Defaults to the reviewed production hostname `sitbank.duckdns.org` | Production deployment URL/configuration and post-deployment production TLS verification |
| `PROD_DEPLOY_ENABLED` | Defaults to disabled unless exactly `true` | Production deployment gate |

The host fallbacks are explicit repository conventions, not discovery
mechanisms. If DNS, certificates, or the public edge move, update the matching
repository variable in the same reviewed change; do not point verification at
an unrelated host. The reusable TLS workflow rejects empty values, URLs, and
command fragments and scans only HTTPS.

These values are hostnames and feature flags, so they are not secrets.
Credentials such as `SONAR_TOKEN`, SSH private keys, known-hosts material,
Cloudflare API tokens, database URLs, signing material, and application keys
must remain GitHub Actions secrets or protected environment secrets as already
documented. Existing staging and production deployment variables remain scoped
to their protected GitHub environments and are validated before deployment;
do not move secret values into repository variables.

Set `ROOT_ADMIN_EMAILS` in both protected GitHub environments before deploying
admin bootstrap support. It is a non-secret allowlist, but it is
security-critical: the value must be exactly 7 comma-separated SIT workplace
email addresses. The deployment workflow renders it into
`/etc/sitbank*/container.env` so `sitbank-admin` and `sitbank-staging-admin`
can enforce the fixed root-admin group. Root-admin bootstrap remains manual
over SSH inside the admin container; it is not a GitHub Actions workflow.

Production admin does not use a public DNS hostname. Keep admin access on the
private Tailscale Serve URL `https://sitbank-ec2.tailca101b.ts.net/` and do
not enable Tailscale Funnel. Production still requires root-managed admin
secret files under `/etc/sitbank/secrets`: `admin_secret_key`,
`admin_wtf_csrf_secret_key`, `admin_session_hmac_keys_json`,
`admin_session_lookup_hmac_key`, `admin_database_url`, and
`admin_password_pepper_b64`.
`admin_database_url` must use a dedicated admin runtime database role and must
not reuse either `database_url` or `database_migration_url`. Provision that
database role, and rotate its password, with a PostgreSQL administrator or
other approved role-management account before deployment; the deployment
wrapper only grants schema, table, sequence, and default privileges to the
existing role after migrations run.
`admin_session_lookup_hmac_key` must not reuse the customer
`session_lookup_hmac_key`.

`SECURITY_AUDIT_HMAC_KEY` is mandatory for production audit integrity.
`SECURITY_AUDIT_ANCHOR_PATH` is also mandatory in production; the one-EC2
runtime renders `SECURITY_AUDIT_ANCHOR_PATH=/var/lib/sitbank/security-audit.anchor`.
The bootstrap creates `/var/lib/sitbank` outside the database volume with
restrictive permissions and mounts it into the app/admin containers so
`check-security-alerts` verifies the hash chain and compares the anchor during
automated alert runs. Do not point the setting at an untrusted, world-writable,
repository-local, or database-local path just to satisfy deployment.
Audit trigger changes require `db upgrade`, then `apply-runtime-db-privileges`
and `verify-runtime-db-privileges`; they do not require an EC2 edge bootstrap
unless host-managed deployment, Nginx, or systemd files also changed.
Production also renders
`SECURITY_ALERT_STATE_PATH=/run/state/security-alert-state.json` and mounts the
host alert-state directory there so `check-security-alerts` can alert when
`users` or `security_audit_events` shrink after a direct database wipe.

Security alert scheduling is host-managed systemd state. Changes to
`ops/systemd/sitbank-security-alerts.service`,
`ops/systemd/sitbank-security-alerts.timer`, or
`ops/deploy/sitbank-container-runtime` require the trusted EC2 bootstrap after
merge so production receives the unit files and runs `systemctl daemon-reload`.
Then enable or verify the timer:

```bash
sudo systemctl enable --now sitbank-security-alerts.timer
sudo systemctl status sitbank-security-alerts.timer
journalctl -u sitbank-security-alerts.service
```

## Host-Managed TLS Certificate Lifecycle

Certificates are issued and renewed on the EC2 host. Certbot's ACME account
state, certificate archive, and TLS private keys are host-managed under
`/etc/letsencrypt`; none of that material may be committed to this repository.
The Flask application and its containers do not issue certificates and do not
mount or read TLS private keys. Normal deployment must never generate or
overwrite a private key.

## Live TLS Scan Evidence

The host configuration is necessary but not sufficient evidence of the public
TLS posture: the deployed certificate chain, Nginx/OpenSSL build, DNS, and edge
configuration decide what Internet clients are actually offered. The **Live TLS
scan evidence** GitHub Actions workflow records that external evidence with the
checksum-verified `testssl.sh` 3.2.3 source release.

The workflow runs weekly, can be started manually from the Actions tab, and is
called by the trusted deployment workflow. After a successful staging deploy it
scans the staging customer endpoint; production deployment is blocked until
that evidence passes. After a successful production deploy it scans the
production customer endpoint, making the resulting artifact the release's live
TLS evidence. A production scan failure marks the deployment
workflow failed and requires investigation before the release is accepted. Run
the workflow manually after Nginx, certificate, DNS, load-balancer, CDN/WAF,
or host TLS changes outside the normal deployment path. It deliberately does
not run on pull requests: PRs do not create a separate public TLS endpoint.

By default it scans these hostname-only targets, which can be overridden as
manual workflow inputs when an approved endpoint changes:

| Environment | Workflow input | Default target | Artifact |
| --- | --- | --- | --- |
| Staging customer | `staging_host` | `https://staging-sitbank.pp.ua` | `tls-scan-staging-sitbank` |
| Production customer | `production_host` | `https://sitbank.duckdns.org` | `tls-scan-prod-sitbank` |

Each target preserves the scanner's original `testssl.raw.json` and produces a
separate `testssl.json` for policy parsing, plus a text log, HTML report, scan
metadata, and policy-finding file. `testssl.sh` can emit the invalid JSON escape
`\,` in certificate subject strings such as the Cloudflare Authenticated
Origin Pull CA subject. The policy copy normalizes only that escape to a comma
before strict `jq empty` validation; the raw file remains unchanged for audit
evidence. All files are retained as GitHub Actions artifacts for 90 days. The
target job summary identifies the UTC scan time, host, run ID/attempt, scanner
version, and pass/fail result. TLS scanning uses no application credentials
and the workflow contains no application secrets.

## Release Smoke And DAST Evidence

Release verification runs `ops/container/smoke-test.sh` against the exact image
digest that will be deployed. When authenticated DAST is enabled, the helper
creates only synthetic customer identities, restricts the target to loopback or
the explicit smoke container host, and keeps real customer, staff, and admin
credentials out of the scan path.

DAST cookie handling is intentionally file-based. `auth-cookie` and
`zap-replacer.properties` are created under `umask 077`, written as `0600`
temporary files, mounted read-only into ZAP, and removed by the cleanup trap when
the smoke test exits. The host-visible ZAP command receives the non-secret
scanner home option `-dir /zap/wrk/.ZAP` plus
`-configfile /run/dast/zap-replacer.properties`; it must not include a raw cookie
value or `replacement=${...}` argument. Do not retain the DAST temporary
directory, upload it as an artifact, or paste its contents into release notes.
ZAP's own cache, browser profile, and report workspace run on container tmpfs
so scanner-owned files disappear with the container instead of breaking host
cleanup.

The production customer verification gate fails for
SSLv2, SSLv3, TLS 1.0, or TLS 1.1; weak, NULL, anonymous, export, RC4, or 3DES
ciphers; missing, disabled, or too-short HSTS; expired certificates; hostname
mismatches; untrusted, incomplete, or missing certificate chains; any
`testssl.sh` HIGH, CRITICAL, or FATAL finding; and missing/invalid JSON
evidence. MEDIUM/LOW/INFO findings remain in the evidence and require operator
review; they are not an automatic release block unless they match one of the
explicit prohibited classes above.

The Cloudflare Access-protected staging target `staging-sitbank.pp.ua` uses a
staging-specific acceptance gate because unauthenticated HTTP requests should
receive a `302 Found` Access challenge before the app. The staging scan still
fails unless TLS 1.0 and TLS 1.1 are not offered, TLS 1.2 and TLS 1.3 are
offered, certificate hostname/trust and chain checks are OK, the certificate
is not expired, HSTS meets the scanner minimum, insecure redirects are absent,
and the final `overall_grade` is `A` or `A+`. Generic LUCKY13 wording and
`cipherlist_OBSOLETED: offered` on Cloudflare Universal SSL are retained as
review evidence for protected staging, not automatic failures.

Because Cloudflare Access can generate the unauthenticated `302 Found`
response before traffic reaches origin Nginx, origin-side HSTS headers are not
sufficient evidence for staging. Configure the Cloudflare edge response for
`staging-sitbank.pp.ua` so the Access challenge includes
`Strict-Transport-Security` with at least the scanner minimum. Removing
Cloudflare Universal SSL obsolete CBC cipher offerings requires Advanced
Certificate Manager/custom cipher suite support; do not claim that
`cipherlist_OBSOLETED: offered` is fixed until that paid capability is enabled
and verified.

Normalization does not suppress malformed JSON generally or change policy
findings. All gates run against the strictly validated policy copy. Cloudflare
Access readiness is a separate zero-trust deployment concern and does not make
staging TLS evidence optional.

For a host-side/manual check, use the same full scan (do not use `-k` or supply
application credentials):

```bash
testssl.sh --warnings batch --color 0 --jsonfile testssl.json \
  --logfile testssl.log --htmlfile testssl.html \
  https://staging-sitbank.pp.ua
testssl.sh --warnings batch --color 0 https://sitbank.duckdns.org
```

SSL Labs remains optional, manual corroborating evidence. Use its public
report when an independently rendered assessment is useful for a release,
certificate renewal, CDN/WAF change, or incident record; retain a link or
screenshot with the release evidence. Production deployment must not depend on
SSL Labs automation because public API capacity and rate limits are external to
this repository.

Before first bootstrap, issue the certificates using the approved host Certbot
flow. The bootstrap retains its certificate-file preflight and installs
`ops/deploy/verify-certbot-host-state` as
`/usr/local/sbin/verify-certbot-host-state`. Once the required files exist, it
runs the verifier before it installs or reloads Nginx; it does not attempt
certificate issuance. A failed verification is a host remediation task, not an
application deployment workaround.

The normal verifier mode is read-only. It checks `certbot`, OpenSSL, an enabled
and active `certbot.timer`, and every expected Certbot certificate and key:

| Hostname | Certificate | Private key |
| --- | --- | --- |
| `sitbank.duckdns.org` | `/etc/letsencrypt/live/sitbank.duckdns.org/fullchain.pem` | `/etc/letsencrypt/live/sitbank.duckdns.org/privkey.pem` |
| `staging-sitbank.pp.ua` | `/etc/letsencrypt/live/staging-sitbank.pp.ua/fullchain.pem` | `/etc/letsencrypt/live/staging-sitbank.pp.ua/privkey.pem` |

Each `fullchain.pem` symlink must resolve to a regular file below
`/etc/letsencrypt`. OpenSSL must parse it, expose a valid `notAfter`, and confirm
that it is neither expired nor due to expire within the minimum validity
window. `CERTBOT_MIN_VALID_DAYS` configures that window and defaults to 14
days; it must be an integer from 1 through 3650. The leaf certificate must
contain an exact DNS SAN for its expected hostname. CN fallback and wildcard
matching are intentionally not accepted.

The `live` private-key path is normally a symlink; the resolved target must
remain below `/etc/letsencrypt`, be owned by `root`, be group-owned by `root`,
be neither group-writable nor world-writable, and grant no permissions to
other users. The normal state is `root:root` mode `0600` (or a stricter
equivalent). A `0640` dedicated TLS-read-group design is allowed only after
that group, its membership, and the Nginx privilege model are documented and
the verifier's explicit group allowlist has been reviewed and updated. Do not
use an application or container group for this purpose.

Verify the host state after issuance, after renewal changes, and before an edge
deployment:

```bash
sudo certbot certificates
sudo systemctl status certbot.timer
sudo /usr/local/sbin/verify-certbot-host-state production
sudo /usr/local/sbin/verify-certbot-host-state staging
sudo /usr/local/sbin/verify-certbot-host-state --renewal-dry-run production

sudo readlink -f /etc/letsencrypt/live/sitbank.duckdns.org/privkey.pem
sudo stat -c '%U %G %a %n' "$(sudo readlink -f /etc/letsencrypt/live/sitbank.duckdns.org/privkey.pem)"
sudo readlink -f /etc/letsencrypt/live/staging-sitbank.pp.ua/privkey.pem
sudo stat -c '%U %G %a %n' "$(sudo readlink -f /etc/letsencrypt/live/staging-sitbank.pp.ua/privkey.pem)"
```

When verifying directly from a reviewed checkout before bootstrap has installed
the script, use `sudo ops/deploy/verify-certbot-host-state production` or
`sudo ops/deploy/verify-certbot-host-state staging`. To use a reviewed
non-default threshold, pass it explicitly, for example
`sudo CERTBOT_MIN_VALID_DAYS=21 /usr/local/sbin/verify-certbot-host-state production`.

Normal bootstrap and deployment verification does not contact an ACME service,
so it does not claim to prove renewal readiness. The explicit
`--renewal-dry-run` mode first performs all local checks and then runs
`certbot renew --dry-run`; it may contact Let's Encrypt's staging service.
Run it after initial issuance, changes to Certbot or ACME configuration, and
renewal failures. Because `certbot renew` evaluates all configured renewal
lineages, one successful invocation is sufficient even though a target is
required for the local host checks. Do not print or copy private-key contents
while troubleshooting.

A failure is not a deployment bypass condition. Repair the path/ownership/mode,
install the certificate for the exact hostname, or renew/replace an expired or
near-expiry certificate, then rerun the verifier and `sudo nginx -t`. The live
TLS scan remains required external evidence for the chain and behavior actually
served through DNS and the deployed edge.

## Production Edge and Network Hardening

The reviewed production bootstrap installs and enables the production edge from `ops/nginx/sitbank-default.conf`, `ops/nginx/sitbank-production.conf`, `ops/nginx/sitbank-production-rate-limits.conf`, `ops/nginx-proxy-headers.conf`, and `ops/nginx/sitbank-tls-policy.conf`. The shared default config owns unknown-host rejection so production and staging can run on the same EC2 without duplicate Nginx `default_server` listeners. Any change to those files requires a production bootstrap after merge.

- Public ingress is TCP `80` and `443` only.
- SSH hardening is deferred in this branch. The Issue 186 OpenSSH drop-in,
  UFW/security-group rollout, and deployment-source migration path are not
  implemented here because they can affect GitHub Actions deployment access.
  Treat live SSH posture as operator-owned infrastructure evidence until a
  separate reviewed change lands.
- Nginx terminates TLS, redirects production customer HTTP to HTTPS, rejects
  unknown hosts with the shared default server, and forwards only expected
  proxy headers.
- The shared TLS policy enables only TLS 1.2 and TLS 1.3, restricts TLS 1.2 to
  ECDHE+AEAD suites, pins the X25519/P-256/P-384 ECDHE curve preference, and
  limits TLS 1.3 to its standard AEAD suites.
- Gunicorn binds only to `127.0.0.1:5000`.
- Admin Gunicorn binds only to `127.0.0.1:5002` and is reached only by the
  private Tailscale Serve operator path.
- `compose.prod.yml` publishes no app ports.
- `/health/ready` is for local deployment and load-balancer checks and should deny public traffic.
- No public admin Nginx server block is configured. The old public admin
  verification page is removed as part of strict Tailscale-only admin access.
  Admin app access is through Tailscale/private operator access only; do not
  enable Tailscale Funnel or expose the admin app through the customer host.
- Cloudflare or AWS WAF should sit in front of Nginx for managed common, SQL injection, XSS, bot, and protocol anomaly rules.
- Cloudflare or AWS WAF rules and security-group allowlists are still infrastructure state and must be checked manually.
- Flask admin auth is implemented only for root-admin-controlled invite
  onboarding with mandatory TOTP, separate admin sessions, and no
  password-only administrator login.

Verification:

```bash
sudo sshd -t
sudo ufw status numbered verbose
sudo test -r /etc/letsencrypt/live/sitbank.duckdns.org/fullchain.pem
sudo /usr/local/sbin/verify-certbot-host-state production
sudo nginx -t
sudo nginx -T | grep -E 'ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_conf_command|ssl_session_tickets'
sudo ss -ltnp | grep -E ':(80|443|5000|5002)([[:space:]]|$)'
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-app
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-admin
curl --fail https://sitbank.duckdns.org/health/live
curl -I https://sitbank.duckdns.org/health/ready
```

Expected: local customer and admin readiness succeeds, external customer
`/health/ready` returns `403`, and no public admin hostname is required.

GitHub-hosted runners do not have stable source IPs. The normal
GitHub-hosted SSH deployment is acceptable only when the runner source is
allowlisted by a reviewed path such as a self-hosted runner, bastion, VPN
egress, or a time-boxed operator-approved maintenance window. Do not leave
global SSH open to support deployment.

Staging admin must follow the same boundary pattern as production. Do not expose
admin routes publicly. The staging admin service must bind only to localhost
and use a separate loopback port from production admin when both environments
share one EC2 host. Production admin owns `127.0.0.1:5002`; staging admin owns
`127.0.0.1:5003`. Operators use Tailscale VPN before opening the private
production admin URL `https://sitbank-ec2.tailca101b.ts.net/`; staging admin
must use the same private-network pattern through an approved tailnet path. Do
not enable Tailscale Funnel and do not add a public staging admin Nginx server
block. Staging admin secrets must be root-managed under
`/etc/sitbank-staging/secrets` and must not reuse customer runtime secrets.

## Staging Edge Setup

Staging uses Cloudflare Access as the identity-aware boundary and Cloudflare
Authenticated Origin Pulls to prevent direct EC2-origin bypass. The staging
Nginx app paths require a verified Cloudflare origin-pull client certificate
before proxying to Flask. The production customer hostname remains public.

Provider-side desired state is repository-managed by
`ops/cloudflare/provision-staging-access` using the Cloudflare-managed hostname
model. From an operator shell with the variables documented in
`docs/security/cloudflare-staging-access.md`, review and apply it before
staging bootstrap:

```bash
python ops/cloudflare/provision-staging-access --plan
python ops/cloudflare/provision-staging-access --apply \
  --confirm APPLY-STAGING-ACCESS
```

Plan is offline and does not require a token. Apply needs a token limited to
Account `Access: Apps and Policies Write` and Zone `DNS Write`; it refuses a
broad or unmanaged Allow policy. The Access IdP, Authenticated Origin Pull
enablement/client certificate, origin CA file, AWS ingress rules, and operator
membership remain deliberate operator controls.

Copy the apply output into protected GitHub `staging` environment variables
`STAGING_CLOUDFLARE_ACCESS_AUD` and
`STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN`. Staging deployment refuses to render
without both. Its signed runtime bundle enables
`STAGING_CLOUDFLARE_ACCESS_JWT_REQUIRED=true`; production does not.

Create a staging Basic Auth file before running the staging bootstrap. This is
a secondary staging control and must not replace Cloudflare Access:

```bash
sudo htpasswd -c /etc/nginx/.htpasswd-sitbank-staging <username>
sudo chown root:www-data /etc/nginx/.htpasswd-sitbank-staging
sudo chmod 0640 /etc/nginx/.htpasswd-sitbank-staging
```

Do not store the Basic Auth password or generated htpasswd hash in the repo.

Install the Cloudflare Authenticated Origin Pull CA certificate on the EC2
host before running staging bootstrap:

```bash
sudo install -o root -g root -m 0644 \
  cloudflare-authenticated-origin-pull-ca.pem \
  /etc/nginx/cloudflare-authenticated-origin-pull-ca.pem
```

The staging bootstrap installs
`/usr/local/sbin/verify-cloudflare-origin-pull-ca` and the reviewed fingerprint
allowlist at
`/etc/sitbank-staging/cloudflare-origin-pull-ca-allowlist.json`. Before it
installs or enables the staging Nginx site, it requires the CA path to be a
root-owned regular non-symlink, permits only `root` or `www-data` as the group
with an approved non-writable mode, parses exactly one currently valid CA with
OpenSSL, and matches its SHA-256 fingerprint, subject, and issuer to the
allowlist. The bootstrap does not download a CA or call Cloudflare.

The repository allowlist initially approves only Cloudflare's global
Authenticated Origin Pull CA. A change to a zone-level or per-hostname CA must
first add its independently reviewed fingerprint and exact OpenSSL
subject/issuer in a separate reviewed commit. For a CA rotation:

1. Obtain the announced replacement from Cloudflare's official documentation
   in a controlled operator session, outside bootstrap.
2. Inspect it with `openssl x509 -noout -subject -issuer -fingerprint -sha256
   -startdate -enddate -ext basicConstraints`.
3. Independently confirm the source, `CA:TRUE`, validity, subject, issuer, and
   fingerprint; then add the new entry alongside the old entry.
4. Deploy the new CA and run the verifier and `nginx -t`. Remove the old entry
   only after every staging origin has completed the rotation.

Do not store Cloudflare API tokens, tunnel credentials, Access IdP secrets, or
origin certificate private keys in the repo. If the staging hostname cannot be
proxied by Cloudflare in the current DNS model, stop and make an approved DNS
change instead of disabling the origin-pull protection.
`staging-sitbank.pp.ua` is the Cloudflare-managed staging hostname for Access.
Use a Cloudflare-managed zone/hostname or Cloudflare Tunnel for this boundary;
for this deployment, the approved Cloudflare-managed hostname is
`staging-sitbank.pp.ua`. The retired DuckDNS staging hostname is not an active
staging deployment, Nginx, Certbot, or TLS-scan target. Issue #215 tracks the
staging domain and CI/CD migration history; Cloudflare Access and origin
protection work is referenced from #198, #199, and #210.

Issue or renew staging TLS before bootstrap:

```bash
sudo certbot --nginx -d staging-sitbank.pp.ua --cert-name staging-sitbank.pp.ua
sudo certbot certonly --webroot -w /var/www/certbot -d staging-sitbank.pp.ua --cert-name staging-sitbank.pp.ua
sudo systemctl status certbot.timer
sudo /usr/local/sbin/verify-certbot-host-state staging
sudo /usr/local/sbin/verify-certbot-host-state --renewal-dry-run staging
```

Then run `ops/deploy/bootstrap-container-ec2 staging WenJiangg/SITBank staging-sitbank.pp.ua`. The bootstrap installs the Nginx proxy header snippet, TLS policy snippet, rate-limit include, and staging Nginx server block for `staging-sitbank.pp.ua`; verifies the staging Basic Auth file and the pinned Cloudflare origin-pull CA; then runs `sudo nginx -t` before `sudo systemctl reload nginx`. This edge setup is separate from application deployment.

Staging verification:

```bash
python ops/cloudflare/provision-staging-access --verify \
  --evidence-file cloudflare-access-evidence.local.json
sudo /usr/local/sbin/verify-cloudflare-origin-pull-ca
curl -I https://staging-sitbank.pp.ua/
curl -I -u "$STAGING_BASIC_AUTH_USER:$STAGING_BASIC_AUTH_PASSWORD" \
  https://staging-sitbank.pp.ua/
curl -I https://staging-sitbank.pp.ua/health/ready
curl -fsS http://127.0.0.1:5001/health/ready
curl --fail --resolve staging-sitbank.pp.ua:443:127.0.0.1 \
  https://staging-sitbank.pp.ua/health/ready
curl -I --resolve staging-sitbank.pp.ua:443:<EC2_PUBLIC_IP> \
  https://staging-sitbank.pp.ua/
curl -I http://127.0.0.1:5001/
curl --fail http://127.0.0.1:5001/health/ready
sudo nginx -T | grep -E 'ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_conf_command|ssl_session_tickets'
curl -fsSI https://staging-sitbank.pp.ua/ | grep -i '^strict-transport-security:'
testssl.sh --warnings batch --color 0 https://staging-sitbank.pp.ua
```

Expected: unauthenticated browser traffic receives the Cloudflare Access
challenge at `staging-sitbank.pp.ua` before reaching staging, approved operators can pass Cloudflare
Access and then reach the normal staging controls, direct EC2-origin access to
`/` returns `403` without Cloudflare's origin-pull client certificate,
direct loopback Flask access to `/` returns `403` without an Access assertion,
external `/health/ready` returns `403`, local app readiness succeeds, and the
retired DuckDNS staging hostname is no longer an active Nginx target.

The script also verifies the live Access application and approved-operator
policy, proxied DNS state, application audience, edge challenge, and direct
origin denial. Flask consumes its printed
`STAGING_CLOUDFLARE_ACCESS_AUD` and
`STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN` values to validate the assertion's
signature, issuer, audience, expiry, and optional not-before time. A
missing/invalid assertion always receives a generic `403`; raw tokens are not
logged. Authenticated Origin Pull remains a separate required check.
The manual `cloudflare-access-verify.yml` workflow performs the same
non-mutating check in the protected `staging` environment and uploads only
sanitized evidence.

The complete operator runbook is
`docs/security/admin-and-staging-zero-trust-access.md`.

After the staging TLS check passes, validate production customer HTTPS with
`testssl.sh --warnings batch --color 0 https://sitbank.duckdns.org`. The
`ssl_conf_command` TLS 1.3 setting is runtime-dependent, so `nginx -t` must
pass on the deployed host before any reload. Do not add the private Tailscale
admin URL to public GitHub-hosted TLS scans.

Production HSTS validation should also confirm the public customer hostname
returns the production edge header before the production live TLS scan is
accepted:

```bash
curl -fsSI https://sitbank.duckdns.org/ | grep -i '^strict-transport-security:'
```
