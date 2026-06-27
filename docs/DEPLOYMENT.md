# Deployment

## Current Architecture

Only Flask/Gunicorn runs in the SITBank container. Nginx, TLS, PostgreSQL, and backups remain host-managed on EC2. Sessions, authentication counters, OTP/reset state, alert dedupe, and breached-password circuit state live in application-owned PostgreSQL tables.

- Production public host: `sitbank.duckdns.org`
- Production admin host: `admin-sitbank.duckdns.org`
- Staging public host: `staging-sitbank.duckdns.org`
- Production customer access: public HTTPS
- Staging access boundary: Cloudflare Access plus Authenticated Origin Pull
- Admin access boundary: Tailscale/private operator access only
- Production image form: `ghcr.io/hetp88/sitbank@sha256:<digest>`
- Repository identity: `hetp88/SITBank`
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

Production also requires a DNS record for `admin-sitbank.duckdns.org` pointing
at the same EC2 edge, Certbot files under
`/etc/letsencrypt/live/admin-sitbank.duckdns.org/`, and root-managed admin
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
that evidence passes. After a successful production deploy it scans both the
production customer and admin endpoints, making the resulting artifacts the
release's live TLS evidence. A production scan failure marks the deployment
workflow failed and requires investigation before the release is accepted. Run
the workflow manually after Nginx, certificate, DNS, load-balancer, CDN/WAF,
or host TLS changes outside the normal deployment path. It deliberately does
not run on pull requests: PRs do not create a separate public TLS endpoint.

By default it scans these hostname-only targets, which can be overridden as
manual workflow inputs when an approved endpoint changes:

| Environment | Workflow input | Default target | Artifact |
| --- | --- | --- | --- |
| Staging customer | `staging_host` | `https://staging-sitbank.duckdns.org` | `tls-scan-staging-sitbank` |
| Production customer | `production_host` | `https://sitbank.duckdns.org` | `tls-scan-prod-sitbank` |
| Production admin | `admin_host` | `https://admin-sitbank.duckdns.org` | `tls-scan-admin-sitbank` |

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

The verification gate fails for SSLv2, SSLv3, TLS 1.0, or TLS 1.1; weak, NULL,
anonymous, export, RC4, or 3DES ciphers; missing, disabled, or too-short HSTS;
expired certificates; hostname mismatches; untrusted, incomplete, or missing
certificate chains; any `testssl.sh` HIGH, CRITICAL, or FATAL finding; and
missing/invalid JSON evidence. MEDIUM/LOW/INFO findings remain in the evidence
and require operator review; they are not an automatic release block unless
they match one of the explicit prohibited classes above.

Normalization does not suppress malformed JSON generally or change policy
findings. All protocol, cipher, HSTS, certificate, chain, and severity gates
run against the strictly validated policy copy. Cloudflare Access readiness is
a separate zero-trust deployment concern and does not make staging TLS
evidence optional.

For a host-side/manual check, use the same full scan (do not use `-k` or supply
application credentials):

```bash
testssl.sh --warnings batch --color 0 --jsonfile testssl.json \
  --logfile testssl.log --htmlfile testssl.html \
  https://staging-sitbank.duckdns.org
testssl.sh --warnings batch --color 0 https://sitbank.duckdns.org
testssl.sh --warnings batch --color 0 https://admin-sitbank.duckdns.org
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
| `admin-sitbank.duckdns.org` | `/etc/letsencrypt/live/admin-sitbank.duckdns.org/fullchain.pem` | `/etc/letsencrypt/live/admin-sitbank.duckdns.org/privkey.pem` |
| `staging-sitbank.duckdns.org` | `/etc/letsencrypt/live/staging-sitbank.duckdns.org/fullchain.pem` | `/etc/letsencrypt/live/staging-sitbank.duckdns.org/privkey.pem` |

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
sudo readlink -f /etc/letsencrypt/live/admin-sitbank.duckdns.org/privkey.pem
sudo stat -c '%U %G %a %n' "$(sudo readlink -f /etc/letsencrypt/live/admin-sitbank.duckdns.org/privkey.pem)"
sudo readlink -f /etc/letsencrypt/live/staging-sitbank.duckdns.org/privkey.pem
sudo stat -c '%U %G %a %n' "$(sudo readlink -f /etc/letsencrypt/live/staging-sitbank.duckdns.org/privkey.pem)"
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
- Nginx terminates TLS, redirects production customer HTTP to HTTPS, returns
  `403` for non-ACME staging/admin HTTP roots, and forwards only expected
  proxy headers.
- The shared TLS policy enables only TLS 1.2 and TLS 1.3, restricts TLS 1.2 to
  ECDHE+AEAD suites, pins the X25519/P-256/P-384 ECDHE curve preference, and
  limits TLS 1.3 to its standard AEAD suites.
- Gunicorn binds only to `127.0.0.1:5000`.
- Admin Gunicorn binds only to `127.0.0.1:5002` and is reached only by the
  public `admin-sitbank.duckdns.org` Nginx server block for denied responses,
  or by a Tailscale/private operator path for the actual admin application.
- `compose.prod.yml` publishes no app ports.
- `/health/ready` is for local deployment and load-balancer checks and should deny public traffic.
- Admin `/`, `/health/ready`, `/login`, and all other admin routes remain
  denied by default at the public Nginx edge. The old public admin verification
  page is removed/denied as part of strict Tailscale-only admin access. Admin
  app access is through Tailscale/private operator access only; do not enable
  Tailscale Funnel or expose the admin app through the customer host.
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
curl -I https://admin-sitbank.duckdns.org/
curl -I https://admin-sitbank.duckdns.org/health/ready
curl -I https://admin-sitbank.duckdns.org/login
```

Expected: local customer and admin readiness succeeds, external `/health/ready`
returns `403`, admin `/` returns `403`, and admin application routes return
`403` or are otherwise denied by Nginx.

GitHub-hosted runners do not have stable source IPs. The normal
GitHub-hosted SSH deployment is acceptable only when the runner source is
allowlisted by a reviewed path such as a self-hosted runner, bastion, VPN
egress, or a time-boxed operator-approved maintenance window. Do not leave
global SSH open to support deployment.

Staging admin must follow the same boundary pattern as production. Do not expose
admin routes publicly. The staging admin service must bind only to localhost
and use a separate loopback port from production admin when both environments
share one EC2 host. Production admin owns `127.0.0.1:5002`; staging admin owns
`127.0.0.1:5003`. Use Tailscale SSH, Tailscale Serve, or another approved
private operator path for admin access; do not enable Tailscale Funnel and do
not add a public staging admin Nginx server block. Staging admin secrets must
be root-managed under `/etc/sitbank-staging/secrets` and must not reuse
customer runtime secrets.

## Staging Edge Setup

Staging uses Cloudflare Access as the identity-aware boundary and Cloudflare
Authenticated Origin Pulls to prevent direct EC2-origin bypass. The staging
Nginx app paths require a verified Cloudflare origin-pull client certificate
before proxying to Flask. The production customer hostname remains public.

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

Do not store Cloudflare API tokens, tunnel credentials, Access IdP secrets, or
origin certificate private keys in the repo. If the staging hostname cannot be
proxied by Cloudflare in the current DNS model, stop and make an approved DNS
change instead of disabling the origin-pull protection. The observed
`staging-sitbank.duckdns.org` hostname resolves directly to EC2; Cloudflare
Access cannot fully protect staging until traffic is routed through a
Cloudflare-managed zone/hostname or Cloudflare Tunnel.

Issue or renew staging TLS before bootstrap:

```bash
sudo certbot --nginx -d staging-sitbank.duckdns.org
sudo certbot certonly --webroot -w /var/www/certbot -d staging-sitbank.duckdns.org
sudo systemctl status certbot.timer
sudo /usr/local/sbin/verify-certbot-host-state staging
sudo /usr/local/sbin/verify-certbot-host-state --renewal-dry-run staging
```

Then run `ops/deploy/bootstrap-container-ec2 staging hetp88/SITBank staging-sitbank.duckdns.org`. The bootstrap installs the Nginx proxy header snippet, TLS policy snippet, and rate-limit include, verifies the staging Basic Auth file and Cloudflare origin-pull CA file, then runs `sudo nginx -t` before `sudo systemctl reload nginx`. This edge setup is separate from application deployment.

Staging verification:

```bash
curl -I https://staging-sitbank.duckdns.org/
curl -I -u "$STAGING_BASIC_AUTH_USER:$STAGING_BASIC_AUTH_PASSWORD" \
  https://staging-sitbank.duckdns.org/
curl -I https://staging-sitbank.duckdns.org/health/ready
curl -fsS http://127.0.0.1:5001/health/ready
curl --fail --resolve staging-sitbank.duckdns.org:443:127.0.0.1 \
  https://staging-sitbank.duckdns.org/health/ready
curl -I --resolve staging-sitbank.duckdns.org:443:<EC2_PUBLIC_IP> \
  https://staging-sitbank.duckdns.org/
sudo nginx -T | grep -E 'ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_conf_command|ssl_session_tickets'
curl -fsSI https://staging-sitbank.duckdns.org/ | grep -i '^strict-transport-security:'
testssl.sh --warnings batch --color 0 https://staging-sitbank.duckdns.org
```

Expected: unauthenticated browser traffic receives the Cloudflare Access
challenge before reaching staging, approved operators can pass Cloudflare
Access and then reach the normal staging controls, direct EC2-origin access to
`/` returns `403` without Cloudflare's origin-pull client certificate,
external `/health/ready` returns `403`, and local app readiness succeeds.

The complete operator runbook is
`docs/security/admin-and-staging-zero-trust-access.md`.

After the staging TLS check passes, validate both production HTTPS hostnames
with `testssl.sh --warnings batch --color 0 https://sitbank.duckdns.org` and
`testssl.sh --warnings batch --color 0 https://admin-sitbank.duckdns.org`. The
`ssl_conf_command` TLS 1.3 setting is runtime-dependent, so `nginx -t` must
pass on the deployed host before any reload.

Production HSTS validation should also confirm both public hostnames return the
production edge header before the production live TLS scan is accepted:

```bash
curl -fsSI https://sitbank.duckdns.org/ | grep -i '^strict-transport-security:'
curl -fsSI https://admin-sitbank.duckdns.org/ | grep -i '^strict-transport-security:'
```
