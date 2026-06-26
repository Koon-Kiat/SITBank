# Deployment

## Current Architecture

Only Flask/Gunicorn runs in the SITBank container. Nginx, TLS, PostgreSQL, and backups remain host-managed on EC2. Sessions, authentication counters, OTP/reset state, alert dedupe, and breached-password circuit state live in application-owned PostgreSQL tables.

- Production public host: `sitbank.duckdns.org`
- Production admin host: `admin-sitbank.duckdns.org`
- Staging public host: `staging-sitbank.duckdns.org`
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

## Database Baseline

Existing databases that already have the baseline tables must be adopted into Alembic instead of recreated.

```bash
python -m flask --app wsgi:app verify-migration-baseline
python -m flask --app wsgi:app db stamp 20260610_0001
python -m flask --app wsgi:app db upgrade
```

Do not run `db.create_all()` in deployment. For role cutover use `sitbank-database-cutover prepare`, review the generated SQL, and execute it only during an approved maintenance window.

## Deployment Prerequisites

Install `/etc/sitbank/secrets/security_alert_webhook_url` or
`/etc/sitbank-staging/secrets/security_alert_webhook_url` with the
operator-managed HTTPS alert webhook for that environment. Install
`smtp_username` and `smtp_password` secret files for the reset email provider,
and set `PASSWORD_RESET_EMAIL_BACKEND=smtp`, `PASSWORD_RESET_EMAIL_FROM`,
`PASSWORD_RESET_BASE_URL`, `SMTP_HOST`, `SMTP_PORT`, and `SMTP_USE_TLS=true` in
the container runtime environment. Production rejects console reset email,
non-HTTPS reset base URLs, and plaintext SMTP delivery.

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

Each target produces JSON, text log, HTML, scan metadata, and a policy-finding
file. They are retained as GitHub Actions artifacts for 90 days. The target job
summary identifies the UTC scan time, host, run ID/attempt, scanner version,
and pass/fail result. TLS scanning uses no application credentials and the
workflow contains no application secrets.

The verification gate fails for SSLv2, SSLv3, TLS 1.0, or TLS 1.1; weak, NULL,
anonymous, export, RC4, or 3DES ciphers; expired certificates; hostname
mismatches; untrusted, incomplete, or missing certificate chains; any
`testssl.sh` HIGH, CRITICAL, or FATAL finding; and scan/JSON-generation errors.
MEDIUM/LOW/INFO findings remain in the evidence and require operator review;
they are not an automatic release block unless they match one of the explicit
prohibited classes above.

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

The verifier is read-only. It checks `certbot`, an enabled and active
`certbot.timer`, every expected `fullchain.pem`, and each resolved
`privkey.pem` target. The `live` private-key path is normally a symlink; the
resolved target must remain below `/etc/letsencrypt`, be owned by `root`, be
group-owned by `root`, be neither group-writable nor world-writable, and grant
no permissions to other users. The normal state is `root:root` mode `0600` (or
a stricter equivalent). A `0640` dedicated TLS-read-group design is allowed
only after that group, its membership, and the Nginx privilege model are
documented and the verifier's explicit group allowlist has been reviewed and
updated. Do not use an application or container group for this purpose.

Verify the host state after issuance, after renewal changes, and before an edge
deployment:

```bash
sudo certbot certificates
sudo systemctl status certbot.timer
sudo /usr/local/sbin/verify-certbot-host-state production
sudo /usr/local/sbin/verify-certbot-host-state staging
sudo certbot renew --dry-run

sudo readlink -f /etc/letsencrypt/live/sitbank.duckdns.org/privkey.pem
sudo stat -c '%U %G %a %n' "$(sudo readlink -f /etc/letsencrypt/live/sitbank.duckdns.org/privkey.pem)"
sudo readlink -f /etc/letsencrypt/live/admin-sitbank.duckdns.org/privkey.pem
sudo stat -c '%U %G %a %n' "$(sudo readlink -f /etc/letsencrypt/live/admin-sitbank.duckdns.org/privkey.pem)"
sudo readlink -f /etc/letsencrypt/live/staging-sitbank.duckdns.org/privkey.pem
sudo stat -c '%U %G %a %n' "$(sudo readlink -f /etc/letsencrypt/live/staging-sitbank.duckdns.org/privkey.pem)"
```

When verifying directly from a reviewed checkout before bootstrap has installed
the script, use `sudo ops/deploy/verify-certbot-host-state production` or
`sudo ops/deploy/verify-certbot-host-state staging`. `certbot renew --dry-run`
is the required manual renewal test; do not print or copy private-key contents
while troubleshooting.

## Production Edge and Network Hardening

The reviewed production bootstrap installs and enables the production edge from `ops/nginx/sitbank-default.conf`, `ops/nginx/sitbank-production.conf`, `ops/nginx/sitbank-production-rate-limits.conf`, `ops/nginx-proxy-headers.conf`, and `ops/nginx/sitbank-tls-policy.conf`. The shared default config owns unknown-host rejection so production and staging can run on the same EC2 without duplicate Nginx `default_server` listeners. Any change to those files requires a production bootstrap after merge.

- Public ingress is TCP `80` and `443` only.
- SSH is restricted to an administrator IP allowlist, AWS Systems Manager, a bastion, or VPN.
- Nginx terminates TLS, redirects HTTP to HTTPS, and forwards only expected proxy headers.
- The shared TLS policy enables only TLS 1.2 and TLS 1.3, restricts TLS 1.2 to
  ECDHE+AEAD suites, pins the X25519/P-256/P-384 ECDHE curve preference, and
  limits TLS 1.3 to its standard AEAD suites.
- Gunicorn binds only to `127.0.0.1:5000`.
- Admin Gunicorn binds only to `127.0.0.1:5002` and is reached only by the
  `admin-sitbank.duckdns.org` Nginx server block.
- `compose.prod.yml` publishes no app ports.
- `/health/ready` is for local deployment and load-balancer checks and should deny public traffic.
- Admin `/` serves only a static Google verification and restricted-access
  notice at the public edge. Admin `/health/ready`, `/login`, and all other
  admin routes should remain denied by default at Nginx until a VPN, explicit
  IP allowlist, or equivalent network control is configured.
- Cloudflare or AWS WAF should sit in front of Nginx for managed common, SQL injection, XSS, bot, and protocol anomaly rules.
- Cloudflare or AWS WAF rules and security-group allowlists are still infrastructure state and must be checked manually.
- Flask admin auth is implemented only for root-admin-controlled invite
  onboarding with mandatory TOTP, separate admin sessions, and no
  password-only administrator login.

Verification:

```bash
sudo test -r /etc/letsencrypt/live/sitbank.duckdns.org/fullchain.pem
sudo /usr/local/sbin/verify-certbot-host-state production
sudo nginx -t
sudo nginx -T | grep -E 'ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_conf_command|ssl_session_tickets'
sudo ss -ltnp | grep -E ':(80|443|5000|5002)([[:space:]]|$)'
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-app
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-admin
curl --fail https://sitbank.duckdns.org/health/live
curl -I https://sitbank.duckdns.org/health/ready
curl https://admin-sitbank.duckdns.org/ | grep google-site-verification
curl -I https://admin-sitbank.duckdns.org/health/ready
curl -I https://admin-sitbank.duckdns.org/login
```

Expected: local customer and admin readiness succeeds, external `/health/ready`
returns `403`, admin `/` returns only the static verification page, and admin
application routes return `403` or are otherwise denied by Nginx. The Google
verification tag proves Search Console ownership only; dangerous-site removal
still requires reviewing Security Issues in Search Console and requesting a
Google review after the reported cause is resolved.

Staging admin must follow the same boundary pattern as production. Do not expose
admin routes publicly. The staging admin service must bind only to localhost
and use a separate loopback port from production admin when both environments
share one EC2 host. Production admin owns `127.0.0.1:5002`; staging admin owns
`127.0.0.1:5003`. If a staging admin Nginx server block is added later, deny
public admin traffic unless an
approved access path such as VPN, SSH tunnel, or explicit allowlist is
configured. Staging admin secrets must be root-managed under
`/etc/sitbank-staging/secrets` and must not reuse customer runtime secrets.

## Staging Edge Setup

Create a staging Basic Auth file before running the staging bootstrap:

```bash
sudo htpasswd -c /etc/nginx/.htpasswd-sitbank-staging <username>
sudo chown root:www-data /etc/nginx/.htpasswd-sitbank-staging
sudo chmod 0640 /etc/nginx/.htpasswd-sitbank-staging
```

Do not store the Basic Auth password or generated htpasswd hash in the repo.

Issue or renew staging TLS before bootstrap:

```bash
sudo certbot --nginx -d staging-sitbank.duckdns.org
sudo certbot certonly --webroot -w /var/www/certbot -d staging-sitbank.duckdns.org
sudo systemctl status certbot.timer
sudo /usr/local/sbin/verify-certbot-host-state staging
sudo certbot renew --dry-run
```

Then run `ops/deploy/bootstrap-container-ec2 staging hetp88/SITBank staging-sitbank.duckdns.org`. The bootstrap installs the Nginx proxy header snippet, TLS policy snippet, and rate-limit include, then runs `sudo nginx -t` before `sudo systemctl reload nginx`. This edge setup is separate from application deployment.

Staging verification:

```bash
curl -k -I https://staging-sitbank.duckdns.org/
curl -k -I -u "$STAGING_BASIC_AUTH_USER:$STAGING_BASIC_AUTH_PASSWORD" \
  https://staging-sitbank.duckdns.org/
curl -k -I https://staging-sitbank.duckdns.org/health/ready
curl -fsS http://127.0.0.1:5001/health/ready
sudo nginx -T | grep -E 'ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_conf_command|ssl_session_tickets'
testssl.sh --warnings batch --color 0 https://staging-sitbank.duckdns.org
```

Expected: unauthenticated `/` returns `401`, authenticated `/` returns `200`, external `/health/ready` returns `403`, and local app readiness succeeds.

After the staging TLS check passes, validate both production HTTPS hostnames
with `testssl.sh --warnings batch --color 0 https://sitbank.duckdns.org` and
`testssl.sh --warnings batch --color 0 https://admin-sitbank.duckdns.org`. The
`ssl_conf_command` TLS 1.3 setting is runtime-dependent, so `nginx -t` must
pass on the deployed host before any reload.
