# Deployment

## Current Architecture

Only Flask/Gunicorn runs in the SITBank container. Nginx, TLS, PostgreSQL, Redis, backups, and FIDO policy files remain host-managed on EC2.

- Production public host: `sitbank.duckdns.org`
- Production admin host: `admin-sitbank.duckdns.org`
- Staging public host: `staging-sitbank.duckdns.org`
- Production image form: `ghcr.io/wenjiangggg/sitbank@sha256:<digest>`
- Repository identity: `WenJiangggg/SITBank`
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
`PASSWORD_RESET_BASE_URL`, `SMTP_HOST`, `SMTP_PORT`, and `SMTP_USE_TLS` in the
container runtime environment. Production rejects console reset email and
non-HTTPS reset base URLs.

Deploy the signed image through the restricted wrapper so it runs
`production-check`, `db upgrade`, `apply-runtime-db-privileges`,
`verify-runtime-db-privileges`, and readiness checks before declaring success.

Production deployment runs from the trusted `main` workflow only after release
verification and staging deployment both succeed. Leave the repository variable
`PROD_DEPLOY_ENABLED` unset or false until the production admin secret files and
matching `PROD_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID` are ready; when the flag is not
explicitly true, production deployment is skipped.

Production also requires a DNS record for `admin-sitbank.duckdns.org` pointing
at the same EC2 edge, Certbot files under
`/etc/letsencrypt/live/admin-sitbank.duckdns.org/`, and root-managed admin
secret files under `/etc/sitbank/secrets`: `admin_secret_key`,
`admin_wtf_csrf_secret_key`, `admin_session_hmac_keys_json`,
`admin_database_url`, `admin_redis_url`, and `admin_password_pepper_b64`.
`admin_database_url` must use a dedicated admin runtime database role and must
not reuse either `database_url` or `database_migration_url`.

When a trusted audit anchor has been exported, set
`SECURITY_AUDIT_ANCHOR_PATH=/var/lib/sitbank/audit-anchor.json` in the
root-managed runtime configuration so `check-security-alerts` verifies the
hash chain and compares the anchor during automated alert runs. Audit trigger
changes require `db upgrade`, then `apply-runtime-db-privileges` and
`verify-runtime-db-privileges`; they do not require an EC2 edge bootstrap
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

## Production Edge and Network Hardening

The reviewed production bootstrap installs and enables the production edge from `ops/nginx/sitbank-production.conf`, `ops/nginx/sitbank-production-rate-limits.conf`, and `ops/nginx-proxy-headers.conf`. Any change to those files requires a production bootstrap after merge.

- Public ingress is TCP `80` and `443` only.
- SSH is restricted to an administrator IP allowlist, AWS Systems Manager, a bastion, or VPN.
- Nginx terminates TLS, redirects HTTP to HTTPS, and forwards only expected proxy headers.
- Gunicorn binds only to `127.0.0.1:5000`.
- Admin Gunicorn binds only to `127.0.0.1:5002` and is reached only by the
  `admin-sitbank.duckdns.org` Nginx server block.
- `compose.prod.yml` publishes no app ports.
- `/health/ready` is for local deployment and load-balancer checks and should deny public traffic.
- Admin `/health/ready` is not public through Nginx. Admin routes use
  `deny all` by default until a future VPN, explicit IP allowlist, or
  equivalent network control is configured.
- Cloudflare or AWS WAF should sit in front of Nginx for managed common, SQL injection, XSS, bot, and protocol anomaly rules.
- Cloudflare or AWS WAF rules and security-group allowlists are still infrastructure state and must be checked manually.
- Admin WebAuthn/passkey authentication and admin step-up are Phase 2 and are
  not implemented in this PR. The current admin app is not publicly usable and
  must not expose password-only administrator login.

Verification:

```bash
sudo test -r /etc/letsencrypt/live/sitbank.duckdns.org/fullchain.pem
sudo nginx -t
sudo ss -ltnp | grep -E ':(80|443|5000|5002)([[:space:]]|$)'
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-app
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-admin
curl --fail https://sitbank.duckdns.org/health/live
curl -I https://sitbank.duckdns.org/health/ready
curl -I https://admin-sitbank.duckdns.org/health/ready
curl -I https://admin-sitbank.duckdns.org/login
```

Expected: local customer and admin readiness succeeds, external `/health/ready`
returns `403`, and admin public routes return `403` or are otherwise denied by
Nginx.

Staging admin must follow the same boundary pattern as production. Do not expose
admin routes publicly. The staging admin service must bind only to localhost,
use a dedicated Nginx server block, and deny public admin traffic unless an
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
sudo certbot renew --dry-run
```

Then run `ops/deploy/bootstrap-container-ec2 staging WenJiangggg/SITBank staging-sitbank.duckdns.org`. The bootstrap installs the Nginx proxy header snippet and rate-limit include, then runs `sudo nginx -t` before `sudo systemctl reload nginx`. This edge setup is separate from application deployment.

Staging verification:

```bash
curl -k -I https://staging-sitbank.duckdns.org/
curl -k -I -u "$STAGING_BASIC_AUTH_USER:$STAGING_BASIC_AUTH_PASSWORD" \
  https://staging-sitbank.duckdns.org/
curl -k -I https://staging-sitbank.duckdns.org/health/ready
curl -fsS http://127.0.0.1:5001/health/ready
```

Expected: unauthenticated `/` returns `401`, authenticated `/` returns `200`, external `/health/ready` returns `403`, and local app readiness succeeds.
