# Deployment

## Current Architecture

Only Flask/Gunicorn runs in the SITBank container. Nginx, TLS, PostgreSQL, Redis, backups, and FIDO policy files remain host-managed on EC2.

- Production public host: `sitbank.duckdns.org`
- Staging public host: `staging-sitbank.duckdns.org`
- Production image form: `ghcr.io/wenjiangggg/sitbank@sha256:<digest>`
- Repository identity: `WenJiangggg/SITBank`
- Production config root: `/etc/sitbank`
- Production compose dir: `/opt/sitbank`
- Production service: `sitbank-container.service`
- Production database: `sitbank_db`
- Production owner role: `sitbank_owner`
- Production app role: `sitbank_app`
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
operator-managed HTTPS alert webhook for that environment. Deploy the signed
image through the restricted wrapper so it runs `production-check`, `db
upgrade`, `apply-runtime-db-privileges`, `verify-runtime-db-privileges`, and
readiness checks before declaring success.

When a trusted audit anchor has been exported, set
`SECURITY_AUDIT_ANCHOR_PATH=/var/lib/sitbank/audit-anchor.json` in the
root-managed runtime configuration so `check-security-alerts` verifies the
hash chain and compares the anchor during automated alert runs. Audit trigger
changes require `db upgrade`, then `apply-runtime-db-privileges` and
`verify-runtime-db-privileges`; they do not require an EC2 edge bootstrap
unless host-managed deployment, Nginx, or systemd files also changed.

## Production Edge and Network Hardening

The reviewed production bootstrap installs and enables the production edge from `ops/nginx/sitbank-production.conf`, `ops/nginx/sitbank-production-rate-limits.conf`, and `ops/nginx-proxy-headers.conf`. Any change to those files requires a production bootstrap after merge.

- Public ingress is TCP `80` and `443` only.
- SSH is restricted to an administrator IP allowlist, AWS Systems Manager, a bastion, or VPN.
- Nginx terminates TLS, redirects HTTP to HTTPS, and forwards only expected proxy headers.
- Gunicorn binds only to `127.0.0.1:5000`.
- `compose.prod.yml` publishes no app ports.
- `/health/ready` is for local deployment and load-balancer checks and should deny public traffic.
- Cloudflare or AWS WAF should sit in front of Nginx for managed common, SQL injection, XSS, bot, and protocol anomaly rules.
- Cloudflare or AWS WAF rules and security-group allowlists are still infrastructure state and must be checked manually.

Verification:

```bash
sudo test -r /etc/letsencrypt/live/sitbank.duckdns.org/fullchain.pem
sudo nginx -t
sudo ss -ltnp | grep -E ':(80|443|5000)([[:space:]]|$)'
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-app
curl --fail https://sitbank.duckdns.org/health/live
curl -I https://sitbank.duckdns.org/health/ready
```

Expected: local readiness succeeds and external `/health/ready` returns `403`.

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
