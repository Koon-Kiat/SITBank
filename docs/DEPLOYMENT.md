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

## Data Reset Required For Legacy MFA Removal

This release removes the legacy one-key MFA AES decrypt path and keeps envelope-encrypted MFA only. Existing test users, old MFA records, active sessions, and staging volumes must be discarded before deploying it.

Staging reset:

```bash
sudo systemctl stop sitbank-staging-container.service || true
sudo docker compose --project-name sitbank-staging -f /opt/sitbank-staging/compose.yml down -v || true
sudo docker volume rm sitbank-staging-postgres-data sitbank-staging-redis-data || true
sudo rm -f /etc/sitbank-staging/secrets/mfa_aes256_gcm_key_b64
sudo test -s /etc/sitbank-staging/secrets/mfa_kek_keys_json
sudo grep -q '^MFA_KEK_ACTIVE_ID=' /etc/sitbank-staging/container.env
```

Before rerunning deployment, create `/etc/sitbank-staging/secrets/mfa_kek_keys_json` with at least one generated 32-byte base64 KEK and set matching `MFA_KEK_ACTIVE_ID` in `/etc/sitbank-staging/container.env`. The active ID must exist as a key in `mfa_kek_keys_json`.

```bash
config_root=/etc/sitbank-staging
active_id=2026-06-staging-mfa-v1
sudo install -d -o root -g root -m 0700 "${config_root}/secrets"
python3 - "${active_id}" <<'PY' | sudo tee "${config_root}/secrets/mfa_kek_keys_json" >/dev/null
import base64, json, secrets, sys
key_id = sys.argv[1]
print(json.dumps({key_id: base64.b64encode(secrets.token_bytes(32)).decode("ascii")}, separators=(",", ":")))
PY
sudo chown root:sitbank-container "${config_root}/secrets/mfa_kek_keys_json"
sudo chmod 0640 "${config_root}/secrets/mfa_kek_keys_json"
if sudo grep -q '^MFA_KEK_ACTIVE_ID=' "${config_root}/container.env"; then
  sudo sed -i "s/^MFA_KEK_ACTIVE_ID=.*/MFA_KEK_ACTIVE_ID=${active_id}/" "${config_root}/container.env"
else
  printf 'MFA_KEK_ACTIVE_ID=%s\n' "${active_id}" | sudo tee -a "${config_root}/container.env" >/dev/null
fi
```

Production reset:

```bash
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -o root -g root -m 0700 /var/backups/sitbank
sudo -u postgres pg_dump -Fc -f "/tmp/sitbank-${timestamp}.dump" sitbank_db
sudo install -o root -g root -m 0600 "/tmp/sitbank-${timestamp}.dump" \
  "/var/backups/sitbank/database-${timestamp}.dump"
sudo rm -f "/tmp/sitbank-${timestamp}.dump"
sudo systemctl stop sitbank-container.service || true
sudo -u postgres dropdb --if-exists sitbank_db
sudo -u postgres createdb -O sitbank_owner sitbank_db
sudo rm -f /etc/sitbank/secrets/mfa_aes256_gcm_key_b64
sudo test -s /etc/sitbank/secrets/mfa_kek_keys_json
sudo grep -q '^MFA_KEK_ACTIVE_ID=' /etc/sitbank/container.env
```

Before rerunning deployment, create `/etc/sitbank/secrets/mfa_kek_keys_json` with at least one generated 32-byte base64 KEK and set matching `MFA_KEK_ACTIVE_ID` in `/etc/sitbank/container.env`. The active ID must exist as a key in `mfa_kek_keys_json`.

```bash
config_root=/etc/sitbank
active_id=2026-06-production-mfa-v1
sudo install -d -o root -g root -m 0700 "${config_root}/secrets"
python3 - "${active_id}" <<'PY' | sudo tee "${config_root}/secrets/mfa_kek_keys_json" >/dev/null
import base64, json, secrets, sys
key_id = sys.argv[1]
print(json.dumps({key_id: base64.b64encode(secrets.token_bytes(32)).decode("ascii")}, separators=(",", ":")))
PY
sudo chown root:sitbank-container "${config_root}/secrets/mfa_kek_keys_json"
sudo chmod 0640 "${config_root}/secrets/mfa_kek_keys_json"
if sudo grep -q '^MFA_KEK_ACTIVE_ID=' "${config_root}/container.env"; then
  sudo sed -i "s/^MFA_KEK_ACTIVE_ID=.*/MFA_KEK_ACTIVE_ID=${active_id}/" "${config_root}/container.env"
else
  printf 'MFA_KEK_ACTIVE_ID=%s\n' "${active_id}" | sudo tee -a "${config_root}/container.env" >/dev/null
fi
```

After the reset, deploy the signed image through the restricted wrapper so it runs `production-check`, `db upgrade`, and readiness checks before declaring success.

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
