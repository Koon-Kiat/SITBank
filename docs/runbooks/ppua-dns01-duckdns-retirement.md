# pp.ua DNS-01 And DuckDNS Retirement Runbook

Use this runbook after the reviewed repository changes have been merged and the
operator is ready to move live Certbot renewal to DNS-01 for the active
`pp.ua` domains.

## Target State

- Production customer canonical URL is `https://sitbank.pp.ua`.
- `https://www.sitbank.pp.ua` redirects permanently to
  `https://sitbank.pp.ua`.
- Staging remains `https://staging-sitbank.pp.ua`.
- Admin remains private at `https://admin-sitbank.tailca101b.ts.net/`.
- No `admin.sitbank.pp.ua` or `admin-sitbank.pp.ua` public admin hostname is
  introduced.
- `sitbank.duckdns.org`, `staging-sitbank.duckdns.org`, and
  `admin-sitbank.duckdns.org` are retired and must not serve SITBank content.
- Production Certbot lineage is named `sitbank.pp.ua` and covers only
  `sitbank.pp.ua` and `www.sitbank.pp.ua`.
- Staging Certbot lineage is named `staging-sitbank.pp.ua` and covers only
  `staging-sitbank.pp.ua`.

Do not delete logs or audit evidence because they contain historical DuckDNS
references. Delete only temporary Nginx backups created for this migration after
successful validation.

## Cloudflare DNS Tokens

Use separate Cloudflare tokens with only `Zone Read` and `DNS Write` for the
matching zone:

- `SITBank production Certbot DNS-01 renewal` for `sitbank.pp.ua`.
- `SITBank staging Certbot DNS-01 renewal` for `staging-sitbank.pp.ua`.

Store token values only in root-owned host files:

```text
/root/.secrets/certbot/cloudflare-production.ini
/root/.secrets/certbot/cloudflare-staging.ini
```

Each file must be `root:root` mode `0600`. Do not reuse Cloudflare Access
provisioning tokens, do not grant Access permissions, and do not paste token
values into GitHub, logs, screenshots, or command output.

## Install DNS-01 Support

Run the reviewed EC2 bootstrap after merge so the host has
`python3-certbot-dns-cloudflare`. Verify the plugin before issuing or renewing:

```bash
sudo certbot plugins | grep -A3 -i cloudflare
```

## Issue Replacement Certificates

Production:

```bash
sudo certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /root/.secrets/certbot/cloudflare-production.ini \
  --cert-name sitbank.pp.ua \
  -d sitbank.pp.ua \
  -d www.sitbank.pp.ua
```

Staging:

```bash
sudo certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /root/.secrets/certbot/cloudflare-staging.ini \
  --cert-name staging-sitbank.pp.ua \
  -d staging-sitbank.pp.ua
```

Keep Cloudflare Access, Authenticated Origin Pull, WAF/rate-limit controls, and
Tailscale admin isolation enabled. DNS-01 does not require exposing staging
HTTP-01 or disabling Cloudflare protections.

## Update And Verify Nginx

Back up the active site before editing:

```bash
sudo cp -a /etc/nginx/sites-available/sitbank /etc/nginx/sites-available/sitbank.before-ppua-dns01.$(date +%Y%m%d-%H%M%S)
```

Production Nginx should use:

```nginx
server_name sitbank.pp.ua www.sitbank.pp.ua;
return 301 https://sitbank.pp.ua$request_uri;
ssl_certificate /etc/letsencrypt/live/sitbank.pp.ua/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/sitbank.pp.ua/privkey.pem;
```

The customer app proxying HTTPS server block should use only:

```nginx
server_name sitbank.pp.ua;
```

The `www.sitbank.pp.ua` HTTPS server block should use the same certificate and
return a permanent redirect to `https://sitbank.pp.ua$request_uri`.

Test and reload only after the config is valid:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## Host Verification

Run target-specific local and renewal checks:

```bash
sudo /usr/local/sbin/verify-certbot-host-state production
sudo /usr/local/sbin/verify-certbot-host-state --renewal-dry-run production
sudo /usr/local/sbin/verify-certbot-host-state staging
sudo /usr/local/sbin/verify-certbot-host-state --renewal-dry-run staging
sudo certbot renew --dry-run --cert-name sitbank.pp.ua
sudo certbot renew --dry-run --cert-name staging-sitbank.pp.ua
sudo nginx -t
```

Verify from the operator laptop:

```powershell
curl.exe -I https://sitbank.pp.ua
curl.exe -I https://www.sitbank.pp.ua
curl.exe -I https://sitbank.pp.ua/admin
curl.exe -I https://sitbank.duckdns.org
curl.exe -I https://staging-sitbank.duckdns.org
curl.exe -I https://admin-sitbank.duckdns.org
```

Expected results:

- `https://sitbank.pp.ua` serves the customer app.
- `https://www.sitbank.pp.ua` redirects to `https://sitbank.pp.ua`.
- `/admin` on the public production host is blocked.
- Retired DuckDNS hostnames fail closed, fail TLS, hit default Nginx rejection,
  or otherwise do not serve SITBank content.

## Cleanup

Only after replacement certificates, Nginx config, renewal dry-runs, and live
checks pass:

```bash
sudo certbot delete --cert-name sitbank.duckdns.org
sudo certbot delete --cert-name staging-sitbank.duckdns.org
sudo certbot delete --cert-name admin-sitbank.duckdns.org
sudo certbot certificates
sudo nginx -t
sudo systemctl reload nginx
```

Remove or deactivate DuckDNS records if the team controls them. Do not point any
DuckDNS hostname at the EC2 instance after the migration.

List migration backups before deleting them:

```bash
sudo ls -l /etc/nginx/sites-available/*before-ppua-dns01* /etc/nginx/sites-available/*before-remove-duckdns* 2>/dev/null
```

Delete only backups created for this migration after confirming rollback is no
longer needed.

## Rollback

If `sitbank.pp.ua` fails during migration:

- Restore the saved Nginx backup.
- Reissue or reuse the previous certificate only if required to restore service.
- Run `sudo nginx -t` before reload.
- Do not delete old certs, DuckDNS records, or migration backups until
  `sitbank.pp.ua` and `www.sitbank.pp.ua` are confirmed working.
- Do not roll back by exposing admin publicly, disabling Cloudflare Access,
  disabling Authenticated Origin Pull, or weakening Tailscale isolation.
