# Production Cloudflare Origin Boundary

Category: [Security architecture](../README.md#architecture).

Production customer traffic uses proxied `sitbank.pp.ua` and
`www.sitbank.pp.ua`. The operator-provided reviewed Cloudflare state is:

- `sitbank.pp.ua`: proxied `A` record to `18.188.152.24`.
- `www.sitbank.pp.ua`: proxied `CNAME` to `sitbank.pp.ua`.
- SSL/TLS mode `Full (strict)`, minimum TLS 1.3, TLS 1.3 and Universal SSL
  enabled.
- Always Use HTTPS, Automatic HTTPS Rewrites, and Certificate Transparency
  Monitoring enabled; Opportunistic Encryption disabled.
- HSTS enabled with `max-age=15552000` (six months), include subdomains
  enabled, and preload disabled.

Repository files do not prove this provider state. Retain sanitized Cloudflare
and AWS evidence after rollout. Production Certbot DNS-01 uses only the
production zone's `Zone Read` and `DNS Write` permissions; do not broaden that
token for origin-pull work.

`ops/nginx/sitbank-production.conf` permits raw HTTP requests for the reviewed
origin IP only to redirect to `https://sitbank.pp.ua$request_uri`. Unknown HTTP
hosts still hit the shared `444` default. Raw HTTPS IP/SNI hits
`ssl_reject_handshake`, while the production hostname blocks direct-origin
HTTPS unless Cloudflare presents the reviewed Authenticated Origin Pull client
certificate. Public `/admin` remains denied and `/health/ready` remains
loopback-only.

Production uses
`/etc/nginx/sitbank-production-cloudflare-origin-pull-ca.pem`; staging keeps
`/etc/nginx/cloudflare-authenticated-origin-pull-ca.pem`. Bootstrap verifies
the production CA and its separate
`/etc/sitbank/cloudflare-origin-pull-ca-allowlist.json` before installing or
reloading Nginx. Missing, malformed, expired, unreviewed, or unsafe trust
material fails closed. The CA certificate is operator-installed and is not
committed.

Where practical, restrict AWS `443/tcp` ingress to current Cloudflare edge
ranges and keep `80/tcp` redirect-only for the raw-IP contract. Keep emergency
access on Tailscale or the approved AWS break-glass path. Cloudflare
Authenticated Origin Pull enablement, proxied DNS, and security-group rules
require operator/provider evidence.

After production bootstrap and provider changes:

```powershell
curl.exe -I https://sitbank.pp.ua/
curl.exe -I http://18.188.152.24/
curl.exe -k -I https://18.188.152.24/
curl.exe -k --resolve sitbank.pp.ua:443:18.188.152.24 -I https://sitbank.pp.ua/
```

The proxied hostname must succeed. Raw HTTP must redirect to the canonical
HTTPS hostname. Raw-IP HTTPS and direct-origin hostname HTTPS without
Cloudflare's client certificate must not return SITBank application content.
