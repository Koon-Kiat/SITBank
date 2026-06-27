# Admin And Staging Zero-Trust Access

Issue #184 uses a hybrid access boundary:

- Staging uses Cloudflare Zero Trust Access.
- Admin uses Tailscale private access.

This intentionally uses both products because the surfaces have different
access patterns. Staging must stay browser-accessible at the staging hostname
for approved operators, and Cloudflare Access can challenge the operator before
traffic reaches Nginx or Flask. Admin is an operator-only surface and should
not be reachable from the public internet at all, so the admin app remains
behind Tailscale/private device access.

References:

- Cloudflare Access self-hosted applications:
  <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/>
- Cloudflare Authenticated Origin Pulls:
  <https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/>
- Tailscale Serve:
  <https://tailscale.com/docs/reference/tailscale-cli/serve>
- Tailscale ACLs and tags:
  <https://tailscale.com/docs/features/access-control/acls> and
  <https://tailscale.com/docs/features/tags>

## Protected Paths

| Surface | Host or path | Boundary | Public exposure |
| --- | --- | --- | --- |
| Production customer | `https://sitbank.duckdns.org` | Public HTTPS edge, Flask customer login and MFA | Public |
| Staging customer | `https://staging-sitbank.pp.ua` | Cloudflare Access, Cloudflare Authenticated Origin Pull, staging Basic Auth, Flask login and MFA | Not directly public at the origin |
| Production admin app | `https://sitbank-ec2.tailca101b.ts.net/` through Tailscale Serve | Tailscale ACLs, approved devices, Flask admin login and TOTP | Private tailnet only |
| Staging admin app | Approved Tailscale/private operator path to `127.0.0.1:5003` | Tailscale ACLs, approved devices, Flask admin login and TOTP | Private tailnet only |

The customer production site remains public. The admin app is not exposed
through the customer app, and the customer Nginx server block continues to
return `404` for `/admin`.

There is no public admin Nginx server block. The old public admin verification
page has been removed from the edge bootstrap, and admin application access is
only through the private Tailscale Serve path. If a retired public admin DNS
record still points at the EC2 host, the shared unknown-host default server
fails closed instead of proxying to the admin app.

## Staging Cloudflare Access

The repository manages the desired provider-side state for
`staging-sitbank.pp.ua` with
`ops/cloudflare/provision-staging-access`. This is the Cloudflare-managed
hostname model, not Cloudflare Tunnel. The script creates or reconciles one
proxied DNS record, one self-hosted Access application, and one Allow policy
containing only configured operator emails or Access groups. It rejects
allow-everyone, service-token browser access, bypass/non-identity policies, and
unmanaged Allow policies. Cloudflare's no-match behavior remains the default
deny. The retired DuckDNS staging hostname is no longer an active staging
deployment, Nginx, Certbot, or TLS-scan target.

Provider prerequisites and actions:

1. Create and test the approved Cloudflare Access identity provider. Record
   its ID if the application must be restricted to specific IdPs.
2. Create a narrowly scoped Cloudflare API token. Verification needs Account
   `Access: Apps and Policies Read` and Zone `DNS Read`; apply needs the
   corresponding Write permissions. Restrict it to the one account and zone.
3. Set the account/zone IDs, team domain, approved email/group allowlist, DNS
   origin, and API token in the operator shell as described in
   `ops/cloudflare/README.md`. Do not store them in repository `.env` files.
4. Review the offline plan, then apply with the exact confirmation phrase:

   ```bash
   python ops/cloudflare/provision-staging-access --plan
   python ops/cloudflare/provision-staging-access --apply \
     --confirm APPLY-STAGING-ACCESS
   ```

5. Enable Cloudflare Authenticated Origin Pulls for staging. Prefer
   per-hostname or zone-level Authenticated Origin Pulls with an
   operator-managed client certificate when available. Global Authenticated
   Origin Pulls are acceptable only with the existing strict hostname routing
   and unknown-host rejection.
6. Install the origin-pull CA certificate on the EC2 host at
   `/etc/nginx/cloudflare-authenticated-origin-pull-ca.pem`. This CA file is
   host-managed and is not committed to the repository.

Apply prints the Access application audience plus expected issuer and JWKS URL.
These are non-secret inputs for the separate origin JWT-validation work:
`CLOUDFLARE_ACCESS_AUD`, `CLOUDFLARE_ACCESS_ISSUER`, and
`CLOUDFLARE_ACCESS_JWKS_URL`. The current runtime does not consume them. Never
log `Cf-Access-Jwt-Assertion`, and do not trust Cloudflare email/identity
headers until that JWT is verified against the signature, issuer, and
application audience.

The staging Nginx server blocks accept `staging-sitbank.pp.ua`, then request a
client certificate with:

```nginx
ssl_client_certificate /etc/nginx/cloudflare-authenticated-origin-pull-ca.pem;
ssl_verify_client optional;
```

All staging browser/app paths return `403` unless
`$ssl_client_verify` is `SUCCESS`. This blocks direct EC2-origin bypass for the
staging app and `/health/live` while preserving loopback readiness checks.
`/health/ready` remains loopback-only and does not require the Cloudflare
client certificate so the deployment wrapper can still check local Nginx and
Flask readiness on the EC2 host.

Keep the existing staging Basic Auth file until a separate reviewed change
removes it. Cloudflare Access is the identity-aware boundary; Basic Auth is a
secondary staging control after Authenticated Origin Pull succeeds. Direct
origin requests without Cloudflare's origin-pull client certificate must
receive `403` rather than a Basic Auth challenge. The Basic Auth password or
htpasswd hash must not be stored in the repository.

## Admin Tailscale Access

Install Tailscale on the EC2 host and enroll it as a tagged service node such
as `tag:sitbank-admin`. Restrict access with the tailnet policy so only
approved operator users, groups, or managed devices can reach the SITBank host
and admin service ports. Do not rely on a shared password as the private
network boundary.

Current admin access path:

```bash
sudo tailscale up --advertise-tags=tag:sitbank-admin
sudo tailscale serve --bg --https=443 127.0.0.1:5002
sudo tailscale serve status
```

Admins connect to the Tailscale VPN first, then open
`https://sitbank-ec2.tailca101b.ts.net/`. The `tailscale serve` command exposes
the local admin service inside the tailnet. It must not be paired with
`tailscale funnel`; Funnel would publish the service to the public internet and
is not approved for SITBank admin. Flask admin login and TOTP remain mandatory
after the private network boundary is satisfied.

If Tailscale Serve is unavailable, use a separate reviewed private operator
path rather than exposing the admin app publicly. In all cases, the Flask
admin login and TOTP remain mandatory after the private network boundary is
satisfied.

## Operator Onboarding

Staging operators:

1. Add the operator to the approved identity provider group or email allowlist
   used by the Cloudflare Access policy.
2. Confirm the operator can authenticate to Cloudflare Access with the required
   IdP and any required MFA or device posture.
3. Provide the staging Basic Auth credential only through the approved secret
   channel while that secondary control remains active.
4. Verify the operator reaches the staging hostname through Cloudflare Access
   and then reaches the normal Flask staging login.

Admin operators:

1. Add the operator to the Tailscale group allowed by the tailnet policy.
2. Approve the operator device according to the tailnet device-approval policy.
3. Confirm the device can reach only the approved SITBank admin service path.
4. Create or maintain the operator's staff/admin account through the
   root-admin invite flow.
5. Confirm admin login still requires password plus TOTP after Tailscale
   access is established.

## Offboarding

When an operator or device is removed:

1. Remove the user or group membership from Cloudflare Access.
2. Revoke the user's active Cloudflare sessions if immediate staging lockout is
   required.
3. Disable or delete the Tailscale device from the tailnet.
4. Remove the user from the Tailscale admin group and confirm ACL tests still
   pass.
5. Revoke or disable the SITBank admin staff account if applicable.
6. Rotate staging Basic Auth, Tailscale auth keys, or other affected
   host-managed credentials if they were shared with the removed operator.
7. Review audit logs for staging/admin access near the offboarding time.

## Deployment Verification

Repository-side checks:

```bash
git diff --check
.\.venv\Scripts\python.exe -m pytest -q tests/test_cloudflare_access_automation.py
.\.venv\Scripts\python.exe -m pytest -q tests/test_deployment.py tests/test_admin_isolation.py
.\.venv\Scripts\python.exe -m pytest -q tests/test_zero_trust_access_boundary.py
```

Provider and live-boundary checks use the protected operator environment:

```bash
python ops/cloudflare/provision-staging-access --verify \
  --evidence-file cloudflare-access-evidence.local.json
```

The same non-mutating check is available through the manual
**Verify staging Cloudflare Access** workflow. It runs only in the protected
`staging` GitHub environment and uploads a sanitized result with no token,
account/zone IDs, operator identities, origin address, application ID, or
audience. It does not run on pull requests or mutate Cloudflare.

Host-side staging checks after bootstrap:

```bash
sudo test -r /etc/nginx/cloudflare-authenticated-origin-pull-ca.pem
sudo /usr/local/sbin/verify-certbot-host-state staging
sudo nginx -t
curl --fail --resolve staging-sitbank.pp.ua:443:127.0.0.1 \
  https://staging-sitbank.pp.ua/health/ready
curl -I --resolve staging-sitbank.pp.ua:443:<EC2_PUBLIC_IP> \
  https://staging-sitbank.pp.ua/
```

Expected: local readiness succeeds through loopback, and direct origin access
to `/` returns `403` without Cloudflare's authenticated origin-pull client
certificate.

The automated verification proves that the Access application and narrow
policy match, DNS is proxied, the audience exists, unauthenticated edge traffic
receives the Access challenge, the repository still contains the origin-pull
gate, and direct origin traffic is blocked. Complete these identity-dependent
live checks manually:

1. An approved operator passes Cloudflare Access through the configured IdP.
2. An unapproved account is denied.
3. Staging Flask login still works after Cloudflare Access and staging Basic
   Auth.
4. Staging `/health/ready` is blocked externally.
5. EC2-local deployment health checks still pass.

Live Tailscale admin checks:

1. An approved operator reaches `https://sitbank-ec2.tailca101b.ts.net/` only from an approved tailnet device.
2. A non-tailnet network cannot reach the admin app.
3. A removed user or deleted device loses access.
4. Admin Flask login and TOTP are still required after Tailscale access.
5. Admin readiness endpoints remain private or restricted.
6. No public admin hostname is required or scanned.
7. `https://sitbank.duckdns.org` remains public.

## Emergency Lockout

For staging compromise or suspected unauthorized staging access:

1. Disable the Cloudflare Access Allow policy or replace it with an empty
   allowlist.
2. Keep the EC2 staging Nginx origin-pull requirement in place.
3. Rotate staging Basic Auth and any affected staging application credentials.
4. Preserve Cloudflare Access logs, Nginx logs, and SITBank audit logs.

For admin compromise or suspected unauthorized admin access:

1. Disable Tailscale Serve for the admin service:

   ```bash
   sudo tailscale serve reset
   sudo tailscale serve status
   ```

2. Remove the affected Tailscale devices or users from the tailnet.
3. Keep the public admin surface absent from Nginx.
4. Revoke affected SITBank admin sessions and disable staff accounts as needed.
5. Preserve Tailscale logs, Nginx logs, and SITBank admin audit logs.

Break-glass access must use an approved operator device and must still complete
Flask admin login plus TOTP. Do not enable Tailscale Funnel or make the public
admin Nginx routes usable as a shortcut.

## Rollback

If the Cloudflare staging setup fails after merge:

1. Keep production unchanged and public.
2. Keep the staging app unavailable externally rather than removing the
   origin-pull requirement.
3. Roll back the staging Nginx file through the reviewed bootstrap only after a
   security owner approves the temporary exposure decision.
4. Redeploy staging and verify readiness before allowing production to proceed
   through the normal pipeline.

If Tailscale admin setup fails:

1. Disable Tailscale Serve or the private admin path.
2. Leave the public admin surface absent from Nginx.
3. Use only approved break-glass host access to recover.
4. Do not expose admin through the customer app or public Nginx routes.

## Secrets And Host-Managed State

Repository-managed desired state with live values supplied at runtime:

- Cloudflare Access application, approved-operator policy, session duration,
  and proxied staging DNS record.

Host-managed values:

- Cloudflare Access IdP settings, operator membership, API token, and emergency
  session revocation.
- Cloudflare Authenticated Origin Pull client certificate/private key if using
  zone-level or per-hostname AOP.
- Cloudflare origin-pull CA file at
  `/etc/nginx/cloudflare-authenticated-origin-pull-ca.pem`.
- Tailscale tailnet policy, ACLs/grants, device approvals, and tagged node
  state.
- Tailscale Serve configuration.
- Staging Basic Auth password and htpasswd hash.

Never commit:

- Tailscale auth keys, API keys, device enrollment secrets, or private keys.
- Cloudflare API tokens, tunnel credentials, Access IdP secrets, or origin
  certificate private keys.
- Private SSH keys.
- Staging Basic Auth passwords or generated htpasswd hashes.
- Any SITBank Flask, CSRF, session, MFA, password-pepper, webhook, SMTP, or
  database secrets.

Rotate a Cloudflare token by creating a replacement with the same narrow
scope, running `--verify` with the replacement, updating the protected GitHub
`staging` environment secret, and revoking the old token. Do not pass tokens
as command arguments.

## How The Layers Fit

Cloudflare Access and Tailscale decide whether a request may reach the SITBank
origin or admin listener. They do not replace Flask login, CSRF, rate limiting,
root-admin authorization, admin TOTP, admin/customer route isolation, admin
cookie isolation, or database runtime role separation.

Readiness remains restricted:

- Production customer `/health/ready` is loopback-only.
- Staging `/health/ready` is loopback-only and bypasses the origin-pull client
  certificate check only for local deployment verification.
- Admin readiness is checked through loopback/private paths only.

Unknown-host rejection remains in `ops/nginx/sitbank-default.conf`; direct
origin requests with unexpected hostnames are rejected by the shared default
server.

## Labels

Zero-trust and network-boundary work should use these repository labels:

- `zero-trust`: identity-aware or private-network access boundary changes.
- `network-security`: firewall, VPN, origin access, private access, or network
  boundary changes.
- `staging`: staging environment, staging deployment, or staging access changes.

Issue and PR labelers apply these labels from terms such as `Cloudflare
Access`, `Tailscale`, `tailnet`, `VPN`, `private access`, `origin bypass`,
`admin exposure`, `staging exposure`, and path changes under `ops/nginx/**`,
staging configuration, and zero-trust documentation.
