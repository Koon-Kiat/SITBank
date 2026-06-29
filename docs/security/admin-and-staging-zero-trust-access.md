# Admin And Staging Zero-Trust Access

SITBank uses a hybrid zero-trust access model:

- Staging uses a Cloudflare-managed public hostname with Cloudflare Access,
  Authenticated Origin Pulls, and Flask-side Access JWT validation.
- Admin access is private through Tailscale and remains protected by Flask
  admin login, TOTP, CSRF, route authorization, and audit logging.

Tailscale is the private network/device boundary for admin access; it does not
replace Flask admin login, TOTP, CSRF protection, route authorization, or audit
logging.

This intentionally uses both products because the surfaces have different
access patterns. Staging must stay browser-accessible at the staging hostname
for approved operators, and Cloudflare Access can challenge the operator before
traffic reaches Nginx or Flask. Admin is an operator-only surface and should
not be reachable from the public internet at all, so the admin app remains
behind Tailscale/private device access.

Implemented repository controls include origin-side Cloudflare Access assertion
validation, Authenticated Origin Pull CA integrity checks, Cloudflare staging
provisioning and verification automation, Tailscale admin host preflight, and
the private-admin CI verification workflow. Live provider policy, device
approval, and host-side Serve state remain operator-owned evidence.

Protected GitHub CI tailnet verification is implemented only by
`.github/workflows/tailscale-private-admin-verify.yml`. It is deliberately not
part of normal public CI.

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

## Protected GitHub CI Tailnet Verification

The manual/reusable **Verify private Tailscale admin access** workflow
temporarily joins a GitHub-hosted runner to the tailnet. The project accepts
this narrow credential exposure because no trusted self-hosted tailnet runner
is available. This exception applies only to that protected workflow. It does
not put pull-request CI, staging, scheduled public TLS scans, or other
GitHub-hosted jobs inside the tailnet.

`workflow_dispatch` supports on-demand checks. `workflow_call` lets the trusted
production workflow invoke the required gate after `deploy-production` and
`verify-production-tls` both succeed. The reusable job uses the protected
`admin-tailscale` GitHub Environment. Configure that environment to require
manual approval by trusted maintainers, restrict deployment branches to
`main`, and store `TAILSCALE_AUTH_KEY` only as an environment secret. Do not
duplicate it as a repository or organization secret. The auth key must be
reusable, ephemeral, pre-approved when device approval is enabled, tagged as
`tag:github-ci`, unable to administer the tailnet or use broad SSH, and granted
only `tag:admin-sitbank:443`. The workflow uses the official Tailscale action
at an immutable commit, checks the targets before joining, and does not check
out or run repository code.

Each approved run:

1. Requires `https://admin-sitbank.duckdns.org/login` to return a documented
   safe denial (`403`, `404`, `421`, or `444`) or have no public endpoint
   (`000`). Any public login/dashboard response fails closed.
2. Confirms `https://admin-sitbank.tailca101b.ts.net/login` cannot respond from
   the public runner before tailnet enrollment. An unexpected response fails
   closed because it may indicate Funnel or another public exposure.
3. Joins the approved tailnet with the protected ephemeral tagged identity and
   verifies tailnet connectivity to `admin-sitbank.tailca101b.ts.net`.
4. Resolves the private hostname and requires the HTTPS login entrypoint to
   return its documented unauthenticated `200` response with ordinary
   certificate and hostname validation.
5. Logs out and relies on ephemeral-node cleanup; it uploads no artifacts or
   Tailscale state.

This is reachability evidence, not an authenticated admin test. It uses no
admin credentials, cookies, or session IDs and does not replace Flask admin
login, TOTP, CSRF protection, route authorization, audit logging,
admin/customer session isolation, host-side Tailscale ACL/device review, or
operator verification of Tailscale Serve state. It does not enable or
configure Tailscale Funnel or Serve, modify tailnet policy, deploy the
application, bootstrap a root admin, or change EC2 state. Tailscale Funnel
remains forbidden.

Normal public TLS scanning remains in `.github/workflows/tls-scan.yml` and
covers only `staging-sitbank.pp.ua` and `sitbank.duckdns.org`. It must not
depend on or include the private Tailscale hostname. Public admin checking in
the protected workflow verifies denial or absence of the retired
`admin-sitbank.duckdns.org` login path; it does not make the private admin URL
a public TLS-scan target.

After a trusted production deployment, the release order is
`deploy-production` -> `verify-production-tls` ->
`verify-private-admin-tailnet`. A private-gate failure fails the completed
deployment workflow and clearly requires post-deploy investigation; it does
not roll back or redeploy automatically. Manual dispatch remains available for
checks after Tailscale DNS, ACL/tag, certificate, Serve, or admin-edge changes.

### Credential Rotation And CI Offboarding

Rotate `TAILSCALE_AUTH_KEY` before expiry, after suspected disclosure, after a
maintainer with environment access is offboarded, or whenever its tag/grant
scope changes:

1. Create a replacement reusable, ephemeral, tagged, and narrowly scoped auth
   key in Tailscale.
2. Replace the protected environment secret, manually approve one verification
   run from `main`, and confirm the ephemeral node is removed after the job.
3. Revoke the old key and remove any stale CI node from the tailnet.

To remove CI tailnet access, delete `TAILSCALE_AUTH_KEY` from the environment,
revoke the key in Tailscale, remove the dedicated CI tag grants and stale
devices, and disable or delete the GitHub Environment. Environment approver
and deployment-branch rules must be reviewed during maintainer offboarding.
Retired private aliases must not be used. If the live tailnet hostname
changes, update the workflow, documentation, and policy tests together.

## Protected Paths

| Surface | Host or path | Boundary | Public exposure |
| --- | --- | --- | --- |
| Production customer | `https://sitbank.duckdns.org` | Public HTTPS edge, Flask customer login and MFA | Public |
| Staging customer | `https://staging-sitbank.pp.ua` | Cloudflare Access, Cloudflare Authenticated Origin Pull, origin JWT validation, staging Basic Auth, Flask login and MFA | Not directly public at the origin |
| Production admin app | `https://admin-sitbank.tailca101b.ts.net/` through Tailscale Serve | Tailscale ACLs, approved devices, Flask admin login and TOTP | Private tailnet only |
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
The reviewed self-hosted application is named `SITBank staging` and uses
`STAGING_ACCESS_SESSION_DURATION=6h`. Its policy membership must match the
exact comma-separated email list stored in
`STAGING_ACCESS_ALLOWED_EMAILS`. `Everyone`, wildcard domains, and broad
allow-all rules are forbidden; group and IdP inputs remain optional unless
those restrictions are intentionally configured.

Provider prerequisites and actions:

1. Create and test the approved Cloudflare Access identity provider. Record
   its ID if the application must be restricted to specific IdPs.
2. Create a narrowly scoped Cloudflare API token. Verification needs Account
   `Access: Apps and Policies Read` and Zone `DNS Read`; apply needs the
   corresponding Write permissions. Restrict it to the one account and zone.
3. Set the account/zone IDs, team domain, approved email/group allowlist, DNS
   origin, and API token in the operator shell as described in
   `docs/security/cloudflare-staging-access.md`. Do not store them in
   repository `.env` files.
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
7. Run `sudo /usr/local/sbin/verify-cloudflare-origin-pull-ca` after bootstrap.
   Bootstrap installs the repository-reviewed allowlist under
   `/etc/sitbank-staging` and fails before enabling staging Nginx unless the
   CA is a safe root-owned regular file containing exactly one currently valid
   CA whose SHA-256 fingerprint, subject, and issuer are approved.

The checked-in allowlist initially covers Cloudflare's global AOP CA only. For
a custom zone/per-hostname CA or announced rotation, obtain the public CA from
the official provider source outside bootstrap, inspect it with OpenSSL, and
independently review its provenance and metadata. Add the new fingerprint and
exact subject/issuer alongside the old entry, deploy and verify it, then remove
the old entry only after rollout. Bootstrap never downloads CA material and
does not need a Cloudflare token or origin private key.

Apply prints `STAGING_CLOUDFLARE_ACCESS_AUD` and
`STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN`. Store them as protected GitHub
`staging` environment variables. The staging deployment enables the
repository-controlled Flask verifier, which checks the
`Cf-Access-Jwt-Assertion` RS256 signature against current Cloudflare JWKS plus
the exact issuer, audience, expiry, and optional not-before claim. Invalid or
missing assertions return a generic `403`; the raw assertion is never logged.
Cloudflare email/identity headers are stripped at Nginx and are not trusted for
SITBank authorization.

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

These controls are independent and both are required: Authenticated Origin
Pull proves the TLS client is Cloudflare, while Access JWT validation proves
the request passed the configured staging Access application. A Cloudflare
edge request without a valid Access assertion therefore still fails closed at
Flask.

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
sudo tailscale set --hostname=admin-sitbank
sudo tailscale serve --bg --https=443 127.0.0.1:5002
sudo tailscale serve status
```

Admins connect to the Tailscale VPN first, then open
`https://admin-sitbank.tailca101b.ts.net/login`. The `tailscale serve` command
exposes the local admin service inside the tailnet. It must not be paired with
`tailscale funnel`; Funnel would publish the service to the public internet and
is not approved for SITBank admin. Flask admin login and TOTP remain mandatory
after the private network boundary is satisfied. Successful browser login
redirects the operator to the private dashboard at
`https://admin-sitbank.tailca101b.ts.net/`.

The `admin-sitbank` machine name is part of the MagicDNS FQDN. A hostname
change must be applied to the live EC2 Tailscale node (or through the Tailscale
Machines page), then Serve status and HTTPS must be verified again. Tailnet
policy entries, monitoring, bookmarks, or automation that contain the previous
hostname must be updated separately; tag-based grants remain unchanged.

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
.\.venv\Scripts\python.exe -m pytest -q -n auto tests/test_cloudflare_access_automation.py
.\.venv\Scripts\python.exe -m pytest -q -n auto tests/test_cloudflare_origin_pull_ca.py
.\.venv\Scripts\python.exe -m pytest -q -n auto tests/test_deployment.py tests/test_admin_isolation.py
.\.venv\Scripts\python.exe -m pytest -q -n auto tests/test_zero_trust_access_boundary.py
```

Provider and live-boundary checks use the protected operator environment:

```bash
python ops/cloudflare/provision-staging-access --verify \
  --evidence-file cloudflare-access-evidence.local.json
```

The same non-mutating check is available through the manual
**Verify staging Cloudflare Access** workflow. It runs only in the protected
`staging` GitHub environment when dispatched from `main` and uploads a
sanitized result with no token, account/zone IDs, operator identities, origin
address, application ID, or audience. It explicitly passes the configured
session duration and expected audience to the script. It does not run on pull
requests or mutate Cloudflare. Application drift names safe fields and
expected/actual values; allowlist drift exposes only counts, never the secret
addresses.

Host-side staging checks after bootstrap:

```bash
sudo /usr/local/sbin/verify-cloudflare-origin-pull-ca
sudo /usr/local/sbin/verify-certbot-host-state staging
sudo nginx -t
curl --fail --resolve staging-sitbank.pp.ua:443:127.0.0.1 \
  https://staging-sitbank.pp.ua/health/ready
curl -I --resolve staging-sitbank.pp.ua:443:<EC2_PUBLIC_IP> \
  https://staging-sitbank.pp.ua/
curl -I http://127.0.0.1:5001/
curl --fail http://127.0.0.1:5001/health/ready
```

Expected: local readiness succeeds through loopback, a direct request to the
Flask staging root returns `403` without an Access assertion, and direct Nginx
origin access to `/` returns `403` without Cloudflare's authenticated
origin-pull client certificate.

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

1. An approved operator reaches `https://admin-sitbank.tailca101b.ts.net/` only from an approved tailnet device.
2. A non-tailnet network cannot reach the admin app.
3. A removed user or deleted device loses access.
4. Admin browser login with workplace password and TOTP reaches the dashboard.
5. Admin readiness endpoints remain private or restricted.
6. No public admin hostname is a valid access path; the retired public hostname
   is absent or returns a safe denial.
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
   Security Owner approves the temporary exposure decision.
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
- `tag:github-ci` access restricted to `tag:admin-sitbank:443`.
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
