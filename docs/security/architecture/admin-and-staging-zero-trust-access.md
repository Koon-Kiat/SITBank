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
provisioning and verification automation, confirmation-gated Tailscale
installation/Serve configuration, Tailscale admin host preflight, and the
private-admin CI verification workflow. Live provider policy, device approval,
group membership, and executed host state remain operator-owned evidence.

Protected GitHub CI tailnet verification is implemented only by the manual
`.github/workflows/tailscale-private-admin-verify.yml` workflow and the direct
production gate in `.github/workflows/ci-deploy.yml`. It is deliberately not
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
- Tailscale OAuth clients:
  <https://tailscale.com/docs/features/oauth-clients>
- Tailscale auth keys:
  <https://tailscale.com/docs/features/access-control/auth-keys>

Category: [Security architecture](../README.md#architecture).

## Protected GitHub CI Tailnet Verification

The manual **Verify private Tailscale admin access** workflow and the direct
production post-deploy gate temporarily join a GitHub-hosted runner to the
tailnet. The project accepts this narrow credential exposure because no
trusted self-hosted tailnet runner is available. This exception applies only
to those protected jobs. It does not put pull-request CI, staging, scheduled
public TLS scans, or other GitHub-hosted jobs inside the tailnet.

`workflow_dispatch` supports on-demand checks. The trusted production workflow
defines a direct required gate after `deploy-production` and
`verify-production-tls` both succeed. This avoids the observed reusable-call
behavior where the called job received empty OAuth inputs despite the same
environment secrets working in a manual run. Both jobs use the protected
`admin-tailscale` GitHub Environment. Configure that environment to require
manual approval by trusted maintainers and restrict deployment branches to
`main`. Production uses OAuth with environment secrets
`TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET`. Manual verification may
select `auth_mode: authkey` and use `TAILSCALE_AUTH_KEY`. Do not duplicate any
of them as repository or organization secrets. The OAuth client needs **Keys >
Auth Keys > Write**; an auth key must be short-lived, one-off where possible,
ephemeral, tagged, and pre-approved when required. Both modes are restricted
to `tag:github-ci`, which may reach only `tag:admin-sitbank:443` and cannot
administer the tailnet or use broad SSH. Each run selects exactly one mode.

Each approved run:

1. Confirms `https://admin-sitbank.tailca101b.ts.net/login` cannot respond from
   the public runner before tailnet enrollment. An unexpected response fails
   closed because it may indicate Funnel or another public exposure.
2. Joins the approved tailnet with the protected ephemeral tagged identity and
   verifies tailnet connectivity to `admin-sitbank.tailca101b.ts.net`.
3. Resolves the private hostname and requires the HTTPS login entrypoint to
   return its documented unauthenticated `200` response with ordinary
   certificate and hostname validation.
4. Logs out and relies on ephemeral-node cleanup; it uploads no artifacts or
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
depend on or include the private Tailscale hostname.

After a trusted production deployment, the release order is
`deploy-production` -> `verify-production-tls` ->
`verify-private-admin-tailnet`. A private-gate failure fails the completed
deployment workflow and clearly requires post-deploy investigation; it does
not roll back or redeploy automatically. Manual dispatch remains available for
checks after Tailscale DNS, ACL/tag, certificate, Serve, or admin-edge changes.

### Credential Rotation And CI Offboarding

Rotate `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET` after suspected disclosure,
after a maintainer with environment access is offboarded, or whenever the
client's tag/grant scope changes:

1. Create a replacement OAuth client with **Keys > Auth Keys > Write**
   permission restricted to `tag:github-ci`.
2. Replace both protected environment secrets, manually approve one
   verification run from `main`, and confirm the ephemeral node is removed
   after the job.
3. Revoke the old OAuth client and remove any stale CI node from the tailnet.

If `auth_mode: authkey` is used, rotate `TAILSCALE_AUTH_KEY` before expiry or
after disclosure, validate one approved run, then revoke the old key. Revoking
either credential does not remove enrolled nodes; remove stale nodes
separately.

To remove CI tailnet access, delete all three optional secrets from the
environment, revoke the applicable OAuth client/auth key, remove the dedicated
CI tag grants and stale devices, and disable or delete the GitHub Environment.
Environment approver and deployment-branch rules must be reviewed during
maintainer offboarding. Retired private aliases must not be used.

### EC2 Tailscale Provisioning Automation

`ops/tailscale/` implements the approved Model B private-HTTPS setup:

- `install-tailscale` installs the authenticated Ubuntu 24.04 stable package
  only after `--confirm`; `--dry-run` performs no network or package action.
- `configure-admin-access` supports explicit `oauth`, `authkey`, and
  `interactive` modes. It accepts no credential before `--confirm`, passes
  secrets through an inherited file descriptor, and never prints or persists
  them.
- `verify-admin-access` delegates to the canonical EC2 verifier.
- `acl-policy.hujson` is a non-secret least-privilege policy reference; it is
  reviewed and applied manually to the live tailnet.

Production bootstrap installs these scripts under `/usr/local/sbin`. The
confirmed configure flow permits only private HTTPS `443` to
`http://127.0.0.1:5002`, clears unsafe route/exit-node/SSH advertisement,
refuses pre-existing Serve mappings, never enables Funnel, and requires the
preflight before and after Serve changes. Staging admin is deliberately not
configured; port `5003`, a staging private hostname, policy, verification, and
docs require a separate approval.

Normal CI performs static/contract tests only and never installs Tailscale,
joins the tailnet, reads host credentials, or configures Serve. Live policy
application, operator/device approval, and execution remain manually approved
external actions. See `ops/tailscale/README.md` for safe secret input,
onboarding, offboarding, quarterly review, rollback, and emergency disable.

### EC2 Host-Side Tailscale Preflight

Production bootstrap installs
`ops/deploy/verify-tailscale-admin-access` at
`/usr/local/sbin/verify-tailscale-admin-access`. It is a non-mutating local
control with three explicit modes:

- `--mode serve` proves the node is running, Funnel is disabled, the admin
  listener is only `127.0.0.1:5002`, local readiness works, Nginx has no admin
  upstream/private hostname, Serve maps only the approved private HTTPS
  endpoint to `http://127.0.0.1:5002`, and private `/login` returns `200`.
- `--mode ssh` proves the same local Tailscale, Funnel, listener, readiness,
  and Nginx prerequisites for fallback private port-forward diagnostics. It
  does not claim to test a remote tunnel.
- `--mode documentation-only` checks arguments and warns that no live
  verification occurred. It is not acceptable production evidence.

Run the primary check on EC2:

```bash
sudo /usr/local/sbin/verify-tailscale-admin-access --mode serve
```

The script invokes only local status and read-only inspection commands. It
does not accept or print auth keys, OAuth credentials, API tokens, node keys,
cookies, or application secrets. It does not run `tailscale up`, change Serve,
enable Funnel, write tailnet policy, call an external provider API, or replace
the protected GitHub workflow.

The two controls answer different questions. The protected GitHub workflow
proves that an approved ephemeral tailnet client can reach the private HTTPS
entrypoint. The EC2 preflight proves the deployed host's local listener,
Nginx, Serve, and Funnel posture. Live ACL/grant contents, tag ownership,
device approval, operator membership, and removal of stale devices remain
operator-owned evidence and must be reviewed in Tailscale.

## Protected Paths

| Surface | Host or path | Boundary | Public exposure |
| --- | --- | --- | --- |
| Production customer | `https://sitbank.duckdns.org` | Public HTTPS edge, Flask customer login and MFA | Public |
| Staging customer | `https://staging-sitbank.pp.ua` | Cloudflare Access, server-level Cloudflare Authenticated Origin Pull, origin JWT validation, Flask login and MFA | Not directly public at the origin |
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
   `docs/security/architecture/cloudflare-staging-access.md`. Do not store them in
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

The staging Nginx TLS server accepts only `staging-sitbank.pp.ua` and requires
a client certificate with:

```nginx
ssl_client_certificate /etc/nginx/cloudflare-authenticated-origin-pull-ca.pem;
ssl_verify_client on;
```

This server-level gate covers every public TLS location, including
`/health/live`, and prevents a future location from omitting a copied check.
Direct-origin connections without Cloudflare's client certificate fail the
TLS client-certificate exchange. Nginx readiness is isolated on
`127.0.0.1:8081` and `[::1]:8081`; the public TLS `/health/ready` location
does not proxy to Flask.

These controls are independent and both are required: Authenticated Origin
Pull proves the TLS client is Cloudflare, while Access JWT validation proves
the request passed the configured staging Access application. A Cloudflare
edge request without a valid Access assertion therefore still fails closed at
Flask.

Nginx shared-password authentication has been removed. Cloudflare Access is
the auditable identity-aware boundary; Authenticated Origin Pull prevents
direct-origin bypass, and Flask continues to enforce its own login, MFA, CSRF,
session, and authorization controls.

## Admin Tailscale Access

Use the confirmation-gated `ops/tailscale/` automation to install Tailscale
and enroll the EC2 host as `tag:sitbank-admin`. Restrict access with the
reviewed tailnet policy so only approved operator users/groups and the narrow
CI identity can reach HTTPS `443`. Do not rely on a shared password as the
private network boundary.

Current admin access path:

```bash
sudo /usr/local/sbin/sitbank-install-tailscale --dry-run
sudo /usr/local/sbin/sitbank-configure-tailscale-admin \
  --dry-run --auth-mode oauth
# After approval, repeat each with --confirm.
sudo /usr/local/sbin/sitbank-verify-tailscale-admin
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
path rather than exposing the admin app publicly. For host diagnostics, run
`sudo /usr/local/sbin/verify-tailscale-admin-access --mode ssh`, then establish
an approved-device tunnel such as
`ssh -N -L 127.0.0.1:5002:127.0.0.1:5002
sitbank-deploy@<approved-private-host>`. This is fallback diagnostics only;
private HTTPS through Serve remains the supported browser path. In all cases,
Flask admin login and TOTP remain mandatory after the private network boundary
is satisfied.

## Operator Onboarding

Staging operators:

1. Add the operator to the approved identity provider group or email allowlist
   used by the Cloudflare Access policy.
2. Confirm the operator can authenticate to Cloudflare Access with the required
   IdP and any required MFA or device posture.
3. Verify the operator reaches the staging hostname through Cloudflare Access
   and then reaches the normal Flask staging login.

Admin operators:

1. Add the operator to the Tailscale group allowed by the tailnet policy.
2. Approve the operator device according to the tailnet device-approval policy.
3. Confirm the device can reach only the approved SITBank admin service path.
4. Create or maintain the operator's staff/admin account through the
   root-admin invite flow.
5. Confirm admin login still requires password plus TOTP after Tailscale
   access is established.
6. Run the EC2 `--mode serve` preflight and retain its non-secret result with
   the operator-change evidence.

## Offboarding

When an operator or device is removed:

1. Remove the user or group membership from Cloudflare Access.
2. Revoke the user's active Cloudflare sessions if immediate staging lockout is
   required.
3. Disable or delete the Tailscale device from the tailnet.
4. Remove the user from the Tailscale admin group and confirm ACL tests still
   pass.
5. Revoke or disable the SITBank admin staff account if applicable.
6. Rotate Tailscale keys or other affected host-managed credentials if they
   were shared with the removed operator.
7. Review audit logs for staging/admin access near the offboarding time.
8. Run the EC2 `--mode serve` preflight, confirm removed devices are absent in
   Tailscale, and retain both results as offboarding evidence.

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
curl --fail http://127.0.0.1:8081/health/ready
curl -I --resolve staging-sitbank.pp.ua:443:<EC2_PUBLIC_IP> \
  https://staging-sitbank.pp.ua/
curl -I http://127.0.0.1:5001/
curl --fail http://127.0.0.1:5001/health/ready
```

Expected: local readiness succeeds through loopback, a direct request to the
Flask staging root returns `403` without an Access assertion, and direct Nginx
origin access to `/` fails the TLS client-certificate exchange without
Cloudflare's authenticated origin-pull client certificate.

The automated verification proves that the Access application and narrow
policy match, DNS is proxied, the audience exists, unauthenticated edge traffic
receives the Access challenge, the repository still contains the origin-pull
gate, and direct origin traffic is blocked. Complete these identity-dependent
live checks manually:

1. An approved operator passes Cloudflare Access through the configured IdP.
2. An unapproved account is denied.
3. Staging Flask login still works after Cloudflare Access.
4. Staging `/health/ready` is blocked externally.
5. EC2-local deployment health checks still pass.

Live Tailscale admin checks:

1. Run
   `sudo /usr/local/sbin/verify-tailscale-admin-access --mode serve` on EC2
   and retain its successful, non-secret output.
2. An approved operator reaches `https://admin-sitbank.tailca101b.ts.net/` only from an approved tailnet device.
3. A non-tailnet network cannot reach the admin app.
4. A removed user or deleted device loses access.
5. Admin browser login with workplace password and TOTP reaches the dashboard.
6. Admin readiness endpoints remain private or restricted.
7. No public admin hostname or Nginx admin upstream is configured.
8. `https://sitbank.duckdns.org` remains public.

## Emergency Lockout

For staging compromise or suspected unauthorized staging access:

1. Disable the Cloudflare Access Allow policy or replace it with an empty
   allowlist.
2. Keep the EC2 staging Nginx origin-pull requirement in place.
3. Rotate affected staging application credentials and Access sessions.
4. Preserve Cloudflare Access logs, Nginx logs, and SITBank audit logs.

For admin compromise or suspected unauthorized admin access:

1. Disable Tailscale Serve for the admin service:

   ```bash
   sudo tailscale serve reset
   sudo tailscale serve status
   sudo /usr/local/sbin/verify-tailscale-admin-access --mode ssh
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
5. Run the host preflight in the selected live mode and do not restore operator
   access until it succeeds.

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

Never commit:

- Tailscale auth keys, API keys, device enrollment secrets, or private keys.
- Cloudflare API tokens, tunnel credentials, Access IdP secrets, or origin
  certificate private keys.
- Private SSH keys.
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
