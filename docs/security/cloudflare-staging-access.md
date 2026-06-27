# Staging Cloudflare Access Automation

`provision-staging-access` manages the provider-side boundary for
`staging-sitbank.pp.ua`. It uses the Cloudflare-managed hostname model: one
proxied DNS record, one self-hosted Access application, and one narrow Allow
policy. It does not manage production, the private admin hostname, an identity
provider, Authenticated Origin Pull certificates, or Cloudflare Tunnel.

Run the tool with Python from the repository root:

```bash
python ops/cloudflare/provision-staging-access --plan
python ops/cloudflare/provision-staging-access --apply \
  --confirm APPLY-STAGING-ACCESS
python ops/cloudflare/provision-staging-access --verify
```

`--plan` is offline and non-mutating. It validates desired configuration and
does not require or read the API token. `--apply` reconciles the Access
application, approved-operator policy, and proxied DNS record only after the
exact confirmation phrase. `--verify` makes read-only API calls, checks that an
unauthenticated edge request receives the Access challenge, and proves that a
direct request to the EC2 origin is blocked by Nginx or the network.

## Required configuration

Set values in the operator shell or a protected GitHub `staging` environment.
Do not put them in `.env`, workflow YAML, Terraform state, or repository files.

| Variable | Purpose |
| --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | Account containing the Access application |
| `CLOUDFLARE_ZONE_ID` | Zone containing `staging-sitbank.pp.ua` |
| `STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN` | `<team>.cloudflareaccess.com` JWT issuer hostname |
| `STAGING_ACCESS_ALLOWED_EMAILS` | Comma-separated operator emails |
| `STAGING_ACCESS_ALLOWED_GROUP_IDS` | Optional comma-separated Access group IDs |
| `STAGING_ACCESS_ALLOWED_IDP_IDS` | Optional comma-separated approved IdP IDs |
| `STAGING_DNS_ORIGIN` | EC2 origin IPv4/IPv6 address or origin hostname |
| `STAGING_ORIGIN_IP` | Public EC2 address used only by `--verify` for bypass testing |
| `CLOUDFLARE_API_TOKEN` | Bearer token; required only by `--apply` and `--verify` |

At least one approved email or group is mandatory. The hostname is fixed to
`staging-sitbank.pp.ua`; attempts to target production or admin fail closed.
Optional settings are `STAGING_ACCESS_APP_NAME`,
`STAGING_ACCESS_POLICY_NAME`, and `STAGING_ACCESS_SESSION_DURATION` (default
`8h`, allowed range `15m` through `24h`).

For `.github/workflows/cloudflare-access-verify.yml`, configure
`CLOUDFLARE_API_TOKEN`, `STAGING_ACCESS_ALLOWED_EMAILS`,
`STAGING_ACCESS_ALLOWED_GROUP_IDS`, `STAGING_DNS_ORIGIN`, and
`STAGING_ORIGIN_IP` as protected `staging` environment secrets. Configure the
account ID, zone ID, team domain, and optional IdP IDs as protected environment
variables. The verification token should have read permissions only.

The staging deployment workflow also requires these protected environment
variables:

| Variable | Runtime behavior |
| --- | --- |
| `STAGING_CLOUDFLARE_ACCESS_AUD` | Exact Access application audience accepted by Flask |
| `STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN` | Exact issuer hostname and source of current JWKS |

The signed staging runtime bundle supplies `DEPLOYMENT_TARGET=staging`,
`STAGING_CLOUDFLARE_ACCESS_JWT_REQUIRED=true`, and
`STAGING_CLOUDFLARE_ACCESS_JWKS_CACHE_TTL_SECONDS=300`. The cache TTL may be
set from 60 through 3600 seconds. Production does not enable this
staging-only request gate.

The Access identity provider must already exist. Configure and test its MFA,
group lifecycle, and emergency access separately. Service tokens are not used
for normal browser access.

## Token scope and lifecycle

Use separate short-lived operator tokens where practical and restrict them to
the one SITBank account and zone:

- Plan: no token.
- Verify: Account `Access: Apps and Policies Read` and Zone `DNS Read`.
- Apply: Account `Access: Apps and Policies Write` and Zone `DNS Write`.

Never use a Global API Key. Store the live-verification token as the protected
GitHub environment secret `CLOUDFLARE_API_TOKEN`, rotate it after operator or
automation changes, test the replacement with `--verify`, then revoke the old
token in Cloudflare. Do not paste tokens into command arguments because shell
history and process listings may expose them. The tool never prints the token
or writes it to disk.

## Safety model

The managed policy contains only explicit email and Access group rules.
Cloudflare's implicit default deny handles all non-matches. Apply and verify
fail if they find `everyone`, service-token, bypass, non-identity, duplicate,
or unmanaged Allow policy state. Existing unknown Allow policies are not
deleted automatically; an operator must review and remove them.

The proxied DNS record hides the origin from ordinary DNS answers. Direct
origin bypass is independently blocked by the repository-managed Nginx
Authenticated Origin Pull check. Keep EC2 security-group ingress restricted to
Cloudflare address ranges where operationally possible. The tool does not
change AWS security groups, issue origin certificates, configure the IdP, or
enable Authenticated Origin Pull in the Cloudflare dashboard/API.

After apply, the tool prints the non-secret runtime values:

```text
STAGING_CLOUDFLARE_ACCESS_AUD=<application audience>
STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN=<team>.cloudflareaccess.com
```

Store both as protected GitHub `staging` environment variables. The staging
customer runtime sets `STAGING_CLOUDFLARE_ACCESS_JWT_REQUIRED=true` and refuses
to start if either value is missing or malformed. It retrieves current signing
keys from the team-domain JWKS endpoint and validates the
`Cf-Access-Jwt-Assertion` signature, issuer, audience, expiry, and optional
not-before time before normal Flask authentication. Never log the JWT.

The runtime ignores `Cf-Access-Authenticated-User-Email` and other identity
headers. Nginx strips those untrusted headers and forwards only the assertion.
Email inside a verified token remains metadata and does not replace SITBank
login, MFA, CSRF, authorization, rate limiting, or audit controls.

Authenticated Origin Pull and JWT validation prove different things. Nginx
requires Cloudflare's client certificate to prove the connection came through
Cloudflare. Flask then requires the signed Access assertion to prove the
request passed the specific staging application and policy. Missing,
malformed, incorrectly signed, expired, not-yet-valid, wrong-issuer, and
wrong-audience assertions all receive the same generic `403`.

Only loopback `/health/ready` bypasses the assertion gate. A non-loopback
readiness request still requires a valid assertion and remains blocked by
Nginx. Production customer and admin runtimes do not install the staging
request hook.

`--verify --evidence-file <path>` writes a sanitized JSON summary containing
only check results, the public staging hostname, and a timestamp. It excludes
tokens, account/zone IDs, email/group allowlists, origin addresses, application
IDs, and the audience.

After deployment, verify the origin-side gate without copying or printing an
Access assertion:

```bash
curl -I http://127.0.0.1:5001/
curl --fail http://127.0.0.1:5001/health/ready
```

The first request must return `403` because it has no assertion; loopback
readiness must succeed. Then use an approved browser session through
`https://staging-sitbank.pp.ua/` and confirm Cloudflare Access, staging Basic
Auth, and normal Flask login/MFA all remain required. Never extract, paste,
record, or add `Cf-Access-Jwt-Assertion` to curl command history.

## Emergency lockout and recovery

For emergency staging lockout, disable the managed Allow policy or replace its
operator membership with an empty approved group in the Cloudflare dashboard.
Keep proxied DNS and Authenticated Origin Pull enabled. Revoke Access sessions,
rotate affected Basic Auth/application credentials, preserve Cloudflare/Nginx
audit evidence, and run `--verify` before restoring access.

If apply fails, leave staging unavailable rather than adding an allow-everyone
or bypass policy or disabling origin-pull enforcement. The API operations are
idempotent, so correct the reported state and rerun apply. Provider-side IdP,
Authenticated Origin Pull enablement/certificates, AWS security-group rules,
and operator approval remain deliberate manual controls.

Cloudflare references:

- Access applications API:
  <https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/>
- Access application policies API:
  <https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/subresources/policies/>
- DNS records API:
  <https://developers.cloudflare.com/api/resources/dns/subresources/records/>
- Access JWT validation:
  <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/>
