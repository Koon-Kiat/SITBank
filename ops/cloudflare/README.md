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
| `STAGING_ACCESS_TEAM_DOMAIN` | `<team>.cloudflareaccess.com` JWT issuer hostname |
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

After apply, the tool prints these non-secret values:

```text
CLOUDFLARE_ACCESS_AUD=<application audience>
CLOUDFLARE_ACCESS_ISSUER=https://<team>.cloudflareaccess.com
CLOUDFLARE_ACCESS_JWKS_URL=https://<team>.cloudflareaccess.com/cdn-cgi/access/certs
```

They are inputs for the separate origin JWT-validation work. The current
runtime does not consume them. Do not trust `Cf-Access-Authenticated-User-Email`
or any other identity header until `Cf-Access-Jwt-Assertion` is verified
against the issuer, audience, signature, and current JWKS. Never log the JWT.

`--verify --evidence-file <path>` writes a sanitized JSON summary containing
only check results, the public staging hostname, and a timestamp. It excludes
tokens, account/zone IDs, email/group allowlists, origin addresses, application
IDs, and the audience.

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
