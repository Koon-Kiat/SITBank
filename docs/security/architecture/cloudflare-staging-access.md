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

Category: [Security architecture](../README.md#architecture).

## Required configuration

Set values in the operator shell or a protected GitHub `staging` environment.
Do not put them in `.env`, workflow YAML, Terraform state, or repository files.

The current application is the self-hosted Access application `SITBank
staging` at `staging-sitbank.pp.ua`. Its session duration is six hours, mapped
as `STAGING_ACCESS_SESSION_DURATION=6h`. The managed policy is `SITBank staging
app - approved operators only` and must contain the exact explicit email
membership from `STAGING_ACCESS_ALLOWED_EMAILS`. `Everyone`, wildcard domains,
and broad allow-all rules are forbidden.

The separate App Launcher policy is `SITBank Access launcher - approved
operators only`. It remains a manual Cloudflare-side policy and is outside
this repository automation unless that automation is explicitly expanded to
manage it later.

Configure these required `staging` environment secrets:

- `CLOUDFLARE_API_TOKEN`
- `STAGING_ACCESS_ALLOWED_EMAILS`
- `STAGING_DNS_ORIGIN`
- `STAGING_ORIGIN_IP`
- `STAGING_EC2_KNOWN_HOSTS`
- `STAGING_EC2_SSH_PRIVATE_KEY_B64`

`STAGING_ACCESS_ALLOWED_GROUP_IDS` is an optional secret. Leave it empty when
the policy uses only exact emails. `STAGING_ACCESS_ALLOWED_EMAILS` must be a
comma-separated list of exact approved Cloudflare Access emails and must match
the live policy. It cannot be empty unless at least one approved Access group
is configured. Never print or document any of these secret values.

Configure these required `staging` environment variables:

| Variable | Current non-secret value or purpose |
| --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | `6faa030c11df15b07615d1e82d0de15e` |
| `CLOUDFLARE_ZONE_ID` | `b92001fc94317a194eba3fc76f4364db` |
| `STAGING_ACCESS_SESSION_DURATION` | `6h` |
| `STAGING_CLOUDFLARE_ACCESS_AUD` | `847a9be3c396f4930a210e3106aa5d86945839ba9ad31be794e4378bf8a55663` |
| `STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN` | `small-boat-a77f.cloudflareaccess.com` |
| `STAGING_PUBLIC_HOST` | `staging-sitbank.pp.ua` |
| `STAGING_EC2_HOST` | Private Tailscale MagicDNS name or `100.x.y.z` deployment target |
| `STAGING_EC2_DEPLOY_USER` | `sitbank-deploy` |
| `STAGING_EC2_PORT` | `22` |

`STAGING_ACCESS_ALLOWED_IDP_IDS` is an optional environment variable. Leave it
empty unless the application intentionally restricts login to specific
identity providers. `STAGING_ACCESS_APP_NAME` and
`STAGING_ACCESS_POLICY_NAME` are also optional environment or operator-shell
overrides; empty values use the defaults `SITBank staging` and `SITBank
staging app - approved operators only`.

The shared staging environment also carries the existing application and
deployment variables `ROOT_ADMIN_EMAILS`,
`STAGING_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID`, `STAGING_MFA_ISSUER_NAME`,
`STAGING_MFA_KEK_ACTIVE_ID`, `STAGING_PASSWORD_PBKDF2_ITERATIONS`,
`STAGING_PASSWORD_RESET_EMAIL_FROM`,
`STAGING_SESSION_HMAC_ACTIVE_KEY_ID`, and `STAGING_SMTP_HOST`. Those values are
not consumed by provider verification and must retain their existing
deployment meanings.

The hostname remains fixed to `staging-sitbank.pp.ua`; attempts to target
production or admin fail closed. Session durations from `15m` through `24h`
are syntactically supported, but the reviewed live value is `6h`.

For `.github/workflows/cloudflare-access-verify.yml`, configure
the values above in the protected `staging` environment. The workflow maps the
public host, account and zone IDs, team domain, expected audience, six-hour
session duration, allowlist inputs, DNS origin, and direct-origin address into
the verifier explicitly. The verification token should have read permissions
only.

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

Run the workflow manually from **Actions → Verify staging Cloudflare Access →
Run workflow → main** before a staging release and after changing Access, DNS,
identity-provider, origin, or environment settings. It has no pull-request
trigger and its job is restricted to `main`; protected-environment approval
controls access to the secrets.

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

Staging bootstrap additionally runs the offline
`verify-cloudflare-origin-pull-ca` helper before installing or enabling the
site. It validates file type, ownership and mode, a single currently valid CA,
and exact fingerprint/subject/issuer membership in the reviewed repository
allowlist. The initial entry is Cloudflare's global AOP CA. Custom
zone/per-hostname CAs and provider rotations require a reviewed allowlist
change before deployment; bootstrap never fetches CA material or uses the
Cloudflare API token. The protected bootstrap workflow runs read-only provider
verification first, while the host bootstrap and deploy wrapper independently
require a live edge Access challenge. Deployment also requires the direct
loopback origin to fail closed before switching runtimes.

Only loopback `/health/ready` bypasses the assertion gate. A non-loopback
readiness request still requires a valid assertion and remains blocked by
Nginx. Production customer and admin runtimes do not install the staging
request hook.

Staging deployment readiness uses only
`http://127.0.0.1:8081/health/ready`. The local Nginx block supplies the trusted
HTTPS forwarding scheme, and the deploy wrapper accepts only the exact ready
JSON with HTTP `200`; redirects and the public TLS `/health/ready` are never
accepted as readiness.

`--verify --evidence-file <path>` writes a sanitized JSON summary containing
only check results, the public staging hostname, expected session duration,
provider-owned review statuses, workflow environment, and a timestamp. It
excludes tokens, account/zone IDs, email/group allowlists, origin addresses,
application IDs, and the audience.

Drift diagnostics identify non-secret application fields. For example,
`session_duration expected=6h actual=24h` identifies a duration mismatch.
Policy membership drift reports expected and actual email/group counts with
`mismatch=true`; it never prints the configured addresses. Raw provider
responses, authorization headers, cookies, JWTs, and Access assertions are not
written to logs or evidence. Correct the named provider or GitHub-environment
field and rerun the manual workflow rather than weakening the policy.

After deployment, verify the origin-side gate without copying or printing an
Access assertion:

```bash
curl -I http://127.0.0.1:5001/
curl --fail http://127.0.0.1:5001/health/ready
```

The first request must return `403` because it has no assertion; loopback
readiness must succeed. Then use an approved browser session through
`https://staging-sitbank.pp.ua/` and confirm Cloudflare Access and normal
Flask login/MFA remain required. Never extract, paste,
record, or add `Cf-Access-Jwt-Assertion` to curl command history.

## Emergency lockout and recovery

For emergency staging lockout, disable the managed Allow policy or replace its
operator membership with an empty approved group in the Cloudflare dashboard.
Keep proxied DNS and Authenticated Origin Pull enabled. Revoke Access sessions,
rotate affected application credentials and Access sessions, preserve Cloudflare/Nginx
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
