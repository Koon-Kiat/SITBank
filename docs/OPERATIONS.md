# Operations

Security owner roles, milestone/release review cadence, accepted-risk handling,
and off-repo evidence expectations are defined in
`docs/security/governance/security-governance.md`.

Production deployment is environment-approved automatic after successful
staging gates. A push to `main` pauses at the protected `production`
environment for reviewer approval; operators do not dispatch production
directly.

For one-stop safe verification commands and EC2 operational path inventory,
start with `docs/runbooks/global-verification.md`, then follow the deeper
runbooks linked from that page.

## Runtime Secrets

Keep root-managed secret files in `/etc/sitbank/secrets` and `/etc/sitbank-staging/secrets`. The container reads only mounted files under `/run/secrets`; long-lived application secrets are not exported into the Compose process environment.

Production admin uses separate root-managed secret files in
`/etc/sitbank/secrets`: `admin_secret_key`, `admin_wtf_csrf_secret_key`,
`admin_session_hmac_keys_json`, `admin_session_lookup_hmac_key`,
`admin_database_url`, and `admin_password_pepper_b64`. These must not reuse
customer Flask signing, CSRF, session-HMAC, session-lookup HMAC,
password-pepper, or database runtime material.
`admin_database_url` must use a dedicated admin runtime role, distinct from
both the customer runtime role and the migration/schema-owner role. Create that
role, and rotate its password, with a PostgreSQL administrator or other
approved role-management account; routine application deployments do not grant
the migration/schema-owner role permission to create, alter, or rotate database
roles.

`SONAR_TOKEN` is a GitHub Actions/SonarQube Cloud analysis credential, not an
EC2 runtime secret. Store and rotate it only through GitHub Actions and
SonarQube Cloud; never copy it into `/etc/sitbank`, staging, Compose, or
deployment environments. The analysis workflow has no production access.
Setup, revocation, rotation, evidence, and incident steps are in
`docs/security/assurance/sonarqube.md`.

GitHub Actions repository variables are non-secret configuration. The CI
workflow treats an unset `ENABLE_GITHUB_CODE_SECURITY` as `false` and uses the
reviewed public-host fallbacks `staging-sitbank.pp.ua` and
`sitbank.pp.ua` when `STAGING_PUBLIC_HOST` or `PROD_PUBLIC_HOST` is
unset. Configure overrides under Actions variables only after the matching
DNS, certificate, and edge change is reviewed. The complete variable table and
secret-placement boundary are in `docs/DEPLOYMENT.md`; never copy credentials
or application secrets into repository variables.

GitHub Actions displays explicit human-readable job names such as
`Test and security checks`, `SonarQube analysis`, `Deploy staging`, and
`Verify private admin tailnet`. Stable kebab-case job IDs remain only for
workflow dependencies and expressions. If a renamed display name is a required
status check, update the GitHub ruleset manually only after the new context has
completed successfully; repository commits cannot mutate or prove that
provider-side setting.

MFA/TOTP seed encryption uses envelope encryption. Keep old KEKs in
`mfa_kek_keys_json` until `rewrap-mfa-deks` has moved stored records to the new
active KEK.

### MFA KEK Rotation

Rotate MFA KEKs in staging first, then production. Do not print, paste, or
commit KEK values, TOTP seeds, wrapped DEKs, ciphertext, nonces, recovery
codes, QR codes, or decrypted MFA material.

1. Add the new key id and base64 key value to the root-managed
   `/etc/sitbank-staging/secrets/mfa_kek_keys_json` file while keeping the old
   key id present. Repeat later for `/etc/sitbank/secrets/mfa_kek_keys_json`
   only after staging passes.
2. Keep `MFA_KEK_ACTIVE_ID` on the old key until the new key id is present and
   `production-check` passes. The error `Target MFA KEK id is not configured`
   means the target id has not been added to the runtime keyring yet.
3. Run the staging dry run and verify only counts and key ids are displayed:

   ```bash
   sudo docker exec sitbank-staging-app python -m flask --app wsgi:app production-check
   sudo docker exec sitbank-staging-app python -m flask --app wsgi:app rewrap-mfa-deks --from-kek-id <old-kek-id> --to-kek-id <new-kek-id> --dry-run
   ```

4. Run the staging rewrap. The command commits only if all matching rows
   rewrap successfully; on any failure it rolls back and reports that no
   changes were committed.

   ```bash
   sudo docker exec sitbank-staging-app python -m flask --app wsgi:app rewrap-mfa-deks --from-kek-id <old-kek-id> --to-kek-id <new-kek-id>
   sudo docker exec sitbank-staging-app python -m flask --app wsgi:app production-check
   sudo docker exec sitbank-staging-app python -m flask --app wsgi:app check-security-alerts --report-only --no-delivery
   ```

5. After staging evidence is reviewed, repeat the same dry run and rewrap in
   production with the production app container. Confirm an encrypted database
   backup exists before production rotation.
6. Set `MFA_KEK_ACTIVE_ID` to the new id only after the new key is present and
   configuration validation passes. New MFA enrollments then use the new KEK.
7. Remove the old KEK from the root-managed keyring only after all rows have
   been rewrapped, post-rotation checks pass, rollback evidence is preserved,
   and the approved rollback window has closed.

## Disposable Database Reset

Use the guarded `reset-demo-database` command documented in
`docs/DEPLOYMENT.md` only for an environment confirmed to contain disposable
project data. Stop customer and admin traffic, run staging first, retain
sanitized verification evidence, and never add the command to routine deploy
automation. Production additionally requires a protected approval and a fresh
encrypted host-managed backup. After reset, rerun migration-baseline, runtime
privilege, production-readiness, and customer/admin isolation checks before
returning the services to traffic.

## Customer Security Unlock

Only root admins in the private admin runtime can request an unlock, and only
for customer locks created automatically by password or MFA failure thresholds.
The requester supplies a support reason and current TOTP. A different active
root admin must approve the HMAC-protected request with a separate current TOTP;
self-approval, identity-linked customer accounts, manual freezes, stale lock
state, and lower roles fail closed. Approval clears the matching password/MFA
failure counters and lock fields, revokes customer sessions, writes required
audit evidence, and queues a customer security notice. It does not disable MFA,
change credentials, clear unrelated throttles, or expose a customer-app route.

## Admin And Staging Access Operations

SITBank uses a hybrid private-access model:

- Staging is protected by Cloudflare Access and Cloudflare Authenticated Origin
  Pulls at `staging-sitbank.pp.ua`.
- Admin is protected by Tailscale/private operator access at
  `https://admin-sitbank.tailca101b.ts.net/`.
- The production customer site `sitbank.pp.ua` remains public.
- `www.sitbank.pp.ua` is a public alias that redirects to
  `https://sitbank.pp.ua`.

Bootstrapped root admins browse to
`https://admin-sitbank.tailca101b.ts.net/login`, sign in with the existing
admin workplace email and password, complete TOTP, and are redirected to the
private dashboard at `https://admin-sitbank.tailca101b.ts.net/`. Customer
accounts cannot authenticate to the admin app, and admin access remains
Tailscale-only.

The Access application, narrow approved-operator policy, session duration, and
proxied staging DNS desired state are managed by
`ops/cloudflare/provision-staging-access`. IdP configuration/operator
membership, API tokens, origin certificate private keys, origin-pull client
credentials, and AWS ingress remain operator-managed. Tailscale auth keys, API
keys, tailnet policy, device approval state, and Serve state are also
operator-managed. None of those secret values belong in the repository.
`staging-sitbank.pp.ua` is the Cloudflare-managed staging hostname for Access.
The retired DuckDNS staging hostname is not an active staging deployment,
Nginx, Certbot, or TLS-scan target.
The staging domain and CI/CD migration are complete. Cloudflare Access and
origin-protection automation are implemented, while live provider state
remains operator-owned evidence.

Routine verification:

```bash
python ops/cloudflare/provision-staging-access --verify
sudo /usr/local/sbin/verify-staging-edge-boundary staging-sitbank.pp.ua
curl -I http://127.0.0.1:5001/
curl --fail http://127.0.0.1:5001/health/ready
curl --fail http://127.0.0.1:8081/health/ready
sudo /usr/local/sbin/verify-cloudflare-origin-pull-ca
sudo nginx -t
curl -I --resolve staging-sitbank.pp.ua:443:<EC2_PUBLIC_IP> \
  https://staging-sitbank.pp.ua/
sudo /usr/local/sbin/sitbank-verify-tailscale-admin
```

The origin-pull verifier is an offline host check. It rejects missing,
symlinked, non-regular, incorrectly owned, or unsafely writable CA/allowlist
files; malformed, multiple, expired, not-yet-valid, or non-CA certificates;
and any fingerprint/subject/issuer not in the repository-reviewed allowlist.
For manual diagnosis without changing state:

```bash
sudo stat -c '%F %U:%G %a %n' \
  /etc/nginx/cloudflare-authenticated-origin-pull-ca.pem \
  /etc/sitbank-staging/cloudflare-origin-pull-ca-allowlist.json
sudo openssl x509 \
  -in /etc/nginx/cloudflare-authenticated-origin-pull-ca.pem \
  -noout -subject -issuer -fingerprint -sha256 \
  -startdate -enddate -ext basicConstraints
```

Do not fetch or replace trust material during bootstrap. Review rotations from
an official Cloudflare source, add the replacement fingerprint alongside the
old one, deploy and verify it, and remove the old fingerprint only after
rollout. Custom zone/per-hostname AOP CAs require their own reviewed allowlist
entry before deployment.

Expected: the loopback Flask root returns `403` without an Access assertion,
local Flask and Nginx staging readiness return exact non-redirect `200`
responses, direct Nginx origin access fails TLS client-certificate verification,
rejects the connection, or returns the approved Nginx `400`/`403` denial
without Cloudflare's origin-pull client certificate, and the
private admin URL is reachable only from an approved tailnet path. Tailscale
Funnel must stay disabled for SITBank admin.
Tailscale is the private network/device boundary for admin access; it does not
replace Flask admin login, TOTP, CSRF protection, route authorization, or audit
logging.
Tailscale installation, production Serve configuration, and host preflight are
implemented as repository-managed scripts. Their execution, live ACL, device,
group, and resulting Serve state still require operator approval and retained
evidence.

Production bootstrap installs the scripts documented in
`ops/tailscale/README.md`. Start with non-mutating plans:

```bash
sudo /usr/local/sbin/sitbank-install-tailscale --dry-run
sudo /usr/local/sbin/sitbank-configure-tailscale-admin \
  --dry-run --auth-mode oauth
```

After change approval, run `sitbank-install-tailscale --confirm`, then run the
configure command with `--confirm` and one explicit mode:

- `oauth` reads `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET`;
- `authkey` reads `TAILSCALE_AUTH_KEY`;
- `interactive` uses approved browser authentication.

OAuth is preferred. The OAuth client needs **Keys > Auth Keys > Write** and
`tag:admin-sitbank`. Auth keys must be short-lived, one-off where possible,
pre-approved where required, and tagged. Read a secret without echo, preserve
only the required variable through `sudo`, and unset it immediately after the
command. Never paste it into history, logs, tickets, screenshots, or files.
Both mutating scripts require `--confirm`; normal CI runs neither.

The configure script permits only private HTTPS `443` to
`http://127.0.0.1:5002`, refuses existing non-empty Serve state, disables
route/exit-node/Tailscale-SSH advertisement, never enables Funnel, and requires
the canonical host preflight. It does not configure staging admin or customer
services. Tailnet policy remains an operator-applied change based on the
non-secret `ops/tailscale/acl-policy.hujson` reference.

Production bootstrap installs the read-only host preflight at
`/usr/local/sbin/verify-tailscale-admin-access`. Run it directly on EC2 after
deployment and whenever the admin listener, Nginx, Tailscale daemon, Serve
mapping, Funnel state, private hostname, or certificate changes:

```bash
sudo /usr/local/sbin/verify-tailscale-admin-access --mode serve
```

Expected output is one `OK:` line for each of these assertions: Tailscale is
running; Tailscale SSH and Funnel are disabled; port `5002` listens only on
`127.0.0.1`; local
admin readiness returns `200`; Nginx has no admin upstream or private
Tailscale hostname; Serve exposes only
`admin-sitbank.tailca101b.ts.net:443` to
`http://127.0.0.1:5002`; and an unauthenticated `GET` to the private `/login`
URL returns `200`. Any
`ERROR:` line and nonzero exit is a failed preflight. Investigate the named
control; do not enable Funnel, broaden the listener, or add an Nginx admin
route to make the check pass.

The reviewed loopback defaults can be overridden with `ADMIN_LOOPBACK_HOST`
and `ADMIN_LOOPBACK_PORT`. The verifier derives the private host from the local
Tailscale node `DNSName`; `PRIVATE_ADMIN_HOST` or `--private-admin-host` is a
strictly validated diagnostic override. GitHub workflows do not use that
override: `TAILSCALE_PRIVATE_ADMIN_HOST` in the protected `admin-tailscale`
environment is their single source of truth. There is intentionally no
public-admin-host setting; there is intentionally no public-admin-host setting
in any workflow or runtime configuration.

For a reviewed fallback diagnostic using private SSH port forwarding, first
run:

```bash
sudo /usr/local/sbin/verify-tailscale-admin-access --mode ssh
```

This verifies the host prerequisites but not the remote tunnel. From an
approved operator device, a reviewed diagnostic tunnel has the form
`ssh -N -L 127.0.0.1:5002:127.0.0.1:5002
sitbank-deploy@<approved-private-host>`. Use it only for loopback diagnostics;
the supported admin browser path remains private HTTPS through Tailscale
Serve. `--mode documentation-only` performs no live checks and prints that
warning; never retain its result as production evidence.

The host script consumes no auth key, OAuth secret, API token, node key, or
policy credential and does not print raw Tailscale status. It never enables
Tailscale, Serve, or Funnel. It supplies EC2-local listener/configuration
evidence; the protected GitHub workflow below separately supplies
tailnet-client reachability evidence. Operators must still retain live ACL,
tag, device-approval, membership, and offboarding evidence.

The staging and production deployment and trusted-main bootstrap jobs, plus
the protected private-admin verification jobs, are the only GitHub-hosted jobs
approved to join the tailnet. Deployment and bootstrap use separate
`tag:github-ci-staging-deploy` and `tag:github-ci-prod-deploy` identities with
access only to the matching EC2 host on port `22`; each joins before its first
SSH/SCP command and logs out even after failure. The direct production
admin-verification job runs after
deployment and public production TLS verification because a reusable-workflow
call did not receive the protected environment secrets. That direct job and
the manual verification workflow use the protected `admin-tailscale`
environment. The direct job uses `TS_OAUTH_CLIENT_ID`/`TS_OAUTH_SECRET`; a
manual run may select `authkey` and use `TAILSCALE_AUTH_KEY`. The environment
must require manual approval and restrict branches to `main`. Either credential
must be restricted to `tag:github-ci-admin-verify`; that tag may access only
`tag:admin-sitbank:443` and must not administer the tailnet or provide broad
SSH access.

`TAILSCALE_PRIVATE_ADMIN_HOST` is mandatory in the protected
`admin-tailscale` environment for both GitHub verification jobs. Do not add a
dispatch hostname input or workflow fallback. Its current provider value is
`admin-sitbank.tailca101b.ts.net`; update it only after an approved Tailscale
DNS/Serve change. `STAGING_EC2_HOST` and `PROD_EC2_HOST` remain separate SSH
deployment targets.

Run the workflow after private DNS, certificates, Tailscale ACLs/tags, Serve
configuration, or the admin edge changes. It first confirms the private URL is
unreachable before joining, then requires
`https://admin-sitbank.tailca101b.ts.net/login` to return the documented
unauthenticated `200` response. The job uses no admin login credentials, makes
no deployment or provider configuration changes, enables neither Tailscale
Funnel nor Serve, uploads no Tailscale state, and logs out at completion.
Flask admin login, TOTP, CSRF, route authorization, audit logging, and
admin/customer isolation still apply.

For rotation, replace and test both OAuth secrets before revoking the old
client, or replace and test `TAILSCALE_AUTH_KEY` before revoking the old key.
During maintainer offboarding, also review environment approvers and branch
rules. To remove CI tailnet access entirely, delete all Tailscale environment
secrets, revoke the selected credential, remove dedicated CI tag
grants/devices, and disable or delete the environment. The full runbook is in
`docs/security/architecture/admin-and-staging-zero-trust-access.md`.

Run the manual **Verify staging Cloudflare Access** workflow before a staging
release and after Access, DNS, IdP, token, origin address, or ingress changes.
It uses protected `staging` environment secrets and retains only sanitized
evidence. Rotate the Cloudflare API token by verifying a narrowly scoped
replacement, updating the environment secret, and revoking the old token.
Dispatch it from `main`. The expected Access application is `SITBank staging`
at `staging-sitbank.pp.ua` with
`STAGING_ACCESS_SESSION_DURATION=6h`, the configured team domain and audience,
and the exact explicit-email membership from
`STAGING_ACCESS_ALLOWED_EMAILS`. `Everyone`, wildcard domains, and broad
allow-all policies are forbidden. A drift message names safe fields such as
`session_duration`; membership drift reports counts only. Never copy tokens,
email values, authorization headers, cookies, JWTs, Access assertions, or raw
provider responses into a ticket or change record.
Provider errors are sanitized before reaching standard error, and the retained
artifact contains only high-level pass/fail fields, public hostname, reviewed
session duration, provider-owned review statuses, and timestamp. Troubleshoot
with the named safe field in an approved operator session; do not upload raw
responses or enable unredacted debug logging.

The detailed onboarding, offboarding, emergency lockout, rollback, and live
operator verification steps are in
`docs/security/architecture/admin-and-staging-zero-trust-access.md`.
Provider automation and origin assertion details are in
`docs/security/architecture/cloudflare-staging-access.md`.

Run the manual **Verify private Grafana Loki observability** workflow from
`main` after private observability bootstrap, Grafana datasource changes,
Tailscale ACL/DNS changes, or token rotation. The workflow uses the protected
`observability-staging` or `observability-production` environment, joins
Tailscale with `tag:github-ci-observability-verify`, verifies private Grafana
health with explicit HTTP `200` status, anonymous denial, non-admin verifier
role, Loki datasource health with explicit HTTP `200` status and schema
validation, and public denial probes, then uploads only sanitized evidence. The
private Grafana URL may use the approved `/grafana/` Tailscale path. It must
not run on pull requests or public TLS jobs and must not receive operator
passwords, browser sessions, cookies, MFA values, raw logs, datasource
credentials, or Grafana admin credentials.

## Production Cloudflare Origin Operations

Production requires Cloudflare Authenticated Origin Pull in addition to
proxied DNS and `Full (strict)`. Install the reviewed CA at
`/etc/nginx/sitbank-production-cloudflare-origin-pull-ca.pem`; production
bootstrap verifies it against the separate
`/etc/sitbank/cloudflare-origin-pull-ca-allowlist.json` before Nginx reload.
Do not copy the staging CA path into production configuration.

Expected Cloudflare state is minimum TLS 1.3 with TLS 1.3 and Universal SSL
enabled; Always Use HTTPS, Automatic HTTPS Rewrites, Certificate Transparency
Monitoring, and six-month HSTS (`max-age=15552000`, include subdomains) enabled;
Opportunistic Encryption and HSTS preload disabled. Repository files do not
prove provider state. Retain sanitized Cloudflare and AWS security-group
evidence and restrict `443/tcp` to Cloudflare edge ranges where practical.

Verify after production bootstrap:

```powershell
curl.exe -I https://sitbank.pp.ua/
curl.exe -I http://18.188.152.24/
curl.exe -k -I https://18.188.152.24/
curl.exe -k --resolve sitbank.pp.ua:443:18.188.152.24 -I https://sitbank.pp.ua/
```

On the production host, also run:

```bash
sudo nginx -t
sudo /usr/local/sbin/verify-production-nginx-boundary \
  --public-bind-address "$(sudo awk -F= '$1 == "PUBLIC_BIND_ADDRESS" {print $2}' /etc/sitbank/deploy.conf)"
```

Normal production deployment invokes the active-config verifier before
changing the runtime. A failure means loaded Nginx state is stale or
ambiguous. Confirm `PUBLIC_BIND_ADDRESS` is the host's exact public/VPC IPv4
address and that `ss -H -ltnp` has no wildcard port `443` listener; public
Nginx must not intercept the private Tailscale Serve HTTPS listener. Do not
bypass the gate or copy templates from an untrusted release.
Rerun the trusted production bootstrap, verify Cloudflare Authenticated Origin
Pull remains enabled using sanitized provider evidence, rerun the verifier,
and only then retry deployment. The verifier prints named pass/fail controls,
not the full `nginx -T` configuration.

The proxied site succeeds, raw HTTP redirects to the canonical hostname, and
both direct HTTPS requests fail closed without returning SITBank application
content. See
`docs/security/architecture/production-cloudflare-origin-boundary.md`.

## Root Admin Bootstrap

Root admins remain a fixed allowlisted group. Staging must contain exactly 2
approved workplace addresses and production exactly 5 from
`ADMIN_ALLOWED_EMAIL_DOMAINS` before any database user can become `root_admin`;
normal customer registration and staff invites must not create `root_admin`
accounts. Configure `STAGING_ROOT_ADMIN_EMAILS` and
`PROD_ROOT_ADMIN_EMAILS` as their respective protected GitHub environment
secrets before deploying this command. The
deployment workflow installs it as `/etc/sitbank*/secrets/root_admin_emails`
and the containers read it through `ROOT_ADMIN_EMAILS_FILE`. Do not commit,
print, screenshot, or paste the real allowlist into GitHub issues, pull
requests, chat, logs, artifacts, or job summaries. Production/admin runtime
rejects missing, empty, malformed, duplicate, built-in default, placeholder,
demo, example, personal-domain, and non-approved-domain root-admin allowlists
before serving admin traffic.

Privileged root-admin, admin, and staff accounts use approved SIT workplace
email domains only. Do not configure personal-provider domains in
`ADMIN_ALLOWED_EMAIL_DOMAINS`; staff invites are delivered to the workplace
email and do not collect personal backup email contacts.
The admin `production-check` command reports
`privileged_email_noncompliant_accounts` as a count when legacy privileged rows
use non-approved domains. Operators must remediate those accounts to approved
SIT workplace emails through a reviewed administrative data fix; the check does
not silently rewrite or delete accounts and does not print the email addresses.

After deployment, verify the admin container received an allowlist with the
expected shape without printing the identities:

```bash
sudo docker exec -i sitbank-admin python - <<'PY'
import os
value = os.environ.get("ROOT_ADMIN_EMAILS", "")
if not value:
    path = os.environ.get("ROOT_ADMIN_EMAILS_FILE", "")
    value = open(path, encoding="utf-8").read() if path else ""
emails = [item.strip().casefold() for item in value.split(",") if item.strip()]
domains = sorted({email.rsplit("@", 1)[1] for email in emails if "@" in email})
print({"count": len(emails), "unique": len(set(emails)), "domains": domains})
PY
```

The output must show `count` and `unique` equal to `7` and only approved SIT
workplace domains before you run bootstrap. It must not reveal the individual
root-admin identities and must not be the built-in `root1` through `root7`
development placeholder set.

Root-admin bootstrap remains a manual-only private operator procedure in the
current design and must not run from GitHub Actions, deployment automation, or
non-interactive bootstrap wrappers. When no usable root admin exists, run the
shell-only bootstrap command from the already deployed private admin container:

```bash
sudo docker exec -it sitbank-admin \
  python -m flask --app admin_wsgi:app admin bootstrap-root
```

For staging, use the staging admin container:

```bash
sudo docker exec -it sitbank-staging-admin \
  python -m flask --app admin_wsgi:app admin bootstrap-root
```

The command prompts for the workplace email, username, full name, and password.
Do not pass the password on the command line. The workplace email must already
be listed in `ROOT_ADMIN_EMAILS`, or the command fails without creating a user.
If the allowlisted account already exists, rerun only with `--reset-existing`
when you intentionally want to rotate its password and TOTP seed.
Do not create a GitHub Actions workflow for root bootstrap, and do not pass the
root-admin password, TOTP secret, QR code, provisioning URI, or setup values
through Actions inputs or secrets.

The command prints one-time sensitive TOTP setup output: a manual-entry secret
and provisioning URI. Add it to an authenticator app immediately. Do not paste,
screenshot, commit, upload, or store the root-admin password, TOTP secret, QR
code, provisioning URI, or setup output in GitHub logs, artifacts, job summaries,
issues, PRs, docs, chat, tickets, shell history, screenshots, or committed files. The
bootstrap stores only the protected password hash and envelope-encrypted TOTP
secret, sets the account active, marks the workplace email verified, and records
a safe `root_admin_bootstrap` audit event without the password or TOTP secret.
Any future automation must be a separate reviewed design with protected
environment approval, no plaintext bootstrap material in logs or artifacts,
short-lived one-time delivery, and explicit redaction tests.
After bootstrap, open `https://admin-sitbank.tailca101b.ts.net/login` from an
approved tailnet device and use that workplace email, password, and TOTP code to
enter the private dashboard.

## EC2 SSH And Deployment Access Operations

GitHub Actions deployment and bootstrap SSH use protected,
environment-specific Tailscale OAuth identities and private EC2 targets. After
staging and production deploy and bootstrap successfully through those paths,
remove public TCP `22` from the AWS security group and host firewall and retain
sanitized provider evidence. Public SSH is not a fallback once the environment
host variable points to a Tailscale IP or MagicDNS name. Keep approved AWS
console/SSM recovery or a documented, source-restricted and time-limited
security-group break-glass procedure.

OpenSSH daemon and UFW hardening automation remains deferred. There is no
repository OpenSSH drop-in or UFW rollout, so do not claim root SSH, password
SSH, `AllowUsers`, or host-firewall policy has been hardened from repository
evidence alone. Tailscale SSH remains disabled; deployment continues to use
OpenSSH with pinned known hosts and the restricted deploy user.

## Repository Secret Scan Operations

The independent `.github/workflows/gitleaks.yml` job runs Gitleaks 8.30.1 on
pull requests, `main` pushes, manual dispatches, and its weekly full Git
history schedule. It uses only repository read access, redacted logs, and no
production secrets, SARIF, or report artifact. The custom repository secret
scanner remains in the main and local CI paths.

Treat a real finding as an incident: revoke and rotate before cleanup, verify
the old credential no longer works, and assess a coordinated history rewrite.
Never copy the matched value into an issue or allowlist. The checked-in
allowlists are narrow reviewed false positives constrained by rule/path/line
shape and historical commit. Follow
`docs/security/assurance/secret-scanning.md` for safe reproduction and triage.

## Repository Static Analysis Operations

ShellCheck 0.11.0, Hadolint 2.14.0, and Semgrep 1.168.0 run in dedicated
automatic workflows with no production secrets. The first two use
checksum-verified releases; Semgrep uses a digest-pinned local/OSS container,
blocks ERROR severity, uploads no source or SARIF, and requires no token.
Tracked-file discovery is implemented by
`ops/security/discover_lint_targets.py` and fails closed when the expected
shell or Dockerfile target set is empty.
The dedicated ShellCheck workflow is authoritative and covers deployment
scripts through repository-wide discovery; `bash -n` is syntax evidence only.

Run `scripts/ci-local` before changing scripts or Dockerfiles. It runs a tool
when installed and explicitly marks it `SKIPPED` otherwise; the GitHub Actions
gate remains authoritative. Bash syntax success does not imply ShellCheck
success. Fix findings where possible. Any ShellCheck directive, Hadolint
instruction ignore, or Semgrep `nosemgrep` must identify a narrow reviewed
reason and must not hide command injection, unsafe file handling, secret
logging, authentication, authorization, or deployment risk.

Scanner jobs never execute deployment, bootstrap, database cutover, Tailscale,
Cloudflare, or registry-push commands. If a scanner-driven change affects
runtime scripts or the Dockerfile, retain the normal deployment, container
build, smoke, and manual staging evidence before release.

## Trivy Exception

The temporary `.trivyignore` exception covers only `CVE-2026-42496` and `CVE-2026-8376` inherited from the official python:3.12 slim-trixie / Debian Trixie base image.

The app does not install Perl directly, does not invoke Perl, and does not process attacker-controlled tar archives with Perl. Debian marks `perl-base` as `Essential: yes`, so it must not be removed. Also, mixing Debian sid packages into Trixie is riskier than keeping the inherited package while monitoring for the fixed official base digest.

This exception is temporary with a review/remove-by date: 2026-06-26. The full Critical Trivy report with no ignore file and the fixable High/Critical gate must continue to run without hiding unrelated findings.

## Rollback

Application rollback restores the previous signed image digest and runtime bundle. Database rollback requires an explicit backup/restore decision because Alembic migrations must remain backward-compatible and are not automatically reversed.

For migration `20260702_0020`, run staging first and preserve sanitized
`db current`, `db heads`, `verify-migration-baseline`, and
`verify-runtime-db-privileges` output before production. Confirm an encrypted
production backup exists before production `db upgrade`. The migration
recomputes any missing `transactions.transaction_hash` values from existing
transaction fields and then makes the column non-null; rollback should use an
explicit restore decision if production verification fails, not manual
schema-edit commands.

## Encrypted Backup Operations

Create database backups with the host-managed encrypted helper:

```bash
sudo /usr/local/sbin/sitbank-backup-encrypted --environment staging
sudo /usr/local/sbin/sitbank-backup-encrypted --environment production
```

The helper runs `pg_dump --format=custom`, keeps plaintext only in a
root-owned temporary directory, encrypts with age recipients from
`/etc/sitbank-staging/backup-age-recipients.txt` or
`/etc/sitbank/backup-age-recipients.txt`, writes root-owned mode `0600`
`.pgdump.age` files under `/var/backups/sitbank-staging` or
`/var/backups/sitbank`, and removes plaintext temporary files on success and
failure. The recipients file contains public recipients only. Decryption
identity files stay host-only, for example under
`/root/.config/sitbank-backups/`, and must not be copied into the repo,
application container, tickets, chat, or audit metadata.

Recurring backup schedules are host/operator-owned. This repository installs
and tests the helper and preflight scripts, but it does not currently install a
systemd backup timer or prune encrypted backup archives. Retain external
schedule, restore-drill, and archive-disposal evidence with the host change
record.

Run restore preflight before any restore operation:

```bash
sudo /usr/local/sbin/sitbank-restore-preflight \
  --environment staging \
  --backup-file /var/backups/sitbank-staging/<backup>.pgdump.age \
  --target-database sitbank_db \
  --identity-file /root/.config/sitbank-backups/age-identity.txt
sudo /usr/local/sbin/sitbank-restore-preflight \
  --environment production \
  --backup-file /var/backups/sitbank/<backup>.pgdump.age \
  --target-database sitbank_db \
  --identity-file /root/.config/sitbank-backups/age-identity.txt \
  --confirm-production-restore
```

The preflight is non-destructive. It checks the approved OS user, explicit
environment, explicit target database, encrypted backup path, backup
owner/mode, parent directory safety, repository/CI-workspace exclusion,
host-only age identity ownership and mode, and production confirmation. Success
output intentionally reports only that the backup file was validated by host
policy; do not paste raw backup or identity paths into tickets unless the
approved host change record requires metadata. Do not run a production restore
during normal verification. Do not commit `.dump`, `.sql`, `.backup`,
`.pgdump`, decrypted dumps, age identity files, GPG private keys, or database
credentials.

For non-production restore drills, record only safe evidence:

- change record, approver, environment, and target database name;
- backup archive basename plus owner/mode evidence, not decrypted contents;
- restore preflight success output;
- post-restore application smoke-test result and audit-chain verification;
- confirmation that plaintext dumps and identity material were not copied out
  of the host-controlled paths.

## Retention Cleanup Operations

The PDPA-aligned operator command for approved temporary security-state cleanup
defaults to dry-run and reports category-level counts:

```bash
python -m flask --app wsgi:app security run-retention-cleanup
python -m flask --app wsgi:app security run-retention-cleanup --limit 500
python -m flask --app wsgi:app security run-retention-cleanup --confirm
```

Without `--confirm`, the command does not mutate rows. With `--confirm`, it
applies only the bounded cleanup implemented in `app/security/state_cleanup.py`
for expired server-side sessions, auth counters, TOTP replay records,
registration OTP challenges, password reset transactions, security alert
dedupe rows, expired password reset tokens that are no longer referenced by
transactions, and closed circuit-breaker state past retention. It must not
delete or truncate accounts, payees, transactions, staff/admin records,
manual-recovery evidence, staff invites, security audit events, investigation
holds, or encrypted backup archives.

The command writes a sanitized system audit event with mode, retention days,
batch limit, scheduling status, and category counts only. The legacy
`cleanup-security-state` entry point now routes through the same dry-run and
confirmation boundary. Weekly `sitbank-retention-review@staging.timer` and
`sitbank-retention-review@production.timer` runs are dry-run reports only;
operators review the aggregate report and separately authorize any confirmed
cleanup. Record the reviewer, approval, report timestamp, target, and bounded
categories in the external change record before running `--confirm`; command
output remains aggregate-only. Full personal-data disposal and encrypted-backup archive pruning
remain governance/operator work, not hidden application behavior.

## Audit Operations

Retain `security_audit_events` for 7 years. The application must not auto-delete
audit rows; disposal after retention requires an operator-approved maintenance
record and a retained summary of the affected date range.
The implementation-focused audit and alert reference is
`docs/security/assurance/audit-and-alerting.md`; current open security gaps are tracked in
`docs/security/governance/security-gap-register.md`.
Privacy, retention, deactivation, and incident response procedures are in
`docs/security/governance/privacy-and-pdpa.md`,
`docs/security/governance/data-retention-and-deactivation.md`, and
`docs/security/governance/incident-response.md`.

After `db upgrade`, run `apply-runtime-db-privileges`, then
`verify-runtime-db-privileges`. The runtime `sitbank_app` role must keep
`SELECT` and `INSERT` on `security_audit_events`, while `UPDATE`, `DELETE`,
and `TRUNCATE` remain revoked so the table is append-only to the app.
PostgreSQL append-only triggers also reject `UPDATE`, `DELETE`, and `TRUNCATE`
with SQLSTATE `42501`; a missing trigger should fail runtime privilege
verification before deployment is considered healthy.

Each new audit row is part of a tamper-evident hash chain stored in
`previous_event_hash`, `event_hash`, and `hash_algorithm`. The chain uses
keyed stdlib HMAC-SHA256 with `SECURITY_AUDIT_HMAC_KEY`; legacy `sha256-v1`
rows remain verifiable for existing history. Keep the audit HMAC key in the
root-managed secret file and run verification after deployments and on a daily
schedule:

```bash
python -m flask --app wsgi:app verify-audit-log-chain
python -m flask --app wsgi:app verify-audit-log-chain --anchor /var/lib/sitbank/security-audit.anchor
```

Refresh the sanitized anchor manually, or through the daily target-aware
systemd timer, after security-sensitive releases:

```bash
python -m flask --app wsgi:app refresh-audit-log-anchor
sudo sitbank-container-runtime staging refresh-audit-log-anchor
sudo sitbank-container-runtime production refresh-audit-log-anchor
```

Operators are responsible for moving anchor JSON to immutable storage, WORM
object storage, signed release artifacts, or a separate SIEM/log archive. The
application does not provision external immutable storage and no real secrets
or cloud credentials belong in the repository.

`SECURITY_AUDIT_HMAC_KEY` and `SECURITY_AUDIT_ANCHOR_PATH` are mandatory in
production. The one-EC2 runtime uses
`SECURITY_AUDIT_ANCHOR_PATH=/var/lib/sitbank/security-audit.anchor`, a local
host path outside the database volume and repository. The app validates that the
configured path is absolute, non-world-writable, outside the application and
database directories, and readable/writable by the runtime where the host can
check it. `verify-audit-log-chain` and `check-security-alerts` use the
configured anchor automatically. A valid chain can be ahead of the saved
anchor after normal append-only audit activity; that reports `anchor_stale`,
`events_since_anchor`, and `anchor_refresh_required` without sending a critical
`audit_anchor_mismatch` alert. Unreadable or malformed anchors, anchor rollback,
anchored event hash changes, missing anchored rows, current chain behind the
anchor, chain rewind, row tampering, tail deletion, missing hashes after the
chain starts, and unsupported hash algorithms remain critical.

Do not blindly refresh anchors. `refresh-audit-log-anchor` and
`sitbank-audit-anchor-refresh@{staging,production}.timer` refuse malformed,
mismatched, missing, permission-unsafe, or invalid-chain state. They accept
only an exactly validated anchor or an append-only stale anchor whose anchored
event still verifies. `check-security-alerts` never rotates an anchor. When
`anchor_status=stale` and the chain is valid, preserve evidence as follows.
This is the required evidence-preserving workflow:
When preserving evidence, record only the sanitized fields listed below.

1. Preserve the current verification output and anchor metadata in root-only
   evidence storage. Record the command, timestamp, environment, `anchor_event_id`,
   `latest_event_id`, and `events_since_anchor`; do not include HMAC keys or
   raw sensitive metadata.
2. Run
   `python -m flask --app wsgi:app verify-audit-log-chain --anchor /var/lib/sitbank/security-audit.anchor`
   and confirm `valid=true`, `anchor_stale=true`, and `anchor_refresh_required=true`.
3. Run `python -m flask --app wsgi:app refresh-audit-log-anchor`.
4. Rerun
   `python -m flask --app wsgi:app check-security-alerts --report-only --no-delivery`
   and restart or resume the alert timer only after `alert_count=0` or after all
   remaining alerts are separately explained and preserved.

On `audit_anchor_mismatch` or `audit_chain_verification_failed`, stop rotating
anchors, preserve the current database and anchor as incident evidence, and
investigate row tampering, chain rewind, anchor corruption, or tail deletion
before resuming routine deployments.

The current banking implementation audits public transaction validation,
TOTP-backed transaction authorization checks, Local Transfer execution, and
PayUp execution. Customer and payee account numbers are exactly 12 decimal
digits across form, route, service, model, and database validation.

Local transfer performs final ledger movement: the sender balance is debited,
the recipient balance is credited, and a `Transaction` record is created in a
single atomic commit. The two-step transfer flow requires MFA step-up before a
DB-backed `PendingTransfer` record is created. The browser session keeps only
the raw single-use confirmation token; the database stores a keyed verifier.
Confirmation consumes the record atomically with `SELECT FOR UPDATE` to prevent
concurrent double-submit replay. Row locks are acquired in ascending `id` order
to prevent deadlocks. Payee ownership and cooldown are enforced at the service
layer independently of the route layer. Transfer amounts are validated to at
most two decimal places. Recipient account state is checked before funds move.
The Local Transfer daily limit remains a documented placeholder until a limit is
implemented for that channel.

PayUp lookup requires an authenticator code before SITBank reveals the
recipient name for a phone number. Unknown, unavailable, and revoked recipients
return the same generic `Invalid phone number` response and the audit metadata
uses opaque references instead of raw phone numbers. PayUp has a per-customer
daily limit stored on `users.payup_daily_limit` and reset at midnight Singapore
time. The default limit is SGD 500; customers can choose a preset or custom
value from transfer settings with TOTP step-up. Confirmation recomputes whether
the transfer brings today's cumulative PayUp spend to at least 80% of the limit
under the current database state. If so, a fresh authenticator code is required
before funds move.

Completed Local Transfer and PayUp rows store an HMAC-SHA256 transaction hash
under the dedicated `TRANSACTION_LEDGER_HMAC_KEYS_JSON` key id and explicit
integrity version. The canonical payload covers transaction reference, sender,
recipient, payee id, amount, customer reference, status, transfer type, and
creation time. Rows without integrity metadata remain explicitly legacy and
use compatibility verification; they are not represented as current keyed
ledger assurance. Legacy session-keyed rows verify only while their historical
session HMAC key remains configured; migration-generated SHA-256 rows retain
their explicit lower-assurance compatibility check. Required audit writes are part of the same
business transaction boundary; if a required success audit fails, ledger
mutation rolls back. Customer-initiated account freezes send a security email
and produce an immediate `account_freeze` alert. Blocked authorization
failures, including payee ownership mismatches, are audited safely using opaque
references so raw account numbers, phone numbers, payee details, exact transfer
amounts, and pending transfer tokens do not appear in the audit log.

The admin boundary audits root-admin-controlled staff invite onboarding,
admin login success/failure, TOTP verification, admin step-up, admin data
access, and admin configuration changes with safe `admin_*` and
`staff_*` event metadata. Admin sessions, credentials, cookies, and session
HMAC keys remain separate from customer sessions.

Useful checks:

```bash
psql "$DATABASE_MIGRATION_URL" --no-psqlrc --command \
  "SELECT event_type, outcome, count(*) FROM security_audit_events GROUP BY 1,2 ORDER BY 3 DESC LIMIT 20;"
psql "$DATABASE_MIGRATION_URL" --no-psqlrc --command \
  "SELECT created_at, ip_address, event_metadata->>'principal_ref' AS principal_ref FROM security_audit_events WHERE event_type = 'login' AND outcome = 'failure' ORDER BY created_at DESC LIMIT 20;"
psql "$DATABASE_MIGRATION_URL" --no-psqlrc --command \
  "SELECT created_at, user_id, event_metadata->>'reason' AS reason FROM security_audit_events WHERE event_type IN ('account_lock', 'session_integrity') ORDER BY created_at DESC LIMIT 20;"
journalctl -u sitbank-container.service --since -15m | grep security_audit_write_failed
python -m flask --app wsgi:app check-security-alerts --report-only
```

## Monitoring

Forward journald, Docker container logs, Nginx logs, application security audit
events, and PostgreSQL events to protected centralized logging.
Keep the Docker `local` log rotation settings in Compose as host-local
backpressure protection.

Run `check-security-alerts` from an operator scheduler. Without flags it exits
non-zero when active alerts are found. Use `--report-only` for dashboards or
cron jobs that should not fail the wrapper, and `--no-delivery` when testing
JSON output only. Production must set `SECURITY_ALERT_ENABLED=true` and provide
`SECURITY_ALERT_WEBHOOK_URL_FILE` as a root-managed secret file. A Discord
incoming webhook URL is supported directly; the application formats Discord
payloads with mention parsing disabled. Optional direct
`SECURITY_ALERT_WEBHOOK_URL` is supported for non-production tests only; these
are placeholder secret names, not checked-in values. Delivery failures are
sanitized by exception type and must not print webhook URLs or tokens. A final
sanitization pass runs immediately before outbound webhook JSON serialization
for both generic and Discord payloads; it redacts sensitive keys, bearer/basic
credentials, cookies, session values, MFA/TOTP secrets, API keys,
private-key-like text, database URLs with credentials, credentialed service URLs, webhook URLs,
and long token-like strings while preserving harmless severity, event type, summary,
timestamp, correlation ID, public session reference, and safe user references.
PostgreSQL alert-dedupe state suppresses repeated delivery of the same alert for
`SECURITY_ALERT_DEDUPE_TTL_SECONDS` while keeping the active alert in the JSON
report. Keep `SECURITY_ALERT_STATE_PATH=/run/state/security-alert-state.json`
on the host-mounted alert state volume so `check-security-alerts` records table
count and identity baselines outside the application database and emits critical
`database_table_regression` alerts when `users` or `security_audit_events`
rewind or shrink. Keep `SECURITY_AUDIT_ANCHOR_PATH` set to the protected local
anchor so `check-security-alerts` emits critical
`audit_chain_verification_failed` or `audit_anchor_mismatch` alerts for chain
tampering, rewind, anchor corruption, or tail deletion detectable from the
anchor. Valid append-only drift after the last exported anchor is reported as
`anchor_stale`/`anchor_refresh_required` and should be refreshed with the
evidence-preserving workflow above rather than delivered as a critical webhook
alert.

After an approved intentional database reset, use
`sitbank-container-runtime <target> rebaseline-security-alert-state
--intentional-reset --reason "<change record>"`. The command refuses missing
acknowledgement/reason, an invalid audit chain, or a critical/mismatched
anchor; it backs up the previous state, writes the protected-table snapshot
atomically with owner-only mode, and audits only a keyed reason reference and
bounded metadata. Never delete or hand-edit the state JSON to clear an
unexplained regression.

Admin/root users may review the same safe report in the private admin runtime
with `GET /alerts`. That browser review is read-only and must not send alerts.
Manual browser delivery uses `POST /alerts/deliver`, requires the existing
admin authorization, browser CSRF token, and current TOTP step-up, then calls
the same sanitized `build_security_alert_report(deliver=True)` delivery path
used by the CLI/timer. Dedupe still suppresses repeat delivery; there is no
browser force-resend mode or Web Push channel. Audit rows record safe
`security_alert_delivery` outcomes only.

Production uses the committed systemd timer `sitbank-security-alerts.timer` to run
`check-security-alerts` through the container runtime wrapper every 5 minutes.
The service fails visibly when alert evaluation fails, when active alerts are
present, or when required delivery fails.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sitbank-security-alerts.timer
sudo systemctl status sitbank-security-alerts.timer
journalctl -u sitbank-security-alerts.service
```

Changes to `ops/systemd/sitbank-security-alerts.service`,
`ops/systemd/sitbank-security-alerts.timer`, or the container runtime wrapper
require the reviewed production bootstrap so the host-managed unit files are
installed, followed by `systemctl daemon-reload`. Application-only alert code
changes require the normal staging/production deploy path. A change to audit
trigger migrations requires `db upgrade` and runtime privilege reapply/verify.

Alert on any `security_audit_write_failed`, `account_lock`, or
`session_integrity` failure; 10 or more login failures for one `principal_ref`
or IP in 5 minutes; 5 or more
`auth_backoff`/`rate_limit` events from the same source in 10 minutes; 3 or more
transaction failures for the same user/ref in 15 minutes; 10 transaction
failures globally in 15 minutes; audit hash-chain verification failure; audit
anchor mismatch; database table regression; failed deployments; signature or
revision mismatches; unexpected image digests; and changes to root-managed
secret files.

## Certificate Lifecycle Operations

Before bootstrap or an edge deployment, run the local host-state check for the
environment:

```bash
sudo /usr/local/sbin/verify-certbot-host-state production
sudo /usr/local/sbin/verify-certbot-host-state staging
```

It fails closed unless Certbot, the `dns-cloudflare` Certbot plugin, and OpenSSL
are installed, `certbot.timer` is installed, enabled, and active, and each
expected `fullchain.pem` and `privkey.pem` resolves below `/etc/letsencrypt`.
It parses each leaf certificate, requires a valid `notAfter`, more than 14 days
of remaining validity by default, and exact DNS SANs for the expected target
hostnames. Production verifies `sitbank.pp.ua` and `www.sitbank.pp.ua` from the
`sitbank.pp.ua` lineage; staging verifies `staging-sitbank.pp.ua` from its own
lineage. It does not accept CN fallback or wildcard substitution. It also requires each
resolved private key to use the approved root ownership/group and denies group
write or any permissions for other users. Override the validity window only
with a reviewed positive value such as
`sudo CERTBOT_MIN_VALID_DAYS=21 /usr/local/sbin/verify-certbot-host-state production`.

Normal verification is local and does not prove that ACME renewal can complete.
After certificate issuance or changes to Certbot/ACME configuration, run the
explicit network-dependent readiness check:

```bash
sudo /usr/local/sbin/verify-certbot-host-state --renewal-dry-run production
sudo /usr/local/sbin/verify-certbot-host-state --renewal-dry-run staging
```

That mode performs the same local checks before invoking
`certbot renew --dry-run --cert-name <target-lineage>`. Production and staging
renewal use DNS-01 through separate root-owned Cloudflare credential files under
`/root/.secrets/certbot/`; do not disable Cloudflare Access, Authenticated
Origin Pull, WAF/rate-limit controls, or Tailscale isolation to make renewal
pass. On any failure, repair or renew the affected certificate and rerun the
check; do not bypass it or expose private-key contents. Finally run
`sudo nginx -t` before reload.

## Live TLS Evidence Operations

The **Live TLS scan evidence** workflow provides scheduled weekly,
operator-dispatched, and post-deployment evidence of the Internet-facing TLS
posture for `staging-sitbank.pp.ua` and `sitbank.pp.ua`. The deployment
workflow calls the staging scan
after staging deploy and blocks production deployment until it passes; it calls
the production scan after production deploy, then calls the required protected
private-admin tailnet gate only after that public scan succeeds.
The manual workflow input `staging_host` defaults to
`staging-sitbank.pp.ua`; the production input defaults to `sitbank.pp.ua`.
Dispatch it after edge, certificate, DNS, Nginx/OpenSSL, CDN/WAF, or
load-balancer changes outside deployment, then retain the successful run with
the release or change record. Do not run a public-endpoint scan from ordinary
pull requests.

The `pp.ua` DNS-01 migration and DuckDNS retirement are complete. Keep retired
names out of active Nginx, Certbot, workflow, and TLS-scan configuration. Use
`docs/runbooks/private-observability-grafana-loki.md` for the private
Grafana/Loki/Alloy stack; Grafana remains private and is not exposed through
the SITBank admin app. Live Grafana/Loki evidence is collected only by the
protected private observability workflow, never by public GitHub-hosted TLS
scan jobs.

The normal public TLS scan deliberately excludes the private Tailscale admin hostname
`admin-sitbank.tailca101b.ts.net`; a GitHub-hosted public runner cannot reach
it. Private reachability is handled only by the separate, manually approved
`admin-tailscale` environment job that joins the tailnet on demand or as the
required final production gate.
Do not make staging or admin verification pass by switching Cloudflare to
Flexible SSL, disabling TLS verification, disabling the Cloudflare proxy,
bypassing Authenticated Origin Pulls, or enabling Tailscale Funnel.

Each target artifact (`tls-scan-staging-sitbank` or `tls-scan-prod-sitbank`)
retains the untouched scanner output as
`testssl.raw.json`, the policy-parsing copy as `testssl.json`, plus the log,
HTML, metadata, and policy-finding file for 90 days. `testssl.sh` may emit the
invalid JSON escape `\,` in certificate subject strings, including the
Cloudflare Authenticated Origin Pull CA subject. The workflow changes only
that escape to a literal comma in the policy copy, then still requires
`jq empty` before applying every TLS policy check. The job summary records the
target, UTC scan time, GitHub run, scanner revision, and result. No application
credentials or secrets are needed or permitted.

Authenticated DAST release evidence is separate from live TLS evidence. The DAST
smoke helper creates synthetic customer identities only, writes `auth-cookie`
and `zap-replacer.properties` as temporary `0600` files under `umask 077`, and
passes only non-secret startup options plus
`-configfile /run/dast/zap-replacer.properties` to ZAP. The non-secret
`-dir /zap/wrk/.ZAP` option gives the scanner UID a writable ZAP home without
relaxing cookie-file permissions. ZAP's cache, browser profile, and report
workspace run on container tmpfs and are discarded with the scanner container, so
host cleanup does not depend on deleting scanner-owned cache files. The cookie is
not passed as a raw process argument, and neither file belongs in GitHub
artifacts, job summaries, chat, screenshots, or issue comments. If a DAST cookie
or full replacer config is exposed, cancel the run, remove the artifact, treat
the synthetic session as compromised until the run cleanup completes, and review
the workflow/script change before retrying.

Pull requests additionally run a 12-minute local-only DAST smoke against an
ephemeral image and database. Its two-minute unauthenticated ZAP baseline
blocks selected header rules at `FAIL`; the synthetic-session smoke also blocks
unexpected responses and required security-header regressions. Warnings remain
report-only. The seven-day artifact contains only a sanitized scope/outcome
summary; raw ZAP responses, cookies, and replacer configuration are never
uploaded. Release/scheduled authenticated ZAP remains the deeper control.

Treat a failed scan as a release/deployment verification failure. A failed
staging scan blocks production deployment, while a failed production scan
marks the completed deployment workflow failed and prevents the private gate
from starting. A failed private gate after a successful production scan also
marks the completed deployment workflow failed. The production customer
automated gate blocks legacy TLS protocols,
weak/NULL/anonymous/export/RC4/3DES ciphers, expired or mismatched
certificates, missing/untrusted chains, all HIGH, CRITICAL, or FATAL
`testssl.sh` findings, and scanner errors. Review MEDIUM/LOW/INFO results in
the retained evidence and create a security change or explicit risk decision
where appropriate. SSL Labs is an optional manual second opinion; save its
public report link or screenshot with the change record, but do not make a
production release depend on its API.

For the Cloudflare Access-protected staging target, an unauthenticated
`302 Found` response is the expected Access challenge and is accepted by the
TLS evidence workflow. The staging gate still requires TLS 1.0 and TLS 1.1 to
be not offered and TLS 1.3 to be offered. TLS 1.2 is permitted for
compatibility but is not required. Certificate hostname/trust and chain checks
must be OK, the certificate must be unexpired, HSTS must meet the scanner
minimum, insecure redirects must be absent, and the final `overall_grade` must
be `A` or `A+`. Generic LUCKY13 wording and
`cipherlist_OBSOLETED: offered` on Cloudflare Universal SSL are retained as
review evidence for protected staging, not automatic failures.

If staging reports `HSTS: not offered`, fix the Cloudflare edge response for
`staging-sitbank.pp.ua`; the unauthenticated Access challenge is generated
before origin Nginx can add its own HSTS header. If staging reports
`cipherlist_OBSOLETED: offered`, document it as a Cloudflare Universal SSL
edge limitation. Removing that finding requires Advanced Certificate Manager
with custom cipher suite support; do not claim it is fixed until that paid
capability is enabled and verified. Do not make HSTS pass by disabling
Cloudflare Access, turning off the proxy, changing SSL mode away from Full
strict, or bypassing Authenticated Origin Pulls.

Cloudflare Access rollout is separate from TLS evidence collection. An
incomplete Access setup does not make the staging scan optional, and the JSON
normalization does not relax Origin Pull, certificate, or TLS policy checks.

The host-state verifier is the pre-deployment check of local certificate
material and renewal scheduling. The live scan complements it by verifying the
chain, hostname, expiry, protocols, ciphers, and HSTS actually served through
the public DNS and edge. Retain both forms of evidence after certificate or
edge changes.

## Password Reset Operations

Customer password reset is customer-domain only. Admin account recovery is not
implemented here and must not be handled through `/forgot-password`,
`/reset-password`, `/auth/password-reset/*`, or `/account-recovery`.

Operational checks for suspected recovery abuse:

```bash
psql "$DATABASE_MIGRATION_URL" --no-psqlrc --command \
  "SELECT created_at, event_type, outcome, ip_address, event_metadata->>'principal_ref' AS principal_ref FROM security_audit_events WHERE event_type LIKE 'password_reset%' OR event_type = 'manual_recovery_requested' ORDER BY created_at DESC LIMIT 50;"
psql "$DATABASE_MIGRATION_URL" --no-psqlrc --command \
  "SELECT status, count(*) FROM manual_recovery_requests GROUP BY status;"
python -m flask --app wsgi:app check-security-alerts --report-only
```

Expected reset email configuration in production:

- `PASSWORD_RESET_EMAIL_BACKEND=smtp`
- `PASSWORD_RESET_BASE_URL=https://sitbank.pp.ua`
- `PASSWORD_RESET_EMAIL_FROM=<approved sender>`
- `SMTP_HOST=<approved provider host>`
- `SMTP_USE_TLS=true`
- `SMTP_USERNAME_FILE=/run/secrets/smtp_username`
- `SMTP_PASSWORD_FILE=/run/secrets/smtp_password`

Production and staging SMTP delivery must use STARTTLS with default certificate
validation and hostname checking. Do not troubleshoot delivery failures by
disabling TLS validation, setting `SMTP_USE_TLS=false`, or pasting SMTP
credentials, reset links, OTPs, invite tokens, or email bodies into tickets or
chat.

Password policy in production:

- `PASSWORD_MIN_LENGTH` defaults to `15` when `APP_ENV=production`.
- Development and test may keep the explicit shorter default for local workflows.
- `production-check` and the production startup guard fail closed if a production
  app is configured below `15`.
- `PASSWORD_HISTORY_RETENTION_COUNT` defaults to `3`; change/reset reject the
  current and retained recent passwords.
- If an incident marks `force_password_change` for a customer, normal
  authenticated routes are blocked until the customer completes password change.
- This length floor complements mandatory TOTP onboarding; password-authenticated
  users still cannot use sensitive banking routes until current MFA setup is
  complete.

Payee activation cooldown in production:

- `PAYEE_COOLDOWN_SECONDS` controls when a newly added payee becomes usable.
- Development and test can keep the short default for demos and automated tests.
- Production must set `PAYEE_COOLDOWN_SECONDS` to at least `43200` seconds
  (12 hours), and `production-check` fails closed below that minimum.
- The customer UI displays server-calculated availability timing; operators
  should not ask users to supply or override activation timestamps.

Do not paste reset links into Discord, Telegram, ntfy, tickets, audit logs, or
security alert payloads. Reset links belong only in customer recovery email.
Manual recovery requests create pending records and audit events only; account
freezing, unlocking, MFA removal, or re-enrollment requires the isolated admin
manual recovery workflow.

Manual recovery operator workflow:

- Root admins review requests in the isolated admin browser UI at
  `GET /manual-recovery/requests`; explicit JSON clients can still request the
  same safe public request contract with `Accept: application/json`.
- The browser queue and detail view show only safe metadata: request reference,
  status, linked/unlinked indicator, request count, created/updated/expiry
  time, completion time, and allowed actions. Unlinked or unknown requests stay
  generic and do not prove whether a submitted identifier belongs to an
  account.
- Root admins move a request through `under_review`, `approved`, or `denied`
  using `POST /manual-recovery/requests/<id>/transition` with browser CSRF,
  an operator reason, and a fresh TOTP code. Approval and denial create durable
  maker-checker admin action requests when required by the service layer.
- Completion uses `POST /manual-recovery/requests/<id>/complete` after
  approval, again with browser CSRF, an operator reason, and a fresh TOTP code;
  the service queues the durable maker-checker completion request.
- Completion forces customer MFA re-enrollment, revokes active customer
  sessions, sends the existing manual recovery completion notification, and
  records `manual_recovery_completed` plus admin actor audit events.
- Public account-recovery submission never unlocks, mutates, or completes an
  account by itself.
- Browser admin logout clears the admin session and redirects to `/login`;
  explicit JSON clients still receive the JSON logout response.

## Customer Email OTP Registration Operations

Customer self-registration uses personal/customer email addresses. The exact
normalized domains in `ADMIN_ALLOWED_EMAIL_DOMAINS` are reserved for
staff/admin/root-admin workplace identities and are blocked from customer
registration:

- `sit.singaporetech.edu.sg`
- `singaporetech.edu.sg`

Registration no longer uses invite links or invite CLI commands. Customers
request a six-digit registration verification code from `/register`, receive it
by email, verify it in the same browser session, and then complete account
creation with the same normalized email address. Codes expire after 5 minutes,
are one-time use, and requesting a new code invalidates the previous code. The
application stores only an HMAC under the active session-HMAC key in
PostgreSQL; raw codes must never
be recorded in runbooks, tickets, logs, Discord, Telegram, or screenshots.

Customer identity is canonicalized before OTP issuance and final creation.
Configured plus-alias and dot-insensitive domains collapse to one canonical
identity, and configured temporary-email domains are rejected. Duplicate and
ineligible requests return the same minimal public response; precise reason
codes remain only in redacted audit metadata. Treat canonicalization policy
changes as a data migration and collision-review event.

Registration OTP delivery uses the same security email backend and SMTP
settings as password reset email:

- `PASSWORD_RESET_EMAIL_BACKEND=smtp`
- `PASSWORD_RESET_EMAIL_FROM=<approved sender>`
- `PASSWORD_RESET_BASE_URL=https://sitbank.pp.ua`
- `SMTP_HOST=<approved provider host>`
- `SMTP_USE_TLS=true`
- `SMTP_USERNAME_FILE=/run/secrets/smtp_username`
- `SMTP_PASSWORD_FILE=/run/secrets/smtp_password`

Operational checks:

- Verify SMTP settings with a controlled staging registration using a test
  personal customer email address.
- Investigate `registration_otp` audit events by outcome
  (`requested`, `verified`, `blocked`, `failed`, `expired`, or `locked`)
  without expecting raw email addresses or codes in event metadata.
- If registration email delivery fails, the request fails closed and the
  PostgreSQL OTP challenge row is deleted.
- Existing-account requests intentionally return the same generic response as
  eligible requests; do not treat the absence of an outgoing email as customer
  proof without independent identity checks.

## Turnstile Operations

Turnstile is defense in depth for public authentication abuse protection. It
does not replace CSRF, rate limits, password checks, MFA, sessions, Cloudflare
Access, Tailscale private admin access, Flask authorization, or audit logging.

Enable only the routes intended for the environment:

- `TURNSTILE_CUSTOMER_LOGIN_ENABLED`
- `TURNSTILE_CUSTOMER_REGISTER_OTP_ENABLED`
- `TURNSTILE_CUSTOMER_REGISTER_ENABLED`
- `TURNSTILE_CUSTOMER_PASSWORD_RESET_ENABLED`
- `TURNSTILE_CUSTOMER_MANUAL_RECOVERY_ENABLED`
- `TURNSTILE_ADMIN_LOGIN_ENABLED`
- `TURNSTILE_ADMIN_INVITE_ACCEPT_ENABLED`

Production and staging require every listed flag,
`TURNSTILE_FAIL_CLOSED_IN_PRODUCTION=true`, `TURNSTILE_ENABLED=true`,
`TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY` or `TURNSTILE_SECRET_KEY_FILE`, and
the official verifier URL
`https://challenges.cloudflare.com/turnstile/v0/siteverify`. Local/test
verifier overrides are for isolated mocks only. Disabling a required flag is a
readiness failure, not a production rollback mechanism; do not point a
production-like environment at a custom verifier host.

GitHub Environment variables use the `PROD_TURNSTILE_*` and
`STAGING_TURNSTILE_*` prefixes; the renderer emits unprefixed runtime keys and
pins the official verifier. Store server credentials as the environment
secrets `PROD_TURNSTILE_SECRET_KEY` and `STAGING_TURNSTILE_SECRET_KEY`.
Deployment installs them as separate root-managed
`/etc/sitbank*/secrets/turnstile_secret_key` files and never writes the value
to `container.env`. Production and staging use separate widgets for
`sitbank.pp.ua`/`www.sitbank.pp.ua` and `staging-sitbank.pp.ua`. The admin app remains private behind Tailscale while its public-auth entry routes retain
Turnstile defense in depth.
