# Deployment

## Current Architecture

Only Flask/Gunicorn runs in the SITBank container. Nginx, TLS, PostgreSQL, and backups remain host-managed on EC2. Sessions, authentication counters, OTP/reset state, alert dedupe, and breached-password circuit state live in application-owned PostgreSQL tables.

- Production public host: `sitbank.pp.ua`
- Production public `www` host: `www.sitbank.pp.ua` redirects to
  `https://sitbank.pp.ua`
- Production private admin URL: `https://admin-sitbank.tailca101b.ts.net/`
- Staging public host: `staging-sitbank.pp.ua`
- Staging Cloudflare Access host: `staging-sitbank.pp.ua`
- Production customer access: public HTTPS
- Staging access boundary: Cloudflare Access plus Authenticated Origin Pull
  plus origin-side Access JWT validation
- Admin access boundary: Tailscale/private operator access only
- Production image form: `ghcr.io/koon-kiat/sitbank@sha256:<digest>`
- Repository identity: `Koon-Kiat/SITBank`
- Production config root: `/etc/sitbank`
- Production compose dir: `/opt/sitbank`
- Production service: `sitbank-container.service`
- Production alert timer: `sitbank-security-alerts.timer`
- Production database: `sitbank_db`
- Production owner role: `sitbank_owner`
- Production app role: `sitbank_app`
- Production admin runtime role: `sitbank_admin` or another distinct least-privilege role
- Staging config root: `/etc/sitbank-staging`
- Staging compose dir: `/opt/sitbank-staging`
- Staging service: `sitbank-staging-container.service`

For centralized verification commands and EC2 operational path inventory, see
`docs/runbooks/global-verification.md`. That runbook links these deployment
paths to safe inspection commands and marks secret-bearing paths that must not
be printed.

The repository identity above was revalidated on 2026-07-01: GitHub reported
`@Koon-Kiat` as an administrator of `Koon-Kiat/SITBank`, so the CODEOWNERS,
GHCR, Cosign/OIDC, bootstrap, and deployment trust paths use an approved owner.
The SonarQube Cloud binding remains `koon-kiat / Koon-Kiat_SITBank`; live
provider settings still require provider-owned evidence.

The separate `.github/workflows/gitleaks.yml` workflow is a pre-merge and
protected-branch source control, not a deployment step. It scans full Git
history with redacted output and no production secrets, artifacts, database
access, Tailscale access, bootstrap, or EC2 impact. The custom repository
secret scanner remains in the main CI path. Response procedures are documented
in `docs/security/assurance/secret-scanning.md`.

ShellCheck, Hadolint, and Semgrep are also pre-deployment source gates, not
deployment steps. They use no production secrets and do not execute the code
they inspect. ShellCheck and Hadolint use shared tracked-file discovery;
Semgrep runs local/OSS ERROR-severity SAST from a pinned container digest.
Passing these checks does not replace container build/smoke validation or
manual staging verification for behavior-changing deployment edits.

## Local Deployment Validation

The normal local CI command can run without Docker:

```bash
scripts/ci-local
```

If the Docker CLI or daemon is unavailable, normal mode marks Docker/Compose
checks as `SKIPPED` and reports an overall partial pass. That result covers the
non-Docker checks but does not prove the production or staging Compose model.

Use strict mode before deployment-related pull requests:

```bash
scripts/ci-local --require-docker
```

Alternatively:

```bash
CI_LOCAL_REQUIRE_DOCKER=1 scripts/ci-local
```

Strict mode fails when Docker, the Docker daemon, or Docker Compose is
unavailable. It runs `ops/container/validate-compose.sh`, which renders and
validates both `compose.prod.yml` and `compose.staging.yml` with the local
validation override. This checks the Compose service model, including the
customer/admin separation and wiring enforced by deployment tests, without
starting containers. CI/CD remains the source of truth for deployment
validation and release evidence.

SonarQube Cloud analysis is a separate reporting workflow, not a deployment
stage or production prerequisite. It receives no EC2, SSH, AWS, database, or
application runtime credentials and does not run bootstrap, publish, or deploy
commands. A SonarQube dashboard result must not be represented as deployed
runtime evidence. See `docs/security/assurance/sonarqube.md`.

## Database Baseline

Existing databases that already have the baseline tables must be adopted into Alembic instead of recreated.

```bash
python -m flask --app wsgi:app verify-migration-baseline
python -m flask --app wsgi:app db stamp 20260610_0001
python -m flask --app wsgi:app db upgrade
```

Do not run `db.create_all()` in deployment. For role cutover use `sitbank-database-cutover prepare`, review the generated SQL, and execute it only during an approved maintenance window.

Migration `20260702_0020` aligns the production migration baseline with the
SQLAlchemy model metadata. It backfills missing `transactions.transaction_hash`
values from the canonical transaction fields used by the application and then
enforces `transaction_hash` as `NOT NULL`; the downgrade relaxes only that
nullability and does not delete transaction evidence. Run it in staging first,
preserve the staging verification output, and take or confirm an encrypted
production backup before production `db upgrade`. After the migration, run
`verify-migration-baseline` and `verify-runtime-db-privileges`; do not repair
reported drift with ad hoc production `ALTER TABLE`, `DROP INDEX`, or
`DROP CONSTRAINT` commands.

## Disposable Database Reset

The current schema intentionally has no compatibility backfill for obsolete
user, invite, browser-credential, session-risk, or 9-digit account-number
state. Reset only an environment confirmed to contain disposable project data.
Stop both customer and admin services first, preserve the maintenance record,
and run the command in the normal application image with that environment's
runtime configuration and schema-owner migration URL.

Run staging preflight and execution first:

```bash
python -m flask --app wsgi:app reset-demo-database --target staging --disposable-data-confirmed
python -m flask --app wsgi:app reset-demo-database --target staging --execute --disposable-data-confirmed --confirm "RESET STAGING DEMO DATABASE"
```

Do not place this command in deployment automation. Production requires the
successful staging evidence, protected manual approval, and a fresh encrypted
root-managed mode-`0600` backup outside the repository/CI workspace:

```bash
sudo /usr/local/sbin/sitbank-backup-encrypted --environment production
python -m flask --app wsgi:app reset-demo-database --target production --disposable-data-confirmed
python -m flask --app wsgi:app reset-demo-database --target production --execute --disposable-data-confirmed --staging-verified --approved --backup-file /var/backups/sitbank/sitbank-production-sitbank_db-<timestamp>.pgdump.age --confirm "RESET PRODUCTION DEMO DATABASE"
```

The executing operator must substitute the exact backup created for this
maintenance window. The reset drops the selected database's reflected schema,
applies the complete Alembic chain, and then verifies that user/payee account
numbers satisfy the current format. It never runs during normal deployment.

Migration `20260703_0023` adds canonical customer registration email identity,
MFA setup-session binding timestamps, and versioned recovery-code HMACs.
Current registration writes the canonical identity directly; the authorized
reset replaces old customer rows instead of inferring canonical identity.

Migration `20260703_0022` adds PayUp support with `users.payup_daily_limit`,
the `transactions.transaction_type` constraint, and the
`payup_pending_transfers` table. After upgrade, verify PayUp lookup, amount,
confirmation, daily-limit, and transfer-limit settings through staging before
production rollout.

Migration `20260703_0024` enforces exactly 12 decimal digits for non-null
`users.account_number` and all `payees.account_number` values. Registration
randomizes all 12 positions independently; route and form validation match the
database constraints. The migration does not convert obsolete identifiers.

Migration `20260704_0025` adds nullable transaction-integrity key id,
algorithm, and version metadata. Existing rows remain explicitly legacy;
new Local Transfer and PayUp rows use the dedicated
`TRANSACTION_LEDGER_HMAC_KEYS_JSON` keyring and cover transaction type plus all
stored ledger fields. Provision the environment-specific root-managed keyring
and matching `TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID` before `db upgrade` and
application restart. Do not reuse session or audit HMAC keys.

Migration `20260704_0027` hardens PayUp daily-limit bounds, staff invite
acceptance verification lockouts, and recovery-code compatibility. It adds the
`ck_users_payup_daily_limit_bounds` database check, stores invite verification
failure lockout counters on `staff_invites`, and marks unused legacy
recovery-code HMAC rows consumed. After upgrade, verify transfer-limit settings,
PayUp lookup throttling, invite acceptance/reset, and password-reset MFA in
staging before production rollout.

Migration `20260705_0028` removes the transaction-integrity compatibility
boundary and adds the per-customer PayUp enable flag. Before upgrading, stop
ledger writes, confirm a fresh encrypted backup, and run the current trusted
application image against the existing schema:

```bash
python -m flask --app wsgi:app security backfill-transaction-integrity
python -m flask --app wsgi:app security backfill-transaction-integrity --confirm
python -m flask --app wsgi:app db upgrade
```

The first command is validation-only and reports aggregate counts. The
confirmed command signs only rows with entirely absent integrity metadata,
refuses partial or invalid signed rows, verifies every row, and commits the
backfill with its completed audit event. The migration then fails closed if
any row is not keyed HMAC-SHA256 version 1 and makes all integrity metadata
non-null. Run and preserve sanitized staging evidence first. Do not downgrade
this migration or restore legacy verification; rollback requires restoring the
approved encrypted backup and previously trusted application release.

## Deployment Prerequisites

Install `/etc/sitbank/secrets/security_alert_webhook_url` or
`/etc/sitbank-staging/secrets/security_alert_webhook_url` with the
operator-managed HTTPS alert webhook for that environment. Install
`smtp_username` and `smtp_password` secret files for the reset email provider,
and set `PASSWORD_RESET_EMAIL_BACKEND=smtp`, `PASSWORD_RESET_EMAIL_FROM`,
`PASSWORD_RESET_BASE_URL`, `SMTP_HOST`, `SMTP_PORT`, and `SMTP_USE_TLS=true` in
the container runtime environment. Production rejects console reset email,
non-HTTPS reset base URLs, and plaintext SMTP delivery. SMTP STARTTLS uses
Python's default certificate validation and hostname checking; do not configure
production or staging with unverifiable SMTP TLS.

Turnstile is disabled until `TURNSTILE_ENABLED=true` and route-specific flags
are set. Customer login, registration OTP, registration submit, password
reset, manual recovery, admin login, and admin invite acceptance each have separate
`TURNSTILE_*_ENABLED` flags. Production and staging must use the official
Cloudflare Siteverify endpoint
`https://challenges.cloudflare.com/turnstile/v0/siteverify`; local/test mocks
must not override that production endpoint. Browser rendering also requires
`TURNSTILE_SITE_KEY` and the narrow CSP allowance for
`https://challenges.cloudflare.com`.

Deployment maps production and staging GitHub Environment variables named
`PROD_TURNSTILE_*` and `STAGING_TURNSTILE_*` to unprefixed
`TURNSTILE_ENABLED`, `TURNSTILE_SITE_KEY`, `TURNSTILE_VERIFY_URL`, and
`TURNSTILE_*_ENABLED` runtime settings. Configure separate Cloudflare widgets:
the production widget covers `sitbank.pp.ua` and `www.sitbank.pp.ua`, while the
staging widget covers `staging-sitbank.pp.ua`. Store server credentials only as
the `PROD_TURNSTILE_SECRET_KEY` and `STAGING_TURNSTILE_SECRET_KEY` GitHub
Environment secrets. The trusted deployment installs each credential as
`/etc/sitbank*/secrets/turnstile_secret_key`; Compose mounts that
environment-specific credential read-only into both the customer and admin
runtimes and exposes only
`TURNSTILE_SECRET_KEY_FILE=/run/secrets/turnstile_secret_key`.

Production-like readiness fails closed unless Turnstile, the site and secret
keys, `TURNSTILE_FAIL_CLOSED_IN_PRODUCTION`, and every runtime-relevant
customer and admin route flag are enabled. This includes
`TURNSTILE_CUSTOMER_MANUAL_RECOVERY_ENABLED`. Private admin networking remains
a separate boundary; it does not justify disabling bot protection. This wiring
adds no public admin hostname and does not replace rate limits, CSRF, MFA,
Cloudflare Access, or Tailscale.

Install the host-managed backup encryption recipients file before running
database cutover or scheduled backups:

- production: `/etc/sitbank/backup-age-recipients.txt`
- staging: `/etc/sitbank-staging/backup-age-recipients.txt`

The recipients file contains age public recipients only. Decryption identities
remain outside the repository and outside application containers. Bootstrap
installs `age`, `/usr/local/sbin/sitbank-backup-encrypted`, and
`/usr/local/sbin/sitbank-restore-preflight`; encrypted backups are stored under
`/var/backups/sitbank` or `/var/backups/sitbank-staging` as root-owned mode
`0600` `.pgdump.age` files. Restore checks are explicit operator preflights
that validate owner, mode, parent directory safety, repository/CI-workspace
exclusion, target database, and host-only identity material; they are not Flask
routes or deployment defaults. Recurring backup timers, restore drills, and
encrypted-archive pruning remain host/operator-owned evidence.

Deploy the signed image through the restricted wrapper so it runs
`production-check`, `db upgrade`, `apply-runtime-db-privileges`,
`verify-runtime-db-privileges`, and readiness checks before declaring success.
Before staging, release verification also verifies a GitHub artifact
attestation, pushed by the trusted publish job to the image registry, for the
exact `ghcr.io/koon-kiat/sitbank@sha256:<digest>` subject. The verifier requires
repository `Koon-Kiat/SITBank`, source ref `refs/heads/main`, the resolved
release commit, exact signer workflow `.github/workflows/ci-deploy.yml`,
GitHub's OIDC issuer, and the same digest passed to deployment. A missing,
wrong-subject, wrong-ref, wrong-workflow, or unverifiable attestation fails
closed. This is SLSA Build L1/L2-aligned release evidence, not a claim of
formal SLSA certification. Repository files do not prove live GHCR state,
branch protection, or GitHub Environment settings; preserve sanitized
release/provider evidence separately.

Production deployment runs from the trusted `main` workflow only after release
verification, staging deployment, and the post-deployment staging TLS scan all
succeed. A successful production deployment is followed by public production
TLS verification and then the required protected private-admin tailnet gate.
The visible Actions checks for those gates are `Release verification`,
`Deploy staging`, `Verify staging TLS`, `Deploy production`,
`Verify production TLS`, and `Verify private admin tailnet`. Their stable
kebab-case job IDs remain in workflow `needs:` expressions and are not display
labels.
Production deployment is environment-approved automatic after successful
staging gates. GitHub Environment approval pauses that automatic `main` flow;
there is no direct manual production dispatch target.
If either post-deploy verification fails, the workflow fails even though the
production deployment already completed. Leave the repository variable
`PROD_DEPLOY_ENABLED` unset or false until the production admin secret files
and matching
`PROD_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID` are ready; when the flag is not
explicitly true, production deployment is skipped.

### GitHub Actions Variables

Configure these non-secret repository variables under **Settings > Secrets and
variables > Actions > Variables** when their reviewed defaults are not
appropriate:

| Variable | Safe behavior when unset | Workflow consumer |
| --- | --- | --- |
| `ENABLE_GITHUB_CODE_SECURITY` | Defaults to `false`; private-repository dependency review runs only when the value is exactly `true` | `Dependency review` (`dependency-review` job ID) in `.github/workflows/ci-deploy.yml` |
| `STAGING_PUBLIC_HOST` | Defaults to the reviewed staging hostname `staging-sitbank.pp.ua` | Staging deployment URL/configuration and post-deployment staging TLS verification |
| `PROD_PUBLIC_HOST` | Defaults to the reviewed production hostname `sitbank.pp.ua` | Production deployment URL/configuration and post-deployment production TLS verification |
| `STAGING_EC2_HOST` | Required private Tailscale MagicDNS name or `100.x.y.z` address | Staging OpenSSH deployment target |
| `PROD_EC2_HOST` | Required private Tailscale MagicDNS name or `100.x.y.z` address | Production OpenSSH deployment target |
| `PROD_DEPLOY_ENABLED` | Defaults to disabled unless exactly `true` | Production deployment gate |

The host fallbacks are explicit repository conventions, not discovery
mechanisms. If DNS, certificates, or the public edge move, update the matching
repository variable in the same reviewed change; do not point verification at
an unrelated host. The reusable TLS workflow rejects empty values, URLs, and
command fragments and scans only HTTPS.

These values are hostnames and feature flags, so they are not secrets.
Credentials such as `SONAR_TOKEN`, SSH private keys, known-hosts material,
Cloudflare API tokens, database URLs, signing material, and application keys
must remain GitHub Actions secrets or protected environment secrets as already
documented. Existing staging and production deployment variables remain scoped
to their protected GitHub environments and are validated before deployment;
do not move secret values into repository variables.

Each deployment environment also stores a separate Tailscale OAuth client as
`TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET`. The staging client may advertise
only `tag:github-ci-staging-deploy`; the production client may advertise only
`tag:github-ci-prod-deploy`. Regenerate `STAGING_EC2_KNOWN_HOSTS` and
`PROD_EC2_KNOWN_HOSTS` for their private Tailscale targets and verify the SSH
fingerprints out of band. Keep the existing OpenSSH private keys and strict
host-key checking. Both the deployment and trusted-main bootstrap workflows
join with the matching environment OAuth client before any SSH or SCP to the
private host and always log out afterward. Do not enable Tailscale SSH or
Funnel. After both private deployment and bootstrap paths are proven, remove
public SSH exposure from the EC2 firewall and security group.

### Tailscale Deployment Rollout

Before changing the live tailnet, export and securely retain the current
Access Controls policy. Merge the reviewed paths from
`ops/tailscale/acl-policy.hujson`, including its deny-by-omission
cross-environment policy tests, into the live policy:

- `tag:github-ci-admin-verify` to `tag:admin-sitbank:443`
- `tag:github-ci-staging-deploy` to `tag:sitbank-staging-ec2:22`
- `tag:github-ci-prod-deploy` to `tag:sitbank-prod-ec2:22`

Apply the matching destination tag to each stable host. Prefer separate
staging and production EC2 instances; if one host carries both destination
tags, retain separate Linux deploy users, sudoers rules, wrappers, and runtime
directories. Create three OAuth clients, restrict each client to its one source
tag, and store it only in `admin-tailscale`, `staging`, or `production` as
appropriate. Update the private EC2 host variables and verified known-hosts
values, deploy staging first, then allow the automatic production flow through
its protected environment. Remove public port `22` only after both private
paths pass. Committed files and tests do not prove live Tailscale, GitHub
Environment, security-group, or host-firewall state; retain sanitized operator
evidence separately.

Once `STAGING_EC2_HOST` and `PROD_EC2_HOST` use a Tailscale IP or MagicDNS
name, both bootstrap and deployment require the private tailnet path; public
SSH is not a workflow fallback. Retain an approved host-recovery path such as
AWS console or SSM access. A temporary security-group exception is break-glass
only: authorize it explicitly, restrict its source and lifetime, record the
change, and remove it immediately after recovery.

### Protected Private-Admin Verification Environment

The manual `.github/workflows/tailscale-private-admin-verify.yml` workflow
uses a GitHub-hosted runner that temporarily joins the tailnet. The
`.github/workflows/ci-deploy.yml` production workflow implements the same
visible `Verify private admin tailnet` check directly after the internal
`deploy-production` and `verify-production-tls` jobs succeed.
The direct job is necessary because the previous reusable-workflow call did
not receive the protected environment secrets. Create a GitHub
Environment named `admin-tailscale`, require manual approval by trusted
maintainers, and restrict its deployment branches to `main`. Each production
run pauses for that approval before the required private gate can access its
secret. This is the required protected post-production-deploy gate and it runs
after production public TLS verification. The production caller explicitly
selects `auth_mode: oauth`. Store `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET`
only as that environment's secrets. The OAuth client must have **Keys > Auth
Keys > Write** permission and be restricted to
`tag:github-ci-admin-verify`, whose tailnet grants reach only
`tag:admin-sitbank:443`.

Manual verification may instead select `auth_mode: authkey`, in
which case the same environment must provide `TAILSCALE_AUTH_KEY`. That key
must be short-lived, one-off where possible, ephemeral, pre-approved when
device approval applies, and tagged `tag:github-ci-admin-verify`. Never configure both
modes for one run. OAuth is the preferred/default mode; the auth-key mode is a
compatibility path with separate rotation.

Do not expose the secret as a repository variable or general repository
secret, and do not permit pull requests, Dependabot, forks, or untrusted
branches to use the environment. The private hostname input defaults to
`admin-sitbank.tailca101b.ts.net`. The workflow checks the private admin URL
before and after joining, validates the unauthenticated login response over
TLS, and logs out. It neither deploys nor changes Flask, Nginx, EC2, tailnet
policy, Tailscale Serve, or Tailscale Funnel.

Rotate the selected credential before expiry or after exposure. For OAuth,
replace both OAuth secrets and revoke the old client after an approved run.
For auth-key mode, replace `TAILSCALE_AUTH_KEY`, validate an approved run, and
revoke the old key. Offboarding requires review of environment
approvers/branch rules and stale nodes. To remove CI tailnet access, delete all
three optional credential secrets, revoke the applicable client/key, remove
CI tag grants/devices, and disable or delete the environment.

### Production Tailscale Provisioning

Production bootstrap installs the non-secret scripts from `ops/tailscale/`:

- `/usr/local/sbin/sitbank-install-tailscale`
- `/usr/local/sbin/sitbank-configure-tailscale-admin`
- `/usr/local/sbin/sitbank-verify-tailscale-admin`

Review plans before an approved host change:

```bash
sudo /usr/local/sbin/sitbank-install-tailscale --dry-run
sudo /usr/local/sbin/sitbank-configure-tailscale-admin \
  --dry-run --auth-mode oauth
# Auth-key compatibility plan:
sudo /usr/local/sbin/sitbank-configure-tailscale-admin \
  --dry-run --auth-mode authkey
```

Mutating execution requires `--confirm`. Host configuration supports
`oauth`, `authkey`, and `interactive` modes. OAuth reads
`TS_OAUTH_CLIENT_ID`/`TS_OAUTH_SECRET`; auth-key mode reads
`TAILSCALE_AUTH_KEY`. Secrets are supplied through protected operator
environment handling and an inherited file descriptor, are never printed or
written to a named file, and must be unset immediately afterward. Detailed
commands, ACL review, onboarding/offboarding, and emergency disable steps are
in `ops/tailscale/README.md`.

The selected production model is private Serve HTTPS on port `443` with the
sole backend `http://127.0.0.1:5002`. The configure script resets unsafe node
advertisements, refuses existing non-empty Serve configuration, never enables
Funnel, and requires pre/post verification. It intentionally does not
configure staging admin, the customer app, tailnet ACLs, group membership, or
device approval. Normal CI tests only the script contracts.

### Production Host Tailscale Preflight

Production bootstrap installs
`ops/deploy/verify-tailscale-admin-access` as
`/usr/local/sbin/verify-tailscale-admin-access` with root ownership and mode
`0755`. Run it on the EC2 host after production deployment and after changes
to Tailscale, Serve, Funnel, Nginx, or the admin listener:

```bash
sudo /usr/local/sbin/verify-tailscale-admin-access --mode serve
```

Serve mode succeeds only when the local Tailscale node reports `Running`,
Tailscale SSH and Funnel are disabled, the admin service has only the
`127.0.0.1:5002` listener, loopback readiness returns `200`, Nginx contains
neither an admin-port upstream nor the private Tailscale hostname, Serve
exposes only `admin-sitbank.tailca101b.ts.net:443` to
`http://127.0.0.1:5002`, and an unauthenticated `GET` to the private `/login`
entrypoint returns `200`.
The script reads local status and configuration only. It does not run
`tailscale up`, change Serve or Funnel, modify policy, call a Tailscale API, or
use OAuth/auth-key material.

`--mode ssh` verifies the same local Tailscale, Tailscale-SSH-disabled,
Funnel, listener, readiness, and Nginx prerequisites for a reviewed private
port-forward diagnostic path,
but does not claim that a remote tunnel or browser session was tested.
`--mode documentation-only` validates arguments and emits a warning without
performing live checks; it is for pre-rollout documentation review and is not
deployment evidence. Any error from a live mode is a failed preflight. Keep
the admin unavailable rather than weakening the listener, Nginx, or Funnel
boundary.

This EC2-local preflight complements rather than replaces the protected
GitHub workflow. The host script proves local listener and Serve/Funnel
posture; the protected workflow proves reachability from an approved
ephemeral tailnet node. Neither control proves live ACL membership, device
approval, or operator offboarding state, which remains operator-owned
evidence.

Set `STAGING_ROOT_ADMIN_EMAILS` in the protected `staging` environment and
`PROD_ROOT_ADMIN_EMAILS` in the protected `production` environment before
deploying admin bootstrap support. They are sensitive privileged-identity
configuration: staging must contain exactly 2 comma-separated SIT workplace
email addresses and production must contain exactly 5. The deployment
workflow validates the secret without printing it, uploads it as a restricted
deployment input, and installs it as `/etc/sitbank*/secrets/root_admin_emails`
so `sitbank-admin` and `sitbank-staging-admin` can enforce the fixed root-admin
group through `ROOT_ADMIN_EMAILS_FILE`. The production/admin runtime rejects the
built-in development root-admin set, placeholders, demo/example identities,
duplicates after normalization, personal domains, and non-approved domains.
Do not copy the real allowlist into issues, pull requests, screenshots, logs,
or job summaries.
Root-admin bootstrap remains manual over SSH inside the admin container; it is
not a GitHub Actions workflow, deployment automation step, or non-interactive
bootstrap wrapper.
`ADMIN_ALLOWED_EMAIL_DOMAINS` defines the approved privileged workplace-domain
allowlist for root-admin, admin, and staff identities. Do not set it to
personal-provider domains; staff invites use the workplace email and do not
collect personal backup email contacts. The current invite schema stores only
the approved workplace email and has no personal-email compatibility field.
Migration `20260704_0026` persists staff invite acceptance session binding,
restart counters, and lock timestamps. It does not store raw invite tokens,
TOTP secrets, passwords, or workplace verification codes. After deployment,
root admins can reset a locked active invite acceptance attempt through the
admin invite screen with a fresh TOTP step-up; do not repair locked invites by
editing production rows ad hoc.

Production admin does not use a public DNS hostname. Keep admin access on the
private Tailscale Serve URL `https://admin-sitbank.tailca101b.ts.net/` and do
not enable Tailscale Funnel. Bootstrapped root admins open
`https://admin-sitbank.tailca101b.ts.net/login`, authenticate with the existing
admin password and TOTP flow, and are redirected to the private dashboard at
`https://admin-sitbank.tailca101b.ts.net/`. Customer accounts cannot access the
admin runtime. Production still requires root-managed admin secret files under
`/etc/sitbank/secrets`: `admin_secret_key`,
`admin_wtf_csrf_secret_key`, `admin_session_hmac_keys_json`,
`admin_session_lookup_hmac_key`, `admin_database_url`, and
`admin_password_pepper_b64`.
`admin_database_url` must use a dedicated admin runtime database role and must
not reuse either `database_url` or `database_migration_url`. Provision that
database role, and rotate its password, with a PostgreSQL administrator or
other approved role-management account before deployment; the deployment
wrapper only grants schema, table, sequence, and default privileges to the
existing role after migrations run.
`admin_session_lookup_hmac_key` must not reuse the customer
`session_lookup_hmac_key`.

`SECURITY_AUDIT_HMAC_KEY` is mandatory for production audit integrity.
`SECURITY_AUDIT_ANCHOR_PATH` is also mandatory in production; the one-EC2
runtime renders `SECURITY_AUDIT_ANCHOR_PATH=/var/lib/sitbank/security-audit.anchor`.
The bootstrap creates `/var/lib/sitbank` outside the database volume with
restrictive permissions and mounts it into the app/admin containers so
`check-security-alerts` verifies the hash chain and compares the anchor during
automated alert runs. Do not point the setting at an untrusted, world-writable,
repository-local, or database-local path just to satisfy deployment.
Audit trigger changes require `db upgrade`, then `apply-runtime-db-privileges`
and `verify-runtime-db-privileges`; they do not require an EC2 edge bootstrap
unless host-managed deployment, Nginx, or systemd files also changed.
Production also renders
`SECURITY_ALERT_STATE_PATH=/run/state/security-alert-state.json` and mounts the
host alert-state directory there so `check-security-alerts` can alert when
`users` or `security_audit_events` shrink after a direct database wipe.

Security alert scheduling is host-managed systemd state. Changes to
`ops/systemd/sitbank-security-alerts.service`,
`ops/systemd/sitbank-security-alerts.timer`, or
`ops/deploy/sitbank-container-runtime` require the trusted EC2 bootstrap after
merge so production receives the unit files and runs `systemctl daemon-reload`.
Then enable or verify the timer:

```bash
sudo systemctl enable --now sitbank-security-alerts.timer
sudo systemctl status sitbank-security-alerts.timer
journalctl -u sitbank-security-alerts.service
```

## Host-Managed TLS Certificate Lifecycle

Certificates are issued and renewed on the EC2 host. Certbot's ACME account
state, certificate archive, and TLS private keys are host-managed under
`/etc/letsencrypt`; none of that material may be committed to this repository.
The Flask application and its containers do not issue certificates and do not
mount or read TLS private keys. Normal deployment must never generate or
overwrite a private key.

## Live TLS Scan Evidence

The host configuration is necessary but not sufficient evidence of the public
TLS posture: the deployed certificate chain, Nginx/OpenSSL build, DNS, and edge
configuration decide what Internet clients are actually offered. The **Live TLS
scan evidence** GitHub Actions workflow records that external evidence with the
checksum-verified `testssl.sh` 3.2.3 source release.

The workflow runs weekly, can be started manually from the Actions tab, and is
called by the trusted deployment workflow. After a successful staging deploy it
scans the staging customer endpoint; production deployment is blocked until
that evidence passes. After a successful production deploy it scans the
production customer endpoint, making the resulting artifact the release's live
TLS evidence. A production scan failure marks the deployment
workflow failed and prevents the private-admin tailnet gate from starting.
After the production TLS scan succeeds, the deployment workflow calls the
protected private-admin gate; failure of that gate also fails the completed
deployment workflow. Run the TLS workflow manually after Nginx, certificate,
DNS, load-balancer, CDN/WAF, or host TLS changes outside the normal deployment
path. It deliberately does not run on pull requests: PRs do not create a
separate public TLS endpoint.

By default it scans these hostname-only targets, which can be overridden as
manual workflow inputs when an approved endpoint changes:

| Environment | Workflow input | Default target | Artifact |
| --- | --- | --- | --- |
| Staging customer | `staging_host` | `https://staging-sitbank.pp.ua` | `tls-scan-staging-sitbank` |
| Production customer | `production_host` | `https://sitbank.pp.ua` | `tls-scan-prod-sitbank` |

Each target preserves the scanner's original `testssl.raw.json` and produces a
separate `testssl.json` for policy parsing, plus a text log, HTML report, scan
metadata, and policy-finding file. `testssl.sh` can emit the invalid JSON escape
`\,` in certificate subject strings such as the Cloudflare Authenticated
Origin Pull CA subject. The policy copy normalizes only that escape to a comma
before strict `jq empty` validation; the raw file remains unchanged for audit
evidence. All files are retained as GitHub Actions artifacts for 90 days. The
target job summary identifies the UTC scan time, host, run ID/attempt, scanner
version, and pass/fail result. TLS scanning uses no application credentials
and the workflow contains no application secrets.

## Release Smoke And DAST Evidence

Release verification runs `ops/container/smoke-test.sh` against the exact image
digest that will be deployed. When authenticated DAST is enabled, the helper
creates only synthetic customer identities, restricts the target to loopback or
the explicit smoke container host, and keeps real customer, staff, and admin
credentials out of the scan path. Its synthetic login submits Cloudflare's
documented public dummy token only with the official always-pass Turnstile test
keys configured by the isolated smoke harness. The smoke app alone receives
`DEPLOYMENT_TARGET=smoke` and `TURNSTILE_ALLOW_TEST_ACTION=true` because the
official dummy-token response uses the provider action `test`; production
readiness rejects that flag outside the smoke target. Real deployments continue
to use protected real Turnstile credentials and route-specific action
validation.

DAST cookie handling is intentionally file-based. `auth-cookie` and
`zap-replacer.properties` are created under `umask 077`, written as `0600`
temporary files, mounted read-only into ZAP, and removed by the cleanup trap when
the smoke test exits. The host-visible ZAP command receives the non-secret
scanner home option `-dir /zap/wrk/.ZAP` plus
`-configfile /run/dast/zap-replacer.properties`; it must not include a raw cookie
value or `replacement=${...}` argument. Do not retain the DAST temporary
directory, upload it as an artifact, or paste its contents into release notes.
ZAP's own cache, browser profile, and report workspace run on container tmpfs
so scanner-owned files disappear with the container instead of breaking host
cleanup.

The production customer verification gate fails for
SSLv2, SSLv3, TLS 1.0, or TLS 1.1; weak, NULL, anonymous, export, RC4, or 3DES
ciphers; missing, disabled, or too-short HSTS; expired certificates; hostname
mismatches; untrusted, incomplete, or missing certificate chains; any
`testssl.sh` HIGH, CRITICAL, or FATAL finding; and missing/invalid JSON
evidence. MEDIUM/LOW/INFO findings remain in the evidence and require operator
review; they are not an automatic release block unless they match one of the
explicit prohibited classes above.

The Cloudflare Access-protected staging target `staging-sitbank.pp.ua` uses a
staging-specific acceptance gate because unauthenticated HTTP requests should
receive a `302 Found` Access challenge before the app. The staging scan still
fails unless TLS 1.0 and TLS 1.1 are not offered and TLS 1.3 is offered.
TLS 1.2 may remain available for compatibility but is optional for staging.
Certificate hostname/trust and chain checks must be OK, the certificate must
not be expired, HSTS must meet the scanner minimum, insecure redirects must be
absent, and the final `overall_grade` must be `A` or `A+`. Generic LUCKY13 wording and
`cipherlist_OBSOLETED: offered` on Cloudflare Universal SSL are retained as
review evidence for protected staging, not automatic failures.

Because Cloudflare Access can generate the unauthenticated `302 Found`
response before traffic reaches origin Nginx, origin-side HSTS headers are not
sufficient evidence for staging. Configure the Cloudflare edge response for
`staging-sitbank.pp.ua` so the Access challenge includes
`Strict-Transport-Security` with at least the scanner minimum. Removing
Cloudflare Universal SSL obsolete CBC cipher offerings requires Advanced
Certificate Manager/custom cipher suite support; do not claim that
`cipherlist_OBSOLETED: offered` is fixed until that paid capability is enabled
and verified.

Normalization does not suppress malformed JSON generally or change policy
findings. All gates run against the strictly validated policy copy. Cloudflare
Access readiness is a separate zero-trust deployment concern and does not make
staging TLS evidence optional.

For a host-side/manual check, use the same full scan (do not use `-k` or supply
application credentials):

```bash
testssl.sh --warnings batch --color 0 --jsonfile testssl.json \
  --logfile testssl.log --htmlfile testssl.html \
  https://staging-sitbank.pp.ua
testssl.sh --warnings batch --color 0 https://sitbank.pp.ua
```

SSL Labs remains optional, manual corroborating evidence. Use its public
report when an independently rendered assessment is useful for a release,
certificate renewal, CDN/WAF change, or incident record; retain a link or
screenshot with the release evidence. Production deployment must not depend on
SSL Labs automation because public API capacity and rate limits are external to
this repository.

Before first bootstrap, issue the certificates using the approved host Certbot
DNS-01 flow with `python3-certbot-dns-cloudflare`. Production and staging use
separate Cloudflare DNS tokens stored only in root-owned host files:

- `/root/.secrets/certbot/cloudflare-production.ini`
- `/root/.secrets/certbot/cloudflare-staging.ini`

Each file must be `root:root` mode `0600` and grant only `Zone Read` and
`DNS Write` for the matching zone. Do not reuse Cloudflare Access provisioning
tokens for Certbot renewal. The bootstrap retains its certificate-file preflight and installs
`ops/deploy/verify-certbot-host-state` as
`/usr/local/sbin/verify-certbot-host-state`. Once the required files exist, it
runs the verifier before it installs or reloads Nginx; it does not attempt
certificate issuance. A failed verification is a host remediation task, not an
application deployment workaround.

The normal verifier mode is read-only. It checks `certbot`, OpenSSL, an enabled
and active `certbot.timer`, and every expected Certbot certificate and key:

| Hostname | Certificate | Private key |
| --- | --- | --- |
| `sitbank.pp.ua`, `www.sitbank.pp.ua` | `/etc/letsencrypt/live/sitbank.pp.ua/fullchain.pem` | `/etc/letsencrypt/live/sitbank.pp.ua/privkey.pem` |
| `staging-sitbank.pp.ua` | `/etc/letsencrypt/live/staging-sitbank.pp.ua/fullchain.pem` | `/etc/letsencrypt/live/staging-sitbank.pp.ua/privkey.pem` |

Each `fullchain.pem` symlink must resolve to a regular file below
`/etc/letsencrypt`. OpenSSL must parse it, expose a valid `notAfter`, and confirm
that it is neither expired nor due to expire within the minimum validity
window. `CERTBOT_MIN_VALID_DAYS` configures that window and defaults to 14
days; it must be an integer from 1 through 3650. The production leaf
certificate must contain exact DNS SANs for `sitbank.pp.ua` and
`www.sitbank.pp.ua`; the staging leaf certificate must contain an exact DNS SAN
for `staging-sitbank.pp.ua`. CN fallback and wildcard matching are
intentionally not accepted.

The `live` private-key path is normally a symlink; the resolved target must
remain below `/etc/letsencrypt`, be owned by `root`, be group-owned by `root`,
be neither group-writable nor world-writable, and grant no permissions to
other users. The normal state is `root:root` mode `0600` (or a stricter
equivalent). A `0640` dedicated TLS-read-group design is allowed only after
that group, its membership, and the Nginx privilege model are documented and
the verifier's explicit group allowlist has been reviewed and updated. Do not
use an application or container group for this purpose.

Verify the host state after issuance, after renewal changes, and before an edge
deployment:

```bash
sudo certbot certificates
sudo systemctl status certbot.timer
sudo /usr/local/sbin/verify-certbot-host-state production
sudo /usr/local/sbin/verify-certbot-host-state staging
sudo /usr/local/sbin/verify-certbot-host-state --renewal-dry-run production
sudo /usr/local/sbin/verify-certbot-host-state --renewal-dry-run staging
sudo certbot renew --dry-run --cert-name sitbank.pp.ua
sudo certbot renew --dry-run --cert-name staging-sitbank.pp.ua

sudo readlink -f /etc/letsencrypt/live/sitbank.pp.ua/privkey.pem
sudo stat -c '%U %G %a %n' "$(sudo readlink -f /etc/letsencrypt/live/sitbank.pp.ua/privkey.pem)"
sudo readlink -f /etc/letsencrypt/live/staging-sitbank.pp.ua/privkey.pem
sudo stat -c '%U %G %a %n' "$(sudo readlink -f /etc/letsencrypt/live/staging-sitbank.pp.ua/privkey.pem)"
```

When verifying directly from a reviewed checkout before bootstrap has installed
the script, use `sudo ops/deploy/verify-certbot-host-state production` or
`sudo ops/deploy/verify-certbot-host-state staging`. To use a reviewed
non-default threshold, pass it explicitly, for example
`sudo CERTBOT_MIN_VALID_DAYS=21 /usr/local/sbin/verify-certbot-host-state production`.

Normal bootstrap and deployment verification does not contact an ACME service,
so it does not claim to prove renewal readiness. The explicit
`--renewal-dry-run` mode first performs all local checks and then runs
`certbot renew --dry-run --cert-name <target-lineage>`; it may contact Let's
Encrypt's staging service.
Run it after initial issuance, changes to Certbot or ACME configuration, and
renewal failures. The target-specific check avoids making production or staging
verification depend on retired DuckDNS lineages. Do not print or copy
private-key contents while troubleshooting.

A failure is not a deployment bypass condition. Repair the path/ownership/mode,
install the certificate for the exact hostname, or renew/replace an expired or
near-expiry certificate, then rerun the verifier and `sudo nginx -t`. The live
TLS scan remains required external evidence for the chain and behavior actually
served through DNS and the deployed edge.

## Production Edge and Network Hardening

The reviewed production bootstrap installs and enables the production edge from `ops/nginx/sitbank-default.conf`, `ops/nginx/sitbank-production.conf`, `ops/nginx/sitbank-production-rate-limits.conf`, `ops/nginx-proxy-headers.conf`, and `ops/nginx/sitbank-tls-policy.conf`. `PUBLIC_BIND_ADDRESS` in root-owned `deploy.conf` must be the exact public/VPC IPv4 address assigned to Nginx; loopback, Tailscale `100.64.0.0/10`, wildcard, and malformed values fail bootstrap. During the first transition from a deploy config without this key, bootstrap derives the kernel's default-route source IPv4, validates it under the same policy, and persists it for subsequent deployments. If route lookup does not return a valid source IPv4, bootstrap fails before changing Nginx; operators with multiple egress interfaces must pass the intended address explicitly. The bootstrap renders every public port `80`/`443` listener onto that address, while Tailscale Serve owns its private HTTPS listener. The shared default config owns unknown-host rejection without wildcard public listeners. Any change to these files or `PUBLIC_BIND_ADDRESS` requires a target bootstrap after merge.

Production bootstrap also installs
`/usr/local/sbin/verify-production-nginx-boundary`. Bootstrap runs it after
Nginx reload, and every normal production deploy runs it before deployment
starts. The verifier inspects the loaded `nginx -T` state and fails closed if
the raw-IP HTTP redirect, production Authenticated Origin Pull CA/client
verification, six-month HSTS, default HTTPS rejection, or public-admin denial
is stale, if a wildcard HTTPS listener exists, or if the configured exact bind
address does not own the public listeners. Normal deploy does not repair Nginx.
This configuration requires a production bootstrap after merge. Rerun the
trusted production bootstrap, confirm Cloudflare Authenticated Origin Pull remains enabled with
sanitized provider evidence, and then retry deployment. Repository and host
checks do not by themselves prove live Cloudflare provider settings.

- Public ingress is TCP `80` and `443` only.
- GitHub deployment SSH reaches private Tailscale targets through separate
  staging and production tags. Remove public TCP `22` from the security group
  and host firewall after private deployment succeeds. OpenSSH drop-in and UFW
  automation remain deferred; treat their live posture and the provider
  firewall change as operator-owned infrastructure evidence.
- Nginx terminates TLS, redirects production customer HTTP to HTTPS, rejects
  unknown hosts with the shared default server, and forwards only expected
  proxy headers.
- The shared TLS policy enables only TLS 1.2 and TLS 1.3, restricts TLS 1.2 to
  ECDHE+AEAD suites, pins the X25519/P-256/P-384 ECDHE curve preference, and
  limits TLS 1.3 to its standard AEAD suites.
- Gunicorn binds only to `127.0.0.1:5000`.
- Admin Gunicorn binds only to `127.0.0.1:5002` and is reached only by the
  private Tailscale Serve operator path.
- `compose.prod.yml` publishes no app ports.
- `/health/ready` is for local deployment and load-balancer checks and should deny public traffic.
- No public admin Nginx server block is configured. The old public admin
  verification page is removed as part of strict Tailscale-only admin access.
  Admin app access is through Tailscale/private operator access only; do not
  enable Tailscale Funnel or expose the admin app through the customer host.
- Cloudflare or AWS WAF should sit in front of Nginx for managed common, SQL injection, XSS, bot, and protocol anomaly rules.
- Cloudflare or AWS WAF rules and security-group allowlists are still infrastructure state and must be checked manually.
- Flask admin auth supports manual root-admin bootstrap plus
  root-admin-controlled staff invite onboarding with mandatory password and
  TOTP login, separate admin sessions, and no password-only administrator
  login.

Verification:

```bash
sudo sshd -t
sudo ufw status numbered verbose
sudo test -r /etc/letsencrypt/live/sitbank.pp.ua/fullchain.pem
sudo /usr/local/sbin/verify-certbot-host-state production
sudo nginx -t
sudo nginx -T | grep -E 'ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_conf_command|ssl_session_tickets'
sudo ss -ltnp | grep -E ':(80|443|5000|5002)([[:space:]]|$)'
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-app
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-admin
curl --fail -H 'Host: sitbank.pp.ua' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-Proto: https' \
  http://127.0.0.1:5000/health/ready
curl --fail -H 'Host: sitbank-admin.internal' -H 'X-Forwarded-Proto: https' \
  http://127.0.0.1:5002/health/ready
curl --fail https://sitbank.pp.ua/health/live
curl -I https://sitbank.pp.ua/health/ready
```

Expected: local customer and admin readiness succeeds through loopback, external
customer `/health/ready` does not return application readiness, and no public
admin hostname is required. The deployment wrapper uses the loopback readiness
checks; production public TLS verification remains a separate protected
post-deploy gate.

GitHub-hosted runners do not have stable source IPs. The normal
GitHub-hosted SSH deployment is acceptable only when the runner source is
allowlisted by a reviewed path such as a self-hosted runner, bastion, VPN
egress, or a time-boxed operator-approved maintenance window. Do not leave
global SSH open to support deployment.

Staging admin must follow the same boundary pattern as production. Do not expose
admin routes publicly. The staging admin service must bind only to localhost
and use a separate loopback port from production admin when both environments
share one EC2 host. Production admin owns `127.0.0.1:5002`; staging admin owns
`127.0.0.1:5003`. Operators use Tailscale VPN before opening the private
production admin URL `https://admin-sitbank.tailca101b.ts.net/`; staging admin
must use the same private-network pattern through an approved tailnet path. Do
not enable Tailscale Funnel and do not add a public staging admin Nginx server
block. Staging admin secrets must be root-managed under
`/etc/sitbank-staging/secrets`. Admin Flask, session, password-pepper, and
database secrets must not reuse customer runtime secrets; only the
environment-specific Turnstile server credential is shared because both
runtimes enforce their configured public-auth challenges.

## Staging Edge Setup

Staging uses Cloudflare Access as the identity-aware boundary and Cloudflare
Authenticated Origin Pulls to prevent direct EC2-origin bypass. The staging
Nginx app paths require a verified Cloudflare origin-pull client certificate
before proxying to Flask. The production customer hostname remains public.

Provider-side desired state is repository-managed by
`ops/cloudflare/provision-staging-access` using the Cloudflare-managed hostname
model. From an operator shell with the variables documented in
`docs/security/architecture/cloudflare-staging-access.md`, review and apply it before
staging bootstrap:

```bash
python ops/cloudflare/provision-staging-access --plan
python ops/cloudflare/provision-staging-access --apply \
  --confirm APPLY-STAGING-ACCESS
```

Plan is offline and does not require a token. Apply needs a token limited to
Account `Access: Apps and Policies Write` and Zone `DNS Write`; it refuses a
broad or unmanaged Allow policy. The Access IdP, Authenticated Origin Pull
enablement/client certificate, origin CA file, AWS ingress rules, and operator
membership remain deliberate operator controls.

Copy the apply output into protected GitHub `staging` environment variables
`STAGING_CLOUDFLARE_ACCESS_AUD` and
`STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN`. Staging deployment refuses to render
without both. Its signed runtime bundle enables
`STAGING_CLOUDFLARE_ACCESS_JWT_REQUIRED=true`; production does not.
Set `STAGING_ACCESS_SESSION_DURATION=6h` in that environment so provider plan,
apply, and verification all use the six-hour duration configured for the
`SITBank staging` Access application. Keep the exact explicit-email policy in
`STAGING_ACCESS_ALLOWED_EMAILS`; `Everyone`, wildcard domains, and broad
allow-all rules are forbidden.

Nginx shared-password authentication has been removed from staging. Cloudflare
Access is the identity-aware entry boundary, and the Flask login/MFA, CSRF,
session, authorization, rate-limit, and audit controls remain in force. Do not
reintroduce a shared staging password as a fallback.

Install the Cloudflare Authenticated Origin Pull CA certificate on the EC2
host before running staging bootstrap:

```bash
sudo install -o root -g root -m 0644 \
  cloudflare-authenticated-origin-pull-ca.pem \
  /etc/nginx/cloudflare-authenticated-origin-pull-ca.pem
```

The staging bootstrap installs
`/usr/local/sbin/verify-cloudflare-origin-pull-ca` and the reviewed fingerprint
allowlist at
`/etc/sitbank-staging/cloudflare-origin-pull-ca-allowlist.json`. Before it
installs or enables the staging Nginx site, it requires the CA path to be a
root-owned regular non-symlink, permits only `root` or `www-data` as the group
with an approved non-writable mode, parses exactly one currently valid CA with
OpenSSL, and matches its SHA-256 fingerprint, subject, and issuer to the
allowlist. The bootstrap does not download a CA or call the Cloudflare API.
Before replacing the old staging edge config, it also requires the public
hostname to return a Cloudflare Access challenge. This fail-closed preflight
prevents the removal of an older edge control while Access is absent.

The repository allowlist initially approves only Cloudflare's global
Authenticated Origin Pull CA. A change to a zone-level or per-hostname CA must
first add its independently reviewed fingerprint and exact OpenSSL
subject/issuer in a separate reviewed commit. For a CA rotation:

1. Obtain the announced replacement from Cloudflare's official documentation
   in a controlled operator session, outside bootstrap.
2. Inspect it with `openssl x509 -noout -subject -issuer -fingerprint -sha256
   -startdate -enddate -ext basicConstraints`.
3. Independently confirm the source, `CA:TRUE`, validity, subject, issuer, and
   fingerprint; then add the new entry alongside the old entry.
4. Deploy the new CA and run the verifier and `nginx -t`. Remove the old entry
   only after every staging origin has completed the rotation.

Do not store Cloudflare API tokens, tunnel credentials, Access IdP secrets, or
origin certificate private keys in the repo. If the staging hostname cannot be
proxied by Cloudflare in the current DNS model, stop and make an approved DNS
change instead of disabling the origin-pull protection.
`staging-sitbank.pp.ua` is the Cloudflare-managed staging hostname for Access.
Use a Cloudflare-managed zone/hostname or Cloudflare Tunnel for this boundary;
for this deployment, the approved Cloudflare-managed hostname is
`staging-sitbank.pp.ua`. The retired DuckDNS staging hostname is not an active
staging deployment, Nginx, Certbot, or TLS-scan target. The staging domain and
CI/CD migration are complete. Cloudflare Access and origin-protection
automation are implemented separately from live operator verification.

Issue or renew staging TLS with DNS-01 before bootstrap:

```bash
sudo certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /root/.secrets/certbot/cloudflare-staging.ini \
  --cert-name staging-sitbank.pp.ua \
  -d staging-sitbank.pp.ua
sudo systemctl status certbot.timer
sudo /usr/local/sbin/verify-certbot-host-state staging
sudo /usr/local/sbin/verify-certbot-host-state --renewal-dry-run staging
```

Then run `ops/deploy/bootstrap-container-ec2 staging Koon-Kiat/SITBank staging-sitbank.pp.ua`. The protected bootstrap workflow first verifies the live Access application, policy, proxied DNS, edge challenge, and direct-origin denial. The host bootstrap independently requires the edge challenge before it installs the Nginx proxy header snippet, TLS policy snippet, rate-limit include, and staging Nginx server block; verifies the pinned Cloudflare origin-pull CA; then runs `sudo nginx -t` before `sudo systemctl reload nginx`. This edge setup is separate from application deployment.

The root deployment wrapper repeats the edge challenge plus loopback
direct-origin denial before stopping the old runtime. After the new
containers start, deployment readiness requires an exact HTTP `200` and the
expected ready JSON through `http://127.0.0.1:8081/health/ready`. It never uses
the intentionally blocked public staging `/health/ready`, never follows a
redirect as readiness, and the local Nginx location forces the trusted
forwarded scheme to `https`.

Staging verification:

```bash
python ops/cloudflare/provision-staging-access --verify \
  --evidence-file cloudflare-access-evidence.local.json
sudo /usr/local/sbin/verify-cloudflare-origin-pull-ca
curl -I https://staging-sitbank.pp.ua/
curl -I https://staging-sitbank.pp.ua/health/ready
curl -fsS http://127.0.0.1:5001/health/ready
curl -fsS http://127.0.0.1:8081/health/ready
curl -I --resolve staging-sitbank.pp.ua:443:<EC2_PUBLIC_IP> \
  https://staging-sitbank.pp.ua/
curl -I http://127.0.0.1:5001/
curl --fail http://127.0.0.1:5001/health/ready
sudo nginx -T | grep -E 'ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_conf_command|ssl_session_tickets'
curl -fsSI https://staging-sitbank.pp.ua/ | grep -i '^strict-transport-security:'
testssl.sh --warnings batch --color 0 https://staging-sitbank.pp.ua
```

Expected: unauthenticated browser traffic receives the Cloudflare Access
challenge at `staging-sitbank.pp.ua` before reaching staging, approved operators can pass Cloudflare
Access and then reach the normal staging controls, direct EC2-origin access to
`/` is rejected during TLS client-certificate verification, rejected at the
connection layer, or returns the approved Nginx `400`/`403` denial without
Cloudflare's origin-pull certificate,
direct loopback Flask access to `/` returns `403` without an Access assertion,
external `/health/ready` is unavailable, local app and Nginx readiness
succeed, and the
retired DuckDNS staging hostname is no longer an active Nginx target.

The script also verifies the live Access application and approved-operator
policy, proxied DNS state, application audience, edge challenge, and direct
origin denial. Flask consumes its printed
`STAGING_CLOUDFLARE_ACCESS_AUD` and
`STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN` values to validate the assertion's
signature, issuer, audience, expiry, and optional not-before time. A
missing/invalid assertion always receives a generic `403`; raw tokens are not
logged. Authenticated Origin Pull remains a separate required check.
The manual `cloudflare-access-verify.yml` workflow performs the same
non-mutating check in the protected `staging` environment and uploads only
sanitized evidence. It maps `STAGING_ACCESS_SESSION_DURATION`,
`STAGING_CLOUDFLARE_ACCESS_AUD`, and every other supported provider value
explicitly, runs only when dispatched from `main`, and reports non-secret
field drift without printing the email allowlist or raw provider responses.

The complete operator runbook is
`docs/security/architecture/admin-and-staging-zero-trust-access.md`.

After the staging TLS check passes, validate production customer HTTPS with
`testssl.sh --warnings batch --color 0 https://sitbank.pp.ua` and verify that
`https://www.sitbank.pp.ua` redirects to the canonical host. The
`ssl_conf_command` TLS 1.3 setting is runtime-dependent, so `nginx -t` must
pass on the deployed host before any reload. Do not add the private Tailscale
admin URL to public GitHub-hosted TLS scans. Private reachability belongs only
to the separate manual, protected tailnet verification workflow; the public
TLS scan and deployment workflows must never require `TS_OAUTH_CLIENT_ID` or
`TS_OAUTH_SECRET`.

Production HSTS validation should also confirm the public customer hostname
returns the production edge header before the production live TLS scan is
accepted:

```bash
curl -fsSI https://sitbank.pp.ua/ | grep -i '^strict-transport-security:'
curl -fsSI https://www.sitbank.pp.ua/ | grep -i '^location: https://sitbank.pp.ua'
```

Production Nginx and the reviewed Cloudflare edge both use six-month HSTS:
`max-age=15552000; includeSubDomains`, with preload disabled. Production
bootstrap requires the separately installed
`/etc/nginx/sitbank-production-cloudflare-origin-pull-ca.pem`, verifies it
against `/etc/sitbank/cloudflare-origin-pull-ca-allowlist.json`, and fails
closed before `nginx -t` or reload. This production path is separate from the
staging CA path.

After bootstrap, verify raw HTTP origin-IP access redirects to
`https://sitbank.pp.ua`, while raw HTTPS IP and direct-origin HTTPS with
`sitbank.pp.ua` SNI do not return application content without Cloudflare's
client certificate. Keep Cloudflare DNS proxied and `Full (strict)`, and
restrict AWS `443/tcp` to Cloudflare edge ranges where practical. Provider and
security-group state require sanitized operator evidence; repository files do
not prove them. See
`docs/security/architecture/production-cloudflare-origin-boundary.md`.

The `pp.ua` DNS-01 migration and DuckDNS retirement are complete. Ongoing
certificate renewal, origin-boundary, and live verification instructions stay
in this deployment guide and `docs/OPERATIONS.md`; do not restore retired
DuckDNS names as active Nginx, Certbot, workflow, or TLS-scan targets.

The private Grafana/Loki deployment is separate from the banking application
runtime. Initial host preparation installs the restricted
`sitbank-observability-bootstrap` wrapper. Subsequent changes use the
main-only, protected `Bootstrap private observability on EC2` workflow, which
uploads a signed trusted-source archive over its narrowly tagged Tailscale SSH
path and invokes only that wrapper. Use
`ops/deploy/bootstrap-observability-ec2` only through the wrapper and
`docs/runbooks/private-observability-grafana-loki.md`; do not add Grafana,
Loki, or Alloy routes to public Nginx or the Flask admin app.

The `observability-staging` and `observability-production` environments must
store bootstrap-only
`OBSERVABILITY_BOOTSTRAP_TS_OAUTH_CLIENT_ID` and
`OBSERVABILITY_BOOTSTRAP_TS_OAUTH_SECRET` values. Their OAuth client may
advertise only `tag:github-ci-observability-bootstrap` and must not be reused
for observability verification or private-admin verification. Apply and review
the reference grant
`tag:github-ci-observability-bootstrap -> tag:sitbank-observability-ec2:22`
without adding Grafana HTTPS, wildcard, Internet, or Tailscale SSH access.
Repository configuration cannot prove the live ACL, tag ownership, environment
secrets, host firewall, security group, or provider state; verify those
boundaries separately with sanitized evidence.
