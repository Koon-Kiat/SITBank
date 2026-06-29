# Operations

Security owner roles, milestone/release review cadence, accepted-risk handling,
and off-repo evidence expectations are defined in
`docs/security/security-governance.md`.

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
`docs/security/sonarqube.md`.

GitHub Actions repository variables are non-secret configuration. The CI
workflow treats an unset `ENABLE_GITHUB_CODE_SECURITY` as `false` and uses the
reviewed public-host fallbacks `staging-sitbank.pp.ua` and
`sitbank.duckdns.org` when `STAGING_PUBLIC_HOST` or `PROD_PUBLIC_HOST` is
unset. Configure overrides under Actions variables only after the matching
DNS, certificate, and edge change is reviewed. The complete variable table and
secret-placement boundary are in `docs/DEPLOYMENT.md`; never copy credentials
or application secrets into repository variables.

MFA/TOTP seed encryption uses envelope encryption. Keep old KEKs in `mfa_kek_keys_json` until `rewrap-mfa-deks` has moved stored records to the new active KEK. Then update `MFA_KEK_ACTIVE_ID` and the root-managed keyring together.

## Disposable Registration Data Reset

If a development, staging, or demo database contains only seeded/test users from
before the registration-field migration, prefer an explicit reset/recreate over
preserving fake contact data. Confirm the target environment, confirm there are
no real users, take any required backup, then run the normal bootstrap or
deployment migration path for that environment. Production-like databases must
not be reset by scripts or deployment automation without a separate approved
maintenance record.

## Admin And Staging Access Operations

SITBank uses a hybrid private-access model:

- Staging is protected by Cloudflare Access and Cloudflare Authenticated Origin
  Pulls at `staging-sitbank.pp.ua`.
- Admin is protected by Tailscale/private operator access at
  `https://admin-sitbank.tailca101b.ts.net/`.
- The production customer site `sitbank.duckdns.org` remains public.

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
curl -I http://127.0.0.1:5001/
curl --fail http://127.0.0.1:5001/health/ready
sudo /usr/local/sbin/verify-cloudflare-origin-pull-ca
sudo nginx -t
curl --fail --resolve staging-sitbank.pp.ua:443:127.0.0.1 \
  https://staging-sitbank.pp.ua/health/ready
curl -I --resolve staging-sitbank.pp.ua:443:<EC2_PUBLIC_IP> \
  https://staging-sitbank.pp.ua/
sudo tailscale set --hostname=admin-sitbank
sudo tailscale serve status
curl -I https://admin-sitbank.tailca101b.ts.net/login
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
local staging readiness succeeds without one, direct Nginx origin access
returns `403` without Cloudflare's origin-pull client certificate, and the
private admin URL is reachable only from an approved tailnet path. Tailscale
Funnel must stay disabled for SITBank admin.
Tailscale is the private network/device boundary for admin access; it does not
replace Flask admin login, TOTP, CSRF protection, route authorization, or audit
logging.
The Tailscale admin host preflight and private admin boundary are implemented
repository controls; live provisioning plus ACL, device, and Serve state still
require operator verification.

Production bootstrap installs the read-only host preflight at
`/usr/local/sbin/verify-tailscale-admin-access`. Run it directly on EC2 after
deployment and whenever the admin listener, Nginx, Tailscale daemon, Serve
mapping, Funnel state, private hostname, or certificate changes:

```bash
sudo /usr/local/sbin/verify-tailscale-admin-access --mode serve
```

Expected output is one `OK:` line for each of these assertions: Tailscale is
running; Funnel is disabled; port `5002` listens only on `127.0.0.1`; local
admin readiness returns `200`; Nginx has no admin upstream or private
Tailscale hostname; Serve exposes only
`admin-sitbank.tailca101b.ts.net:443` to
`http://127.0.0.1:5002`; and the private `/login` URL returns `200`. Any
`ERROR:` line and nonzero exit is a failed preflight. Investigate the named
control; do not enable Funnel, broaden the listener, or add an Nginx admin
route to make the check pass.

The reviewed defaults can be overridden with
`ADMIN_LOOPBACK_HOST`, `ADMIN_LOOPBACK_PORT`, and `PRIVATE_ADMIN_HOST`, or
their matching command-line flags. Values are strictly validated. Change a
default only with the Compose, Tailscale, documentation, and tests in the same
review; there is intentionally no public-admin-host setting.

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

The **Verify private Tailscale admin access** workflow is the only
GitHub-hosted workflow approved to join the tailnet. It can run manually and is
the required final production gate after deployment and public production TLS
verification. It uses the protected `admin-tailscale` environment and its
`TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET` environment secrets. The
environment must require manual approval by trusted maintainers and restrict
deployment branches to `main`. The OAuth client must have **Keys > Auth Keys >
Write** permission and be restricted to `tag:github-ci`; that tag may access
only `tag:admin-sitbank:443` and must not administer the tailnet or provide
broad SSH access.

Run the workflow after private DNS, certificates, Tailscale ACLs/tags, Serve
configuration, or the admin edge changes. It first confirms the private URL is
unreachable before joining, then requires
`https://admin-sitbank.tailca101b.ts.net/login` to return the documented
unauthenticated `200` response. The job uses no admin login credentials, makes
no deployment or provider configuration changes, enables neither Tailscale
Funnel nor Serve, uploads no Tailscale state, and logs out at completion.
Flask admin login, TOTP, CSRF, route authorization, audit logging, and
admin/customer isolation still apply.

For credential rotation, create a replacement OAuth client with the same
narrow scope and tag; update both protected environment secrets; approve and
verify one `main` run; then revoke the old client and remove stale CI nodes.
During maintainer offboarding, also review environment approvers and branch
rules. To remove CI tailnet access entirely, delete both environment secrets,
revoke the OAuth client, remove the dedicated CI tag grants/devices, and
disable or delete the environment. The full runbook is in
`docs/security/admin-and-staging-zero-trust-access.md`.

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

The detailed onboarding, offboarding, emergency lockout, rollback, and live
operator verification steps are in
`docs/security/admin-and-staging-zero-trust-access.md`.
Provider automation and origin assertion details are in
`docs/security/cloudflare-staging-access.md`.

## Root Admin Bootstrap

Root admins remain a fixed allowlisted group. `ROOT_ADMIN_EMAILS` must contain
exactly 7 approved SIT workplace email addresses before any database user can
become `root_admin`; normal customer registration and staff invites must not
create `root_admin` accounts. Configure `ROOT_ADMIN_EMAILS` as a protected
GitHub environment variable in both `staging` and `production` before deploying
this command. Do not commit the allowlist to the repository.

After deployment, verify the admin container received the allowlist:

```bash
sudo docker exec sitbank-admin printenv ROOT_ADMIN_EMAILS
```

The output must be the configured comma-separated 7-email allowlist before you
run bootstrap.

When no usable root admin exists, run the shell-only bootstrap command from the
already deployed private admin container:

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
and provisioning URI. Add it to an authenticator app immediately. Do not paste
that output into logs, tickets, chat, shell history, or committed files. The
bootstrap stores only the protected password hash and envelope-encrypted TOTP
secret, sets the account active, marks the workplace email verified, and records
a safe `root_admin_bootstrap` audit event without the password or TOTP secret.
After bootstrap, open `https://admin-sitbank.tailca101b.ts.net/login` from an
approved tailnet device and use that workplace email, password, and TOTP code to
enter the private dashboard.

## EC2 SSH And Deployment Access Operations

EC2 SSH hardening is deferred and is not implemented by this branch.
There is no repository OpenSSH drop-in, UFW rollout, security-group migration,
or deployment-source allowlisting runbook to apply from this checkout.

Keep the existing approved deployment path in place until a separate reviewed
change designs and tests the EC2 host, AWS security-group, GitHub Actions, and
rollback impact together. Do not claim root SSH, password SSH, `AllowUsers`,
UFW, or TCP `22` ingress has been hardened from repository evidence alone.

## Trivy Exception

The temporary `.trivyignore` exception covers only `CVE-2026-42496` and `CVE-2026-8376` inherited from the official python:3.12 slim-trixie / Debian Trixie base image.

The app does not install Perl directly, does not invoke Perl, and does not process attacker-controlled tar archives with Perl. Debian marks `perl-base` as `Essential: yes`, so it must not be removed. Also, mixing Debian sid packages into Trixie is riskier than keeping the inherited package while monitoring for the fixed official base digest.

This exception is temporary with a review/remove-by date: 2026-06-26. The full Critical Trivy report with no ignore file and the fixable High/Critical gate must continue to run without hiding unrelated findings.

## Rollback

Application rollback restores the previous signed image digest and runtime bundle. Database rollback requires an explicit backup/restore decision because Alembic migrations must remain backward-compatible and are not automatically reversed.

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
permissions, host-only age identity, and production confirmation. Do not run a
production restore during normal verification. Do not commit `.dump`, `.sql`,
`.backup`, `.pgdump`, decrypted dumps, age identity files, GPG private keys, or
database credentials.

## Audit Operations

Retain `security_audit_events` for 7 years. The application must not auto-delete
audit rows; disposal after retention requires an operator-approved maintenance
record and a retained summary of the affected date range.
The implementation-focused audit and alert reference is
`docs/security/audit-and-alerting.md`; current open security gaps are tracked in
`docs/security/security-gap-register.md`.
Privacy, retention, deactivation, and incident response procedures are in
`docs/security/privacy-and-pdpa.md`,
`docs/security/data-retention-and-deactivation.md`, and
`docs/security/incident-response.md`.

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

Export a sanitized anchor at least daily and after security-sensitive releases:

```bash
python -m flask --app wsgi:app export-audit-log-anchor
python -m flask --app wsgi:app export-audit-log-anchor --output /var/lib/sitbank/security-audit.anchor
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
configured anchor automatically and fail or alert when it is unreadable or does
not match the current chain head.

On an anchor mismatch, stop rotating anchors, preserve the current database and
the mismatched anchor as incident evidence, run
`python -m flask --app wsgi:app verify-audit-log-chain --anchor /var/lib/sitbank/security-audit.anchor`,
and investigate possible row tampering, chain rewind, or tail deletion before
resuming routine deployments.

The current banking implementation audits public transaction validation,
TOTP-backed transaction authorization checks, and local transfer execution.
Local transfer performs final ledger movement: the sender balance is debited,
the recipient balance is credited, and a `Transaction` record is created in a
single atomic commit. The two-step transfer flow requires MFA step-up before a
DB-backed `PendingTransfer` record is created; the single-use confirmation token
is consumed atomically with `SELECT FOR UPDATE` to prevent concurrent
double-submit replay. Row locks are acquired in ascending `id` order to prevent
deadlocks. Payee ownership and cooldown are enforced at the service layer
independently of the route layer. Transfer amounts are validated to at most two
decimal places. Recipient account state is checked before funds move.
Blocked authorization failures, including payee ownership mismatches, are
audited safely using opaque references so raw account numbers, payee details,
and pending transfer tokens do not appear in the audit log.

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
tampering, rewind, or tail deletion detectable from the anchor.

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

It fails closed unless Certbot and OpenSSL are installed, `certbot.timer` is
installed, enabled, and active, and each expected `fullchain.pem` and
`privkey.pem` resolves below `/etc/letsencrypt`. It parses each leaf
certificate, requires a valid `notAfter`, more than 14 days of remaining
validity by default, and an exact DNS SAN for the expected hostname. It does
not accept CN fallback or wildcard substitution. It also requires each
resolved private key to use the approved root ownership/group and denies group
write or any permissions for other users. Override the validity window only
with a reviewed positive value such as
`sudo CERTBOT_MIN_VALID_DAYS=21 /usr/local/sbin/verify-certbot-host-state production`.

Normal verification is local and does not prove that ACME renewal can complete.
After certificate issuance or changes to Certbot/ACME configuration, run the
explicit network-dependent readiness check:

```bash
sudo /usr/local/sbin/verify-certbot-host-state --renewal-dry-run production
```

That mode performs the same local checks before invoking
`certbot renew --dry-run`. On any failure, repair or renew the affected
certificate and rerun the check; do not bypass it or expose private-key
contents. Finally run `sudo nginx -t` before reload.

## Live TLS Evidence Operations

The **Live TLS scan evidence** workflow provides scheduled weekly,
operator-dispatched, and post-deployment evidence of the Internet-facing TLS
posture for `staging-sitbank.pp.ua` and `sitbank.duckdns.org`. The deployment
workflow calls the staging scan
after staging deploy and blocks production deployment until it passes; it calls
the production scan after production deploy, then calls the required protected
private-admin tailnet gate only after that public scan succeeds.
The manual workflow input `staging_host` defaults to
`staging-sitbank.pp.ua`.
Dispatch it after edge, certificate, DNS, Nginx/OpenSSL, CDN/WAF, or
load-balancer changes outside deployment, then retain the successful run with
the release or change record. Do not run a public-endpoint scan from ordinary
pull requests.

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
be not offered, TLS 1.2 and TLS 1.3 to be offered, certificate
hostname/trust and chain checks to be OK, the certificate to be unexpired,
HSTS to meet the scanner minimum, no insecure redirect finding, and a final
`overall_grade` of `A` or `A+`. Generic LUCKY13 wording and
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
- `PASSWORD_RESET_BASE_URL=https://sitbank.duckdns.org`
- `PASSWORD_RESET_EMAIL_FROM=<approved sender>`
- `SMTP_HOST=<approved provider host>`
- `SMTP_USE_TLS=true`
- `SMTP_USERNAME_FILE=/run/secrets/smtp_username`
- `SMTP_PASSWORD_FILE=/run/secrets/smtp_password`

Password policy in production:

- `PASSWORD_MIN_LENGTH` defaults to `15` when `APP_ENV=production`.
- Development and test may keep the explicit shorter default for local workflows.
- `production-check` and the production startup guard fail closed if a production
  app is configured below `15`.
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

- Root admins review requests in the admin app with
  `GET /manual-recovery/requests`.
- Root admins move a request through `under_review`, `approved`, or `denied`
  using `POST /manual-recovery/requests/<id>/transition` with an operator
  reason and fresh TOTP code.
- Completion uses `POST /manual-recovery/requests/<id>/complete` after
  approval, again with an operator reason and fresh TOTP code.
- Completion forces customer MFA re-enrollment, revokes active customer
  sessions, sends the existing manual recovery completion notification, and
  records `manual_recovery_completed` plus admin actor audit events.
- Public account-recovery submission never unlocks, mutates, or completes an
  account by itself.

## SIT Email OTP Registration Operations

Customer self-registration is limited to exact normalized SIT email domains:

- `sit.singaporetech.edu.sg`
- `singaporetech.edu.sg`

Registration no longer uses invite links or invite CLI commands. Customers
request a six-digit registration verification code from `/register`, receive it
by email, verify it in the same browser session, and then complete account
creation with the same normalized email address. Codes expire after 5 minutes,
are one-time use, and requesting a new code invalidates the previous code. The
application stores only an HMAC of the code in PostgreSQL; raw codes must never
be recorded in runbooks, tickets, logs, Discord, Telegram, or screenshots.

Registration OTP delivery uses the same security email backend and SMTP
settings as password reset email:

- `PASSWORD_RESET_EMAIL_BACKEND=smtp`
- `PASSWORD_RESET_EMAIL_FROM=<approved sender>`
- `PASSWORD_RESET_BASE_URL=https://sitbank.duckdns.org`
- `SMTP_HOST=<approved provider host>`
- `SMTP_USE_TLS=true`
- `SMTP_USERNAME_FILE=/run/secrets/smtp_username`
- `SMTP_PASSWORD_FILE=/run/secrets/smtp_password`

Operational checks:

- Verify SMTP settings with a controlled staging registration using a test SIT
  email address.
- Investigate `registration_otp` audit events by outcome
  (`requested`, `verified`, `failed`, `expired`, or `locked`) without expecting
  raw email addresses or codes in event metadata.
- If registration email delivery fails, the request fails closed and the
  PostgreSQL OTP challenge row is deleted.
- Existing-account requests intentionally return the same generic response as
  eligible requests; do not treat the absence of an outgoing email as customer
  proof without independent identity checks.
