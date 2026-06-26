# Operations

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

MFA/TOTP seed encryption uses envelope encryption. Keep old KEKs in `mfa_kek_keys_json` until `rewrap-mfa-deks` has moved stored records to the new active KEK. Then update `MFA_KEK_ACTIVE_ID` and the root-managed keyring together.

## Trivy Exception

The temporary `.trivyignore` exception covers only `CVE-2026-42496` and `CVE-2026-8376` inherited from the official python:3.12 slim-trixie / Debian Trixie base image.

The app does not install Perl directly, does not invoke Perl, and does not process attacker-controlled tar archives with Perl. Debian marks `perl-base` as `Essential: yes`, so it must not be removed. Also, mixing Debian sid packages into Trixie is riskier than keeping the inherited package while monitoring for the fixed official base digest.

This exception is temporary with a review/remove-by date: 2026-06-26. The full Critical Trivy report with no ignore file and the fixable High/Critical gate must continue to run without hiding unrelated findings.

## Rollback

Application rollback restores the previous signed image digest and runtime bundle. Database rollback requires an explicit backup/restore decision because Alembic migrations must remain backward-compatible and are not automatically reversed.

## Audit Operations

Retain `security_audit_events` for 7 years. The application must not auto-delete
audit rows; disposal after retention requires an operator-approved maintenance
record and a retained summary of the affected date range.

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

The current banking implementation audits public transaction validation and
TOTP-backed transaction authorization checks. There is no final ledger movement
endpoint in this codebase, so final transfer execution is intentionally out of
scope until such an endpoint exists.

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
