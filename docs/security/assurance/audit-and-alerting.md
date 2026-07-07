# Audit And Alerting

This document describes the current SITBank audit logging and security alerting
implementation. It is implementation evidence, not a future design note.
Personal-data handling, retention/deactivation, and incident workflows are
documented in `docs/security/governance/privacy-and-pdpa.md`,
`docs/security/governance/data-retention-and-deactivation.md`, and
`docs/security/governance/incident-response.md`.

Category: [Security assurance](../README.md#assurance).

## Purpose

Audit logging records security-relevant actions with enough context for
incident review while avoiding secrets and raw identifiers. Alerting evaluates
recent audit events and runtime signals for patterns that need operator
attention.

Primary implementation files:

| Area | Evidence |
| --- | --- |
| Audit write, metadata sanitization, hash chain, anchor export | `app/security/audit.py` |
| Alert rules, severity, dedupe, delivery sanitization | `app/security/alerts.py` |
| CLI commands | `app/ops/commands.py` |
| Audit model | `app/models.py::SecurityAuditEvent` |
| Append-only database controls | `migrations/versions/20260618_0003_audit_append_only_triggers.py`, `migrations/versions/20260618_0004_audit_truncate_trigger.py`, `app/ops/db_privileges.py` |

## Audited Events

SITBank records events across customer, admin, banking, and operational flows.
Representative event families include:

| Event family | Examples | Evidence |
| --- | --- | --- |
| Authentication | `login_password`, `login`, `mfa_login_verify`, `admin_login_password`, `admin_mfa_login`, `logout` | `app/auth/services.py`, `app/admin/services.py` |
| MFA lifecycle | `mfa_setup_generate`, `mfa_setup_verify`, `mfa_replace_start`, `mfa_replace_verify`, `mfa_recovery_code_verify`, `recovery_codes_regenerate` | `app/auth/services.py`, `app/auth/recovery_codes.py` |
| Password reset and manual recovery | `password_reset_requested`, `password_reset_token_exchanged`, `password_reset_mfa_failed`, `password_reset_completed`, `manual_recovery_requested`, `manual_recovery_admin_transition`, `manual_recovery_completed` | `app/auth/password_reset.py`, `app/admin/services.py` |
| Session management | `session_terminate`, protected backend `session_revoke_others`, `session_integrity`, `session_expired`, `session_risk` | `app/auth/services.py`, `app/security/sessions.py` |
| Account security | `password_change`, account detail updates, `account_freeze` | `app/auth/services.py` |
| Admin and staff operations | `admin_dashboard_access`, `staff_invite_create`, `staff_invite_revoked`, `staff_invite_accept`, `staff_invite_accept_reset`, `staff_account_activated`, `staff_account_deactivated`, `staff_account_reactivated`, `staff_activation_reset`, `audit_log_view`, `security_alert_review`, `security_alert_delivery`, `admin_access_denied` | `app/admin/services.py`, `app/admin/routes.py` |
| Banking and payees | `payee_lookup`, `payee_add`, `payee_remove`, transaction validation events | `app/banking/routes.py`, `app/banking/services.py` |
| Operations | `mfa_dek_rewrap`, audit chain verification/export, alert checks | `app/ops/commands.py`, `app/security/audit.py`, `app/security/alerts.py` |

Some actions use `audit_event_required()` so a missing audit row fails the
security-sensitive action rather than silently continuing.

## Metadata Rules

Audit metadata is sanitized before persistence and before structured log
output. Sensitive keys and sensitive-looking values are redacted recursively in
dicts and lists. Raw identifiers are represented with HMAC-derived references
through `audit_reference()` and `principal_reference()`.

Banking and payee audit calls must avoid raw account identifiers and
customer-controlled free text at the call site. Use fields such as
`payee_account_ref`, `transaction_ref`, boolean presence flags, counts, and
bounded lengths so investigation correlation remains possible without storing
raw account numbers, payee nicknames, or transfer reference text in the audit
row.

Do not log or paste these values into audit metadata, application logs, alert
payloads, tickets, or chat:

- passwords and password confirmation values
- TOTP codes
- recovery codes
- raw session IDs, cookies, and signed session payloads
- CSRF tokens
- password reset selectors, verifiers, and full reset URLs
- MFA secrets, nonces, ciphertext, and KEK material
- HMAC keys, Flask/CSRF secrets, database passwords, API tokens, webhook URLs,
  and private keys
- raw credential payloads or full request bodies containing secrets

Relevant tests:

| Test | Coverage |
| --- | --- |
| `tests/test_audit_metadata_sanitization.py` | Redacts nested metadata, URLs, tokens, session data, webhook URLs, and long sensitive values |
| `tests/test_audit_alerting.py::test_structured_audit_log_output_is_sanitized` | Structured audit logs are safe for log forwarding |
| `tests/test_password_reset.py` reset-token tests | Password reset tokens and recovery codes are not stored or logged raw |
| `tests/test_payee_management_security.py::test_invalid_payee_lookup_is_generic_and_audited` | Payee lookup failures audit only safe account references |
| `tests/test_payee_management_security.py::test_payee_add_and_remove_audit_metadata_uses_safe_references` | Payee add/remove events store safe account references and bounded nickname metadata |

## Audit Integrity

Each `SecurityAuditEvent` participates in an HMAC-SHA256 hash chain:

- `previous_event_hash` links to the prior event.
- `event_hash` covers canonical audit fields.
- `hash_algorithm` identifies the active hash format.
- `SECURITY_AUDIT_HMAC_KEY` is a production secret and is not stored in the
  database.

Operators verify and anchor the chain with:

```bash
python -m flask --app wsgi:app verify-audit-log-chain
python -m flask --app wsgi:app verify-audit-log-chain --anchor /var/lib/sitbank/security-audit.anchor
python -m flask --app wsgi:app export-audit-log-anchor --output /var/lib/sitbank/security-audit.anchor
python -m flask --app wsgi:app refresh-audit-log-anchor
```

`SECURITY_AUDIT_ANCHOR_PATH` points production checks and alerting at the
host-protected anchor. Verification reports separate anchor freshness from
hash-chain integrity:

- `anchor_validated=true` means the saved anchor exactly matches the current
  chain head.
- `anchor_stale=true` with `anchor_refresh_required=true` means the chain is
  valid, the saved anchor event still exists with the same event hash, and
  normal append-only audit rows were written after the anchor. This state
  includes `anchor_event_id`, `latest_event_id`, and `events_since_anchor`; it
  does not emit a critical `audit_anchor_mismatch` alert.
- `audit_anchor_mismatch` remains critical for unreadable or malformed anchors,
  anchor rollback, current chain behind the anchor, missing anchored rows, or
  anchored event hash changes.
- `audit_chain_verification_failed` remains critical for hash-chain failures
  such as `event_hash_mismatch`, `previous_hash_mismatch`, missing hashes after
  the chain starts, and unsupported hash algorithms.

Chain rewind, tail deletion, malformed rows, missing append-only controls, and
runtime database privilege failures are treated as high-priority operational
signals.

The daily `sitbank-audit-anchor-refresh@{staging,production}.timer` uses the
target-aware container wrapper. Refresh accepts only an exactly validated or
append-only stale anchor and atomically preserves owner-only permissions. It
refuses malformed, missing, mismatched, or invalid-chain states; alert checking
does not rotate anchors.

## Alerting

`check-security-alerts` builds a sanitized report from recent audit events and
runtime state:

```bash
python -m flask --app wsgi:app check-security-alerts --report-only
python -m flask --app wsgi:app check-security-alerts
```

Alert rules cover at least:

- audit hash-chain verification failure
- critical audit anchor mismatch or corruption
- stale audit anchor refresh due without alert delivery noise
- security audit write failures
- append-only audit protection failures
- runtime database privilege verification failures
- session-integrity failures
- account lock events
- password reset and manual recovery abuse thresholds
- login, auth backoff, transaction failure, and rate-limit bursts
- alert table regression signals from `SECURITY_ALERT_STATE_PATH`
- alert delivery failures

After an approved reset, `rebaseline-security-alert-state
--intentional-reset --reason ...` verifies the audit chain and configured
anchor, backs up the previous baseline, and atomically snapshots the same
protected tables. Unknown loss, chain failure, anchor mismatch, missing
acknowledgement, or missing reason fails closed. Output and audit evidence use
only table metrics, a keyed reason reference, whether a backup was created,
and its basename; the host backup path is not returned.

Alert severity values are configured in `app/security/alerts.py` and filtered
by `SECURITY_ALERT_MIN_SEVERITY`. Delivery supports HTTPS webhooks such as
Discord incoming webhooks. Before delivery, the report passes through a final
sanitizer that redacts secrets, bearer/basic credentials, cookies, database
URLs with credentials, webhook URLs, API keys, private-key-like values, and
long token-like strings.

`SecurityAlertDedupe` in PostgreSQL suppresses repeated delivery of the same
active alert for `SECURITY_ALERT_DEDUPE_TTL_SECONDS` while preserving the alert
in the JSON report. Delivery failures are reported by error type only and must
not include request bodies, webhook URLs, tokens, headers, passwords, session
IDs, or account numbers.

Authorized admin/root users can review a browser-rendered audit log viewer at
`GET /audit-logs` and safe details at `GET /audit-logs/<event_id>` in the
isolated admin runtime. The viewer is read-only: it has no export, edit, or
delete route. `staff` users and customers cannot access it.

The viewer defaults to a single visible `q` search box and keeps exact filters
inside an advanced filter disclosure. It validates filters, sort fields, sort
direction, page number, and page size server-side before any query is built.
Supported advanced controls are exact event type, actor user ID, approved
target-reference metadata keys, role, severity, outcome/status, request or
correlation ID, IP address, timestamp range using native date controls plus
SGT hour/half-hour time dropdowns, timestamp/severity/event-type/actor
sorting, and bounded pagination with Previous and Next links. The `q`
search field is limited to approved safe fields: activity/event type, outcome,
request ID, safe source display, target reference, actor user ID, actor
username, and privileged workplace email. It does not search raw unbounded
metadata. Customer personal email is never part of `q` search, including for
root admins; email matching is limited to privileged account roles whose
address also matches the configured workplace-domain allowlist.

List rows render only safe top-level event fields. Detail pages pass metadata
through the same display redaction used by tests, suppressing sensitive keys
and redacting sensitive-looking legacy values before Jinja autoescaping renders
the response. Viewer list and detail access are themselves audited with filter
names, sort direction, and page bounds only; sensitive query values are not
logged.

Audit list and detail pages include a human-readable activity label, concise
event description, investigation hint, safe actor summary, actor role, source
kind/display, target reference, request ID, outcome, severity, and hash-chain
status. Visible UI timestamps display in UTC+8/SGT such as
`02 Jul 2026, 06:11:49 SGT`; machine-readable UTC/ISO values remain in HTML
`datetime` attributes, existing UTC ISO filter query links, and JSON fields for
tooling. JavaScript-enhanced pagination fetches the same authorized JSON
payload, updates the table and browser history in place, and falls back to the
normal Previous and Next links if JavaScript is unavailable or fetch fails.
Invalid or reversed timestamp ranges return generic validation feedback without
parser internals. Known admin, MFA, staff
invite, staff lifecycle, manual recovery, deployment, Cloudflare, Tailscale,
runtime privilege, and alerting event types use explicit descriptions. Unknown
event types fall back to a safe readable label and preserve the raw technical
event name without rendering secrets. A field legend explains Actor, Actor
role, Source kind, Source, Target reference, Request ID, Timestamp, Hash chain,
Hash algorithm, Severity, and Outcome so admins can build an investigation case
without copying secrets into issues, pull requests, screenshots, or chat.

Authorized admin/root users can review current security alert report output at
`GET /alerts`. This dashboard route calls `build_security_alert_report()` with
delivery disabled; it does not send, resend, or acknowledge alerts. The browser
view shows labeled report cards, readable SGT timestamps with UTC `datetime`
values, friendly alert source summaries for first-pass triage, actionable safe
alert details, audit-chain and database-integrity status, delivery status,
dedupe status, next action text, and links to existing authorized audit-event
detail pages only when a related event row exists. The JSON, CLI, webhook,
dedupe, and audit-evidence report contract keeps machine-readable UTC values;
the browser detail panel preserves sanitized technical source, status, window,
reason, error type, related audit event, and recommended-action fields behind
the summary view.

Manual browser delivery is explicit and state-changing through
`POST /alerts/deliver` only. The route requires the existing admin/root session
authorization, the normal browser CSRF token, and a current TOTP step-up before
calling the same `build_security_alert_report(deliver=True)` path used by the
CLI/timer. It does not implement a parallel delivery mechanism, force-resend
mode, Web Push subscription, or browser notification channel. Existing severity
filtering, final delivery sanitization, and `SecurityAlertDedupe` suppression
remain in force. The route audits safe `security_alert_delivery` outcomes for
`requested`, `delivered`, `deduped`, `failed`, and `blocked` without storing
webhook URLs, tokens, TOTP codes, CSRF tokens, request bodies, authorization
headers, cookies, or raw alert payloads. Browser responses use safe
redirect/flash messages; JSON clients receive a whitelisted safe summary.

Operational logs are intentionally outside the admin app. Nginx, container,
deployment, systemd, Cloudflare, Tailscale, and other host-operation logs belong
in the Grafana/Loki observability boundary documented in
`operational-observability.md`. The admin app does not receive Loki or Grafana
credentials, does not query operational log stores, and does not render broad
host logs. Host-operation evidence for an incident should be summarized with
safe time windows, labels, command categories, and outcomes rather than raw
shell history, environment dumps, command arguments, tokens, or secret-bearing
payloads.

Production installs:

```bash
sudo systemctl enable --now sitbank-security-alerts.timer
sudo systemctl status sitbank-security-alerts.timer
journalctl -u sitbank-security-alerts.service
```

The timer runs `check-security-alerts` through the container runtime wrapper
every five minutes.

## Cloudflare Access Validation Events

The staging assertion gate records
`cloudflare_access_assertion_validation` with outcome `blocked` before
returning the same generic `403`. Safe reason codes distinguish
`missing_assertion`, `malformed_assertion`, `expired`, `not_yet_valid`,
`wrong_audience`, `wrong_issuer`, `invalid_signature`,
`unknown_signing_key`, `jwks_fetch_failed`, and `jwks_parse_failed`.
Metadata is limited to the reason, validator name, whether validation was
required, whether audience/issuer configuration exists, and whether a JWKS
cache entry was available.
The request correlation hook runs before the assertion gate, so every denial
event has the same safe correlation ID used by later request auditing. JWKS
cache availability is read under the cache lock used for refreshes and clears.

The raw assertion, JWT claims, JWKS document, authorization/cookie headers,
Cloudflare or service tokens, sessions, CSRF values, request body, and provider
response are never audit metadata. Provider automation applies its own output
sanitizer before handled errors reach CI logs; raw provider exports are not
workflow artifacts. Investigate using the reason code and protected provider
console, retaining only the approved sanitized evidence summary.

## Operator Expectations

- Review active alerts promptly and preserve the report output in the incident
  record.
- Treat audit-chain or anchor mismatches as evidence-preservation events; stop
  routine anchor rotation until investigation completes.
- Keep webhook URLs, audit HMAC keys, alert state paths, and anchor files
  host/operator-managed.
- Do not use alerting channels to deliver password reset links, recovery
  codes, MFA secrets, private keys, raw request bodies, or database dumps.
- After migrations, run `apply-runtime-db-privileges` and
  `verify-runtime-db-privileges` so append-only audit protections remain
  enforced.

## Test Coverage

| Test file | Coverage |
| --- | --- |
| `tests/test_audit_alerting.py` | Audit hash chain, anchor export/verify, alert thresholds, delivery sanitization, dedupe, failure handling |
| `tests/test_audit_metadata_sanitization.py` | Recursive metadata redaction and safe persistence/logging |
| `tests/test_deployment.py` | Audit runbooks, append-only migrations, runtime DB privilege commands, alert timer installation |
| `tests/test_password_reset.py` | Reset/manual-recovery audit flows and secret non-disclosure |
| `tests/test_admin_manual_recovery.py` | Admin manual recovery audit and route authorization |
| `tests/test_admin_dashboard_operations.py` | Admin dashboard, audit viewer, alert review, staff lifecycle, and template secret-regression coverage |
| `tests/test_admin_audit_viewer.py` | Audit viewer authorization, query validation, safe search, metadata redaction, escaping, and read-only behavior |
| `tests/test_session_management.py`, `tests/test_session_absolute_lifetime.py` | Session revocation, expiry, and integrity audit behavior |
| `tests/test_cloudflare_access_staging.py`, `tests/test_cloudflare_access_automation.py` | Fail-closed Access validation audit reasons and provider-output redaction |
