# Session Management

This document describes the session management controls implemented in the
SITBank repository. The implementation uses database-backed server-side
sessions identified by an opaque browser cookie.
Framework coverage and current follow-up items are centralized in
`docs/security/framework-control-matrix.md` and
`docs/security/security-gap-register.md`.

## Session Storage

SITBank installs a custom `DatabaseSessionInterface` from
`app/security/sessions.py` during application startup in `app/__init__.py`.
Browser cookies hold only an opaque session id. Session state is stored in the
`server_side_sessions` table represented by `ServerSideSession` in
`app/models.py`.

| Stored value | Implementation evidence | Protection |
| --- | --- | --- |
| Browser session id | `app/security/sessions.py::_new_session_id()` | Opaque id generated with `uuid.uuid4()`; not stored raw in the database |
| Database lookup key | `app/security/sessions.py::session_lookup_hash()` | HMAC-SHA256 with `SESSION_LOOKUP_HMAC_KEY` |
| Serialized session payload | `ServerSideSession.payload` in `app/models.py` | Signed by `app/security/session_hmac.py` with a binding context that includes the component and lookup hash |
| User/session metadata | `user_id`, `created_at`, `last_activity_at`, `expires_at`, `revoked_at`, `ended_reason`, `risk_fingerprint` | Used for revocation, session inventory, inactivity timeout, and risk reauthentication |
| Signed session risk context | HMAC-derived coarse network, User-Agent family, and normalized User-Agent hashes plus the last check time | Detects context drift without storing raw IP or User-Agent values in the risk-context payload |
| Public session reference | `session_ref` and `_public_reference_from_lookup_hash()` | HMAC-derived public id for session-management actions; raw internal ids are rejected |

The session payload signature is versioned and key-id aware. The active HMAC
key signs new payloads, and old keys can remain configured so existing
sessions survive key rotation. Evidence: `app/security/session_hmac.py` and
`tests/test_db_session_integrity.py::test_db_session_payload_survives_active_hmac_key_rotation`.

## Cookie Structure

Customer and admin runtimes use different cookie names and separate secret
material:

| Runtime | Cookie name | Evidence |
| --- | --- | --- |
| Customer app | `__Host-sitbank_session` | `config.py` customer runtime config |
| Admin app | `__Host-sitbank_admin_session` | `config.py` admin runtime config |

Both cookies are configured with:

| Attribute | Value | Evidence |
| --- | --- | --- |
| `Secure` | Enabled | `SESSION_COOKIE_SECURE = True` in `config.py`; `app/__init__.py` passes it to Flask-Talisman |
| `HttpOnly` | Enabled | `SESSION_COOKIE_HTTPONLY = True` in `config.py` |
| `SameSite` | `Strict` | `SESSION_COOKIE_SAMESITE = "Strict"` in `config.py` |
| Cookie name prefix | `__Host-` | Customer and admin cookie names in `config.py` |
| Domain | Not configured in the repo | Required by the `__Host-` browser prefix semantics |
| Path | Flask default path `/` | No narrower path override was found in config |

The cookie value is an opaque session id. It does not contain the user id, role,
MFA state, CSRF token, or serialized account data. The server uses the opaque
id to compute a lookup HMAC and retrieve the signed payload from the database.

Tests:

| Test | Coverage |
| --- | --- |
| `tests/test_session_management.py::test_login_sets_secure_session_cookie_and_hides_raw_session_id` | Checks secure cookie behavior and that the raw session id is not exposed in session management UI |
| `tests/test_admin_staff_invites.py::test_admin_login_creates_only_admin_session_cookie` | Confirms admin login creates only the admin cookie |
| `tests/test_config.py` runtime secret map checks | Confirms runtime secret maps include the required session lookup HMAC key |

## Cookie Transmission

Cookies are transmitted by the browser on HTTPS requests to the configured
hostname. Production and staging Nginx terminate HTTPS and forward to loopback
Gunicorn listeners. Nginx overwrites proxy headers in
`ops/nginx-proxy-headers.conf`, and `app/__init__.py` applies `ProxyFix` with
`TRUSTED_PROXY_COUNT`.

Staging browser traffic must pass Cloudflare Access before the staging Nginx
server reaches Flask, and the staging origin requires Cloudflare Authenticated
Origin Pulls for browser/app paths. Admin browser traffic must use a
Tailscale/private operator path before it can reach the loopback admin service.
These network boundaries do not merge session state: customer and admin
cookies, lookup HMAC keys, session key prefixes, rate-limit prefixes, and
runtime database roles remain separate.

Transport protections:

| Control | Evidence |
| --- | --- |
| HTTPS edge | `ops/nginx/sitbank-production.conf`, `ops/nginx/sitbank-staging.conf` |
| HTTP handling | Production Nginx redirects customer HTTP to HTTPS; public admin non-ACME HTTP returns `403` |
| HSTS | Production Nginx sets `Strict-Transport-Security "max-age=31536000; includeSubDomains"` |
| Flask secure cookie enforcement | `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and `SESSION_COOKIE_SAMESITE` in `config.py` |
| Proxy trust boundary | `ops/nginx-proxy-headers.conf` and `tests/test_deployment.py::test_proxyfix_trusts_exactly_the_configured_nginx_hop` |

All configured HTTPS edges include `ops/nginx/sitbank-tls-policy.conf`, which
pins TLS 1.2 to ECDHE+AEAD suites, TLS 1.3 to standard AEAD suites, and the
ECDHE curve preference. TLS 1.0 and TLS 1.1, legacy weak cipher families, and
session tickets remain disabled. Operators validate the loaded policy on the
deployed Nginx/OpenSSL build before release.

## Session Modification And Tamper Resistance

The browser cannot directly modify authenticated session state because the
cookie contains only an opaque session id. The database payload is signed with
HMAC-SHA256 and bound to the session row context. A copied signed payload from
one session row is rejected when placed in another row.

Tamper handling in `app/security/sessions.py`:

| Condition | Behavior | Evidence |
| --- | --- | --- |
| Unknown or expired session | Returns a fresh anonymous session | `DatabaseSessionInterface.open_session()` |
| Revoked session | Treated as ended and not authenticated | `ServerSideSession.revoked_at` checks |
| Missing or invalid payload signature | Logs `session_integrity` with a safe reference and starts a new anonymous session | `_handle_integrity_failure()` |
| Unsupported payload format | Rejected rather than interpreted | `tests/test_db_session_integrity.py::test_unsupported_db_session_payload_format_is_rejected` |
| Copied payload between rows | Rejected because the binding context changes | `tests/test_db_session_integrity.py::test_signed_db_session_payload_copied_to_another_row_is_rejected` |

Relevant integrity tests:

| Test | Coverage |
| --- | --- |
| `tests/test_db_session_integrity.py::test_valid_db_session_payload_continues_to_authenticate` | Baseline valid database session payload |
| `tests/test_db_session_integrity.py::test_modified_db_session_user_id_is_rejected` | User id tampering |
| `tests/test_db_session_integrity.py::test_modified_db_session_privilege_flags_are_rejected` | Privilege flag tampering |
| `tests/test_db_session_integrity.py::test_invalid_db_session_signature_is_rejected` | Invalid HMAC |
| `tests/test_db_session_integrity.py::test_tampered_db_session_payload_logs_only_safe_reference` | Logging does not expose raw session material |
| `tests/test_db_session_integrity.py::test_session_payload_binding_context_is_required_and_checked` | Binding context enforcement |

## Session Lifecycle

Session creation and rotation are implemented in `app/security/sessions.py` and
called from authentication services in `app/auth/services.py` and
`app/admin/services.py`.

| Lifecycle event | Control | Evidence |
| --- | --- | --- |
| Password login that requires MFA | Creates a pending MFA session instead of a fully authenticated session | `app/auth/services.py::authenticate_primary()`; `tests/test_pentest_auth_bypass.py::test_pending_mfa_session_cannot_access_dashboard` |
| Successful customer MFA | Rotates the session id and records authenticated session metadata | `app/auth/services.py::complete_pending_mfa()` and `app/security/sessions.py` |
| Successful admin MFA | Uses the admin session cookie and staff account checks | `app/admin/services.py`; `tests/test_admin_staff_invites.py::test_admin_login_creates_only_admin_session_cookie` |
| Password change | Requires TOTP step-up, rotates current session, revokes other sessions | `app/auth/services.py::change_password()`; `tests/test_account_security_actions.py::test_password_change_succeeds_with_recent_mfa_and_revokes_other_sessions` |
| Logout | Revokes current server-side session | `tests/test_session_management.py::test_logout_invalidates_current_session` |
| Revoke other sessions | Requires high-risk TOTP authorization and keeps the current session after rotation | `tests/test_session_management.py::test_revoke_other_sessions_accepts_totp_stepup_and_rotates_session` |
| Terminate one listed session | Uses public session references and ownership checks | `tests/test_session_management.py::test_terminate_other_session_by_public_reference_revokes_it` |
| Inactivity expiry | Rejects sessions after `SESSION_INACTIVITY_SECONDS` | `tests/test_session_management.py::test_session_inactivity_expiry_revokes_session` |
| Absolute authenticated lifetime | Rejects fully authenticated sessions after `SESSION_ABSOLUTE_LIFETIME_SECONDS` without refreshing the timestamp during activity or step-up | `tests/test_session_absolute_lifetime.py` |

The customer and admin runtimes default to five minutes for
`SESSION_INACTIVITY_SECONDS` and `PERMANENT_SESSION_LIFETIME` in `config.py`.
The database record's `expires_at` is renewed on active requests and revoked
when inactivity is detected.

Fully authenticated sessions also carry a server-side `auth_created_at`
timestamp. Customer sessions default to a 12-hour absolute lifetime through
`CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS`; admin sessions default to a
4-hour absolute lifetime through `ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS`.
Runtime mode maps the appropriate value to `SESSION_ABSOLUTE_LIFETIME_SECONDS`.
Normal activity, CSRF requests, and TOTP step-up rotations do not refresh this
timestamp. Pending MFA sessions keep their separate absolute age check covered
by `tests/test_mfa_lifecycle.py::test_pending_mfa_session_expires_by_absolute_age`.

## Stolen-Cookie Resistance And Session Context

SITBank does not implement cryptographic device-bound sessions. A copied active
cookie remains a bearer credential: public browsers do not expose a suitable
per-request private key to this application, and IP addresses or User-Agent
strings are not proof of possession. Device-held keys, browser proof-of-
possession, and mTLS for public customer sessions remain outside the current
architecture.

The practical control is a risk-based context layer in
`app/security/sessions.py`. At full customer or admin authentication it stores,
inside the signed server-side payload:

- an HMAC of the coarse client network (`/24` for IPv4 or `/64` for IPv6);
- an HMAC of the parsed User-Agent family;
- an HMAC of the normalized User-Agent; and
- the last context-check timestamp.

These values use the runtime's session HMAC keyring, so customer and admin
contexts are cryptographically separated. The payload does not store a raw IP
address or raw User-Agent in the risk-context object. Existing session
inventory/audit records retain their separately documented request metadata.

Authenticated requests compare the current context after absolute-lifetime and
idle-timeout enforcement, so a context check cannot refresh or bypass either
lifetime:

| Change | Customer policy | Admin policy |
| --- | --- | --- |
| No change | Continue and update only the last context-check time | Continue |
| Same browser family, changed detailed User-Agent such as a version update | Audit the low-risk change and refresh the context baseline | Revoke and require full admin login |
| Coarse network or browser family changes | Allow ordinary customer navigation, mark the session for full reauthentication, and reject sensitive actions before TOTP processing | Revoke and require full admin login |
| Coarse network and browser family both change | Revoke and require full customer login | Revoke and require full admin login |

Risk audit metadata contains only the runtime, severity, and changed signal
names. It does not contain cookies, raw session ids, raw context values, or
session payloads. Standard audit request columns remain governed by
`docs/security/audit-and-alerting.md`.

Legacy authenticated sessions without the structured context are migrated on
their next request. A matching legacy `risk_fingerprint` is accepted and
upgraded; a mismatch requires customer reauthentication or revokes an admin
session. A session with no prior fingerprint is initialized without pretending
that historical context was verified.

Focused coverage is in `tests/test_session_risk_binding.py`. It verifies
customer/admin context creation, low/medium/high handling, strict admin
revocation, lifetime precedence, CSRF behavior, audit safety, and runtime/key
isolation.

## Session Attack Coverage

| Attack or risk | Implemented control | Evidence |
| --- | --- | --- |
| Session fixation | Session id is rotated after authentication milestones and high-risk changes | `rotate_session_id()` in `app/security/sessions.py`; password-change and revoke-other-session tests |
| Client-side privilege tampering | Authenticated state is server-side and HMAC-signed | `tests/test_db_session_integrity.py` |
| Raw session id exposure in management UI | UI uses public HMAC-derived references | `tests/test_session_management.py::test_session_termination_rejects_raw_internal_session_id` |
| Terminating another user's session | Ownership and public-reference checks | `tests/test_pentest_auth_bypass.py::test_cannot_terminate_other_users_session` |
| Public reference brute force | Invalid references are rejected | `tests/test_pentest_auth_bypass.py::test_session_ref_bruteforce_rejected` |
| Pending MFA bypass | Pending sessions cannot access authenticated pages or sensitive APIs | `tests/test_pentest_auth_bypass.py::test_pending_mfa_session_cannot_access_dashboard`, `tests/test_pentest_auth_bypass.py::test_pending_mfa_session_cannot_freeze_account` |
| CSRF on session-changing routes | Global Flask-WTF CSRF plus route inventory checks | `tests/test_route_inventory_security.py::test_route_inventory_has_complete_security_decisions` |
| Insecure transport | HTTPS-only Nginx and secure cookie flag | `ops/nginx/sitbank-production.conf`, `config.py`, `tests/test_deployment.py` |
| Risk drift after login | HMAC-derived coarse network and User-Agent context triggers customer reauthentication or revocation; admin drift revokes the session | `app/security/sessions.py`; `tests/test_session_risk_binding.py` |
| Stolen active cookie | Inactivity timeout, absolute lifetime, revocation, session inventory, and risk-based reauthentication reduce impact, but the cookie is not cryptographically device-bound | `app/security/sessions.py`, `tests/test_session_risk_binding.py`, `tests/test_session_management.py`, `tests/test_session_absolute_lifetime.py` |

Remaining session risk-reduction items, such as optional active-session count
caps and stronger device-bound session proof, are tracked in
`docs/security/security-gap-register.md`.
