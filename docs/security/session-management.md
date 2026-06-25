# Session Management

This document describes the session management controls implemented in the
SITBank repository. The implementation uses database-backed server-side
sessions with an opaque browser cookie, not Redis or client-side session
payloads.

## 2.1 Session Storage

SITBank installs a custom `DatabaseSessionInterface` from
`app/security/sessions.py` during application startup in `app/__init__.py`.
Although `config.py` sets `SESSION_TYPE = "database"`, the repository does not
use Flask-Session or Redis for production session storage. Browser cookies hold
only an opaque session id. Session state is stored in the `server_side_sessions`
table represented by `ServerSideSession` in `app/models.py`.

| Stored value | Implementation evidence | Protection |
| --- | --- | --- |
| Browser session id | `app/security/sessions.py::_generate_sid()` | Opaque id generated with `uuid.uuid4()`; not stored raw in the database |
| Database lookup key | `app/security/sessions.py::session_lookup_hash()` | HMAC-SHA256 with `SESSION_LOOKUP_HMAC_KEY` |
| Serialized session payload | `ServerSideSession.data` in `app/models.py` | Signed by `app/security/session_hmac.py` with a binding context that includes the component and lookup hash |
| User/session metadata | `user_id`, `auth_level`, `created_at`, `last_seen_at`, `expires_at`, `revoked_at`, `ended_reason`, `risk_fingerprint` | Used for revocation, session inventory, inactivity timeout, and risk reauthentication |
| Public session reference | `session_ref` and `_public_reference_from_lookup_hash()` | HMAC-derived public id for session-management actions; raw internal ids are rejected |

The session payload signature is versioned and key-id aware. The active HMAC
key signs new payloads, and old keys can remain configured so existing
sessions survive key rotation. Evidence: `app/security/session_hmac.py` and
`tests/test_db_session_integrity.py::test_db_session_payload_survives_active_hmac_key_rotation`.

Current gap: Redis-backed session storage is not implemented. Any control that
specifically requires Redis session persistence or Redis payload HMACs is not
applicable to the current codebase unless the storage layer is changed.

## 2.2 Cookie Structure

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
| `tests/test_config.py::test_runtime_secret_maps_use_session_lookup_key_not_redis_url` | Confirms runtime secret maps use the session lookup HMAC key and not Redis URL configuration |

## 2.3 Cookie Transmission

Cookies are transmitted by the browser on HTTPS requests to the configured
hostname. Production and staging Nginx terminate HTTPS and forward to loopback
Gunicorn listeners. Nginx overwrites proxy headers in
`ops/nginx-proxy-headers.conf`, and `app/__init__.py` applies `ProxyFix` with
`TRUSTED_PROXY_COUNT`.

Transport protections:

| Control | Evidence |
| --- | --- |
| HTTPS edge | `ops/nginx/sitbank-production.conf`, `ops/nginx/sitbank-staging.conf` |
| HTTP to HTTPS redirect | Production Nginx redirects customer and admin HTTP hostnames to HTTPS |
| HSTS | Production Nginx sets `Strict-Transport-Security "max-age=31536000; includeSubDomains"` |
| Flask secure cookie enforcement | `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and `SESSION_COOKIE_SAMESITE` in `config.py` |
| Proxy trust boundary | `ops/nginx-proxy-headers.conf` and `tests/test_deployment.py::test_proxyfix_trusts_exactly_the_configured_nginx_hop` |

Current gap: TLS cipher suite pinning is not explicit in Nginx. Session cookie
transport depends on the deployed host's Nginx/OpenSSL cipher defaults in
addition to the repository's `ssl_protocols TLSv1.2 TLSv1.3` setting.

## 2.4 Session Modification And Tamper Resistance

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

## 2.5 Session Lifecycle

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

The customer and admin runtimes default to five minutes for
`SESSION_INACTIVITY_SECONDS` and `PERMANENT_SESSION_LIFETIME` in `config.py`.
The database record's `expires_at` is renewed on active requests and revoked
when inactivity is detected.

Current gap: the active authenticated session lifetime is sliding. No
independent hard absolute maximum lifetime for a fully authenticated session
was found. Pending MFA sessions do have an absolute age check covered by
`tests/test_mfa_lifecycle.py::test_pending_mfa_session_expires_by_absolute_age`.

## 2.6 Session Attack Coverage

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
| Risk drift after login | IP/UA-derived risk fingerprint requires reauthentication before sensitive actions | `app/security/sessions.py`; `tests/test_account_security_actions.py::test_session_risk_drift_requires_reauth_before_sensitive_action` |
| Stolen active cookie | Inactivity timeout, revocation, session inventory, and risk step-up reduce impact | `app/security/sessions.py`, `tests/test_session_management.py` |

Current gap: there is no concurrent-session count limit. Users can view and
revoke sessions, but the repository does not cap the number of active sessions
per user.

Current gap: a stolen active cookie may remain usable until inactivity expiry,
revocation, or risk-based reauthentication triggers. There is no cryptographic
binding to a device key or client certificate.
