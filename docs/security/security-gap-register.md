# Security Gap Register

This register is the source of truth for current security gaps,
assessment-relevant constraints, implemented controls that are often reviewed,
and recently closed gaps. Other security documents should describe implemented
behavior and link here instead of carrying separate stale gap tables.

## Current Open Gaps

| Title | Status | Affected area | Evidence or reason | Recommended next action |
| --- | --- | --- | --- | --- |
| Password history beyond current-password reuse | Open | Authentication and password reset | `app/auth/services.py::change_password()` and `app/auth/password_reset.py::complete_password_reset()` reject reuse of the current password, but there is no previous-password history table or retention policy | Add a password-history table with pepper-aware hash metadata, retention limits, and tests for change/reset history rejection |
| Active-session count cap | Open | Session management | Users can view, terminate, and revoke sessions, but `app/security/sessions.py` does not cap total active sessions per user | Decide whether a numeric cap improves security/usability, then enforce it in session creation with tests |
| Device-bound session proof | Open | Session management | Stolen cookies are bounded by idle expiry, absolute lifetime, revocation, inventory, and risk step-up, but sessions are not cryptographically bound to a client-held device key or mTLS certificate | Keep as defense-in-depth unless project scope adds device-bound proof; document operator tradeoffs before implementation |
| Authenticated DAST on ordinary pull requests | Open policy tradeoff | CI/CD testing | `.github/workflows/ci-deploy.yml` reserves full authenticated DAST for scheduled/release paths to keep PR feedback fast | Revisit if CI budget allows PR DAST, or keep release-only with clear evidence collection |
| Local Docker/Compose proof when Docker is unavailable | Open local-environment constraint | Local developer checks | `scripts/ci-local` reports Docker/Compose checks as skipped when Docker is unavailable; CI and Docker-enabled local runs still validate Compose | Keep explicit skip output; use CI or a Docker-enabled workstation for release validation |

## Implemented Controls

| Control | Status | Key files | Key tests | Explanation |
| --- | --- | --- | --- | --- |
| Absolute authenticated session lifetime | Implemented and tested | `app/security/sessions.py`, `config.py` | `tests/test_session_absolute_lifetime.py` | Customer and admin sessions expire from the original authenticated timestamp; activity and TOTP step-up do not refresh that absolute age |
| Generated admin route inventory | Implemented and tested | `tests/test_admin_route_inventory_security.py`, `app/admin/routes.py` | `tests/test_admin_route_inventory_security.py` | Admin routes have an inventory separate from the customer route inventory, including auth, CSRF, rate-limit, and step-up decisions |
| Recovery-code regeneration fresh TOTP step-up | Implemented and tested | `app/auth/services.py::regenerate_totp_recovery_codes()` | `tests/test_mfa_lifecycle.py::test_recovery_code_regeneration_requires_fresh_totp_stepup` | Recovery-code regeneration requires an authenticated MFA-ready account and fresh TOTP authorization |
| Admin manual recovery review and completion | Implemented and tested | `app/admin/routes.py`, `app/admin/services.py`, `app/auth/password_reset.py` | `tests/test_admin_manual_recovery.py` | Root admins can review, transition, and complete manual recovery requests only in the isolated admin app with TOTP and operator reason controls |
| Production payee activation cooldown floor | Implemented and tested | `config.py::_validate_payee_cooldown_config()`, `app/ops/commands.py` | `tests/test_config.py`, `tests/test_deployment.py::test_production_check_rejects_short_payee_cooldown` | Production rejects payee cooldowns below 12 hours while development/test may use shorter explicit values |
| Production startup security guard | Implemented and tested | `app/security/production_guard.py`, `wsgi.py`, `admin_wsgi.py` | `tests/test_production_guard.py` | Runtime WSGI entrypoints fail closed in production when shared production prerequisites are unsafe |
| Payee IDOR and enumeration regression tests | Implemented and tested | `app/banking/routes.py`, `tests/test_payee_management_security.py` | `tests/test_payee_management_security.py` | Tests cover direct banking MFA gates, pre-TOTP recipient lookup blocking, ownership-scoped removal, self/duplicate rejection, and pending-payee expiry |
| Encrypted database backup tooling | Implemented and tested | `ops/backups/sitbank-backup-encrypted`, `ops/backups/sitbank-restore-preflight` | `tests/test_backup_security.py` | Host-managed scripts create age-encrypted `.pgdump.age` backups and provide explicit restore preflight checks |
| Audit hash-chain integrity and alerting | Implemented and tested | `app/security/audit.py`, `app/security/alerts.py`, `app/ops/commands.py` | `tests/test_audit_alerting.py`, `tests/test_audit_metadata_sanitization.py` | Audit rows are sanitized, HMAC-chained, verified/exported, and alert evaluation deduplicates and sanitizes delivery payloads |

## Not Applicable Or Out Of Scope

| Item | Status | Reason |
| --- | --- | --- |
| JavaScript package-manager auditing | Not applicable | No `package.json`, lockfile, npm/yarn/pnpm workspace, or JavaScript package manifest is present |
| Redis-backed session or security state | Out of scope | Current session, auth counter, alert dedupe, and security state are PostgreSQL-backed application-owned tables |
| WebAuthn/passkey/security-key login or step-up | Out of scope / disabled legacy | Current MFA baseline is TOTP; legacy WebAuthn/passkey routes and services are disabled or compatibility-only |
| OAuth or external high-level auth delegation | Out of scope | Authentication is application-owned with local password, TOTP, recovery-code, and admin invite flows |

## Recently Closed Gaps

| Closed item | Closed by | Evidence |
| --- | --- | --- |
| Registration migration generated fake phones and predictable accounts | Issue 148 | `migrations/versions/20260622_0008_add_user_registration_fields.py`, `tests/test_deployment.py` |
| Session timeout UX and web revocation controls were incomplete | Issue 149 | `app/static/js/session-timeout.js`, `app/web/routes.py`, `tests/test_session_management.py` |
| Banking routes lacked direct MFA gate and payee lookup revealed recipient identity before TOTP | Issue 150 | `app/banking/routes.py`, `tests/test_payee_management_security.py` |
| Production password minimum allowed 8-character passwords by default | Issue 156 | `config.py`, `app/security/passwords.py`, `tests/test_production_guard.py`, `tests/test_passwords.py` |
| Backup encryption and restore access checks were only operational notes | Issue 167 | `ops/backups/sitbank-backup-encrypted`, `ops/backups/sitbank-restore-preflight`, `tests/test_backup_security.py` |
