# Feature Security Checklist

This checklist is the current repository-level index for feature security
status. It is not a substitute for the focused architecture, governance,
deployment, and runbook documents linked from `docs/security/README.md`.

Category: [Security assurance](../README.md#assurance).

## Current Feature Status

| Feature or boundary | Current security status | Evidence |
| --- | --- | --- |
| Customer registration | Email OTP is required before account creation; client-supplied account numbers and admin-domain customer emails are rejected; new account numbers are 12-digit server-generated identifiers | `app/auth/registration_otp.py`, `app/auth/services.py`, `tests/test_auth_registration_login.py` |
| Customer login and MFA | Password login uses generic errors, PBKDF2 password hashing, failed-attempt controls, encrypted TOTP seeds, recovery-code fallback, and TOTP replay prevention | `app/auth/services.py`, `app/security/passwords.py`, `tests/test_auth_registration_login.py`, `tests/test_mfa_lifecycle.py` |
| Customer sessions | Server-side sessions use opaque cookie identifiers, HMAC-signed payloads, absolute lifetime enforcement, risk drift handling, and scoped session termination | `app/security/sessions.py`, `tests/test_session_management.py`, `tests/test_session_absolute_lifetime.py`, `tests/test_session_risk_binding.py` |
| CSRF | Global Flask-WTF CSRF is expected on unsafe browser routes and is tracked by route inventories plus targeted runtime tests | `app/extensions.py`, `tests/test_route_inventory_security.py`, `tests/test_payup.py` |
| Password reset and manual recovery | Token and recovery-code verifiers are HMAC-backed; manual recovery is request-only until root-admin review and maker-checker approval | `app/auth/password_reset.py`, `tests/test_password_reset.py`, `tests/test_admin_manual_recovery.py`, `tests/test_admin_maker_checker.py` |
| Account freeze | Customer-initiated freeze requires TOTP, revokes other sessions, blocks sensitive actions, sends a security email, and produces an immediate alert | `app/auth/services.py`, `app/security/alerts.py`, `tests/test_account_security_actions.py`, `tests/test_audit_alerting.py` |
| Payee management | Payee lookup requires TOTP before recipient identity disclosure; self, duplicate, missing, expired, and cross-user paths fail closed | `app/banking/routes.py`, `tests/test_payee_management_security.py`, `tests/test_payee_idor.py` |
| Local Transfer | Final execution reloads the payee and pending record, validates owner/account/amount state, consumes a keyed pending-token verifier, locks rows in deterministic order, and commits ledger movement with required audit | `app/banking/services.py`, `tests/test_local_transfer.py`, `tests/test_local_transfer_security.py` |
| PayUp | Phone lookup requires TOTP before recipient name disclosure; unknown and unavailable recipients are generic; daily limits reset at midnight Singapore time; the 80% confirmation step-up is recomputed at send time; pending tokens are keyed verifiers | `app/banking/routes.py`, `app/banking/services.py`, `tests/test_payup.py` |
| Transfer limits | PayUp limit changes require TOTP and CSRF; custom limits are server-side validated | `app/banking/routes.py`, `tests/test_transfer_limits.py`, `tests/test_payup.py` |
| Staff/admin login | Admin runtime is isolated from the customer app and accepts only active staff roles with approved workplace email, verified workplace email, password, and TOTP | `app/__init__.py`, `app/admin/services.py`, `tests/test_admin_isolation.py`, `tests/test_admin_dashboard_operations.py` |
| Root-admin bootstrap and allowlist | Production root-admin allowlists require exact environment-specific counts, approved domains, no duplicates, no defaults, and no placeholder or numeric placeholder identities | `config.py`, `app/admin/bootstrap.py`, `tests/test_config.py`, `tests/test_production_guard.py` |
| Staff/admin maker-checker | Highest-risk staff lifecycle and manual recovery changes require a requester and different active root-admin approver; target state and request state are updated atomically for staff lifecycle execution | `app/admin/services.py`, `tests/test_admin_maker_checker.py` |
| Audit and alerts | Audit metadata redacts sensitive values, audit chains are HMAC-linked, selected critical events are immediate alerts, and webhook delivery sanitizes payloads | `app/security/audit.py`, `app/security/alerts.py`, `tests/test_audit_alerting.py`, `tests/test_audit_metadata_sanitization.py` |
| Deployment and runtime boundaries | Customer/admin runtimes, database roles, Docker secrets, Tailscale private admin access, Cloudflare staging controls, Nginx TLS, and readiness gates are documented and tested from repo-controlled artifacts | `docs/DEPLOYMENT.md`, `tests/test_deployment.py`, `tests/test_zero_trust_access_boundary.py`, `tests/test_tailscale_admin_access.py` |
| Browser E2E | Local-only Playwright tests exercise browser-rendered authentication, MFA, session, banking, and boundary regressions against a loopback Flask server; they do not prove live staging or production provider state | `tests/e2e/`, `tests/test_playwright_e2e_config.py` |

## Maintenance Rules

- When a feature changes authentication, authorization, CSRF, rate limiting,
  session state, audit metadata, alerting, banking ledger behavior, migration
  shape, deployment gates, or operator action, update this checklist or a more
  specific linked security document in the same change.
- Add or update a stale-documentation test when the documented security status
  could otherwise drift silently.
- Do not describe live provider state, branch protection, SonarQube results, or
  production deployment outcomes as current unless the change also includes the
  verification artifact or points to the external evidence owner.
- Use fake values in examples and tests. Never add production secrets, real
  customer data, raw session ids, CSRF tokens, TOTP seeds, recovery codes, JWTs,
  private keys, provider exports, or real infrastructure credentials.
