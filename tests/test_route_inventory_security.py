from __future__ import annotations

import ast
from pathlib import Path


UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
AUTH_DECORATORS = {"login_required", "web_login_required"}
RATE_LIMIT_DECISIONS = {
    "per_route",
    "edge_auth",
    "edge_app",
    "edge_health_ready",
    "not_needed_liveness",
}
STEP_UP_DECISIONS = {
    "not_required",
    "required",
    "conditional",
    "already_authorized_continuation",
    "reset_mfa",
}
SENSITIVE_CLASSIFICATIONS = {
    "account_freeze",
    "csrf",
    "dashboard",
    "login",
    "logout",
    "mfa",
    "password",
    "account_recovery",
    "profile",
    "registration",
    "session",
    "webauthn",
}


ROUTE_MODULES = {
    "auth": Path("app/auth/routes.py"),
    "banking": Path("app/banking/routes.py"),
    "main": Path("app/main/routes.py"),
    "web": Path("app/web/routes.py"),
}


ROUTE_SECURITY_INVENTORY = {
    "main.index": {
        "endpoint": "main.index",
        "rule": "/",
        "methods": {"GET"},
        "access": "public",
        "classification": "homepage",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "Public landing page; authenticated users are redirected to the dashboard.",
    },
    "main.health_live": {
        "endpoint": "main.health_live",
        "rule": "/health/live",
        "methods": {"GET"},
        "access": "public",
        "classification": "health",
        "csrf": "not_applicable",
        "rate_limit": "not_needed_liveness",
        "step_up": "not_required",
        "public_justification": "Liveness endpoint intentionally returns only process status for external monitors.",
    },
    "main.health_ready": {
        "endpoint": "main.health_ready",
        "rule": "/health/ready",
        "methods": {"GET"},
        "access": "public",
        "classification": "health",
        "csrf": "not_applicable",
        "rate_limit": "edge_health_ready",
        "step_up": "not_required",
        "public_justification": "Readiness is public only inside Flask; production and staging Nginx restrict it to loopback.",
    },
    "auth.csrf_token": {
        "endpoint": "auth.csrf_token",
        "rule": "/auth/csrf-token",
        "methods": {"GET"},
        "access": "public",
        "classification": "csrf",
        "csrf": "not_applicable",
        "rate_limit": "edge_auth",
        "step_up": "not_required",
        "public_justification": "JSON clients need a token before submitting CSRF-protected auth requests.",
    },
    "auth.register": {
        "endpoint": "auth.register",
        "rule": "/auth/register",
        "methods": {"POST"},
        "access": "public",
        "classification": "registration",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Account creation must be reachable before authentication but requires a verified customer email OTP.",
    },
    "auth.register_otp_request": {
        "endpoint": "auth.register_otp_request",
        "rule": "/auth/register/otp/request",
        "methods": {"POST"},
        "access": "public",
        "classification": "registration",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Registration OTP requests must be reachable before account creation and block configured admin workplace email domains.",
    },
    "auth.register_otp_verify": {
        "endpoint": "auth.register_otp_verify",
        "rule": "/auth/register/otp/verify",
        "methods": {"POST"},
        "access": "public",
        "classification": "registration",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Registration OTP verification binds the approved customer email to the caller's pre-authentication session.",
    },
    "auth.login": {
        "endpoint": "auth.login",
        "rule": "/auth/login",
        "methods": {"POST"},
        "access": "public",
        "classification": "login",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Primary authentication must be reachable before a user has a session.",
    },
    "auth.password_reset_request": {
        "endpoint": "auth.password_reset_request",
        "rule": "/auth/password-reset/request",
        "methods": {"POST"},
        "access": "public",
        "classification": "password",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Forgot-password requests must be reachable before authentication and return generic responses.",
    },
    "auth.password_reset_exchange": {
        "endpoint": "auth.password_reset_exchange",
        "rule": "/auth/password-reset/exchange",
        "methods": {"POST"},
        "access": "public",
        "classification": "password",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "reset_mfa",
        "public_justification": "Reset-token exchange happens before a customer has an authenticated session.",
    },
    "auth.password_reset_transaction": {
        "endpoint": "auth.password_reset_transaction",
        "rule": "/auth/password-reset/transaction",
        "methods": {"GET"},
        "access": "public",
        "classification": "password",
        "csrf": "not_applicable",
        "rate_limit": "edge_auth",
        "step_up": "reset_mfa",
        "public_justification": "Reset transaction status is scoped to the tokenless reset cookie state.",
    },
    "auth.password_reset_mfa_method": {
        "endpoint": "auth.password_reset_mfa_method",
        "rule": "/auth/password-reset/mfa/method",
        "methods": {"POST"},
        "access": "public",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "reset_mfa",
        "public_justification": "Reset MFA method selection is bound to the tokenless reset transaction before login.",
    },
    "auth.password_reset_totp": {
        "endpoint": "auth.password_reset_totp",
        "rule": "/auth/password-reset/mfa/totp",
        "methods": {"POST"},
        "access": "public",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "reset_mfa",
        "public_justification": "TOTP verification completes a password-reset transaction before login.",
    },
    "auth.password_reset_recovery_code": {
        "endpoint": "auth.password_reset_recovery_code",
        "rule": "/auth/password-reset/mfa/recovery-code",
        "methods": {"POST"},
        "access": "public",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "reset_mfa",
        "public_justification": "A recovery code can complete a password-reset transaction before login.",
    },
    "auth.password_reset_webauthn_options": {
        "endpoint": "auth.password_reset_webauthn_options",
        "rule": "/auth/password-reset/mfa/webauthn/options",
        "methods": {"POST"},
        "access": "public",
        "classification": "webauthn",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Legacy password-reset WebAuthn compatibility endpoint fails closed before authentication.",
    },
    "auth.password_reset_webauthn_verify": {
        "endpoint": "auth.password_reset_webauthn_verify",
        "rule": "/auth/password-reset/mfa/webauthn/verify",
        "methods": {"POST"},
        "access": "public",
        "classification": "webauthn",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Legacy password-reset WebAuthn compatibility endpoint fails closed before authentication.",
    },
    "auth.password_reset_complete": {
        "endpoint": "auth.password_reset_complete",
        "rule": "/auth/password-reset/complete",
        "methods": {"POST"},
        "access": "public",
        "classification": "password",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "reset_mfa",
        "public_justification": "Password reset completion is authorized by reset transaction state rather than an app login.",
    },
    "auth.manual_recovery_request": {
        "endpoint": "auth.manual_recovery_request",
        "rule": "/auth/account-recovery",
        "methods": {"POST"},
        "access": "public",
        "classification": "account_recovery",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Manual customer recovery requests must be possible before authentication but cannot change account state.",
    },
    "auth.webauthn_register_options": {
        "endpoint": "auth.webauthn_register_options",
        "rule": "/auth/webauthn/register/options",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "webauthn",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "",
    },
    "auth.webauthn_register_verify": {
        "endpoint": "auth.webauthn_register_verify",
        "rule": "/auth/webauthn/register/verify",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "webauthn",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "",
    },
    "auth.webauthn_authenticate_options": {
        "endpoint": "auth.webauthn_authenticate_options",
        "rule": "/auth/webauthn/authenticate/options",
        "methods": {"POST"},
        "access": "public",
        "classification": "webauthn",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "WebAuthn login challenge endpoint is part of authentication before a user session exists.",
    },
    "auth.webauthn_authenticate_verify": {
        "endpoint": "auth.webauthn_authenticate_verify",
        "rule": "/auth/webauthn/authenticate/verify",
        "methods": {"POST"},
        "access": "public",
        "classification": "webauthn",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "WebAuthn login assertion endpoint completes authentication before a user session exists.",
    },
    "auth.webauthn_step_up_options": {
        "endpoint": "auth.webauthn_step_up_options",
        "rule": "/auth/webauthn/step-up/options",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "webauthn",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "",
    },
    "auth.webauthn_step_up_verify": {
        "endpoint": "auth.webauthn_step_up_verify",
        "rule": "/auth/webauthn/step-up/verify",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "webauthn",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "",
    },
    "auth.webauthn_credentials": {
        "endpoint": "auth.webauthn_credentials",
        "rule": "/auth/webauthn/credentials",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "webauthn",
        "csrf": "not_applicable",
        "rate_limit": "edge_auth",
        "step_up": "not_required",
        "public_justification": "",
    },
    "auth.webauthn_revoke_credential": {
        "endpoint": "auth.webauthn_revoke_credential",
        "rule": "/auth/webauthn/credentials/<credential_id>",
        "methods": {"DELETE"},
        "access": "authenticated",
        "classification": "webauthn",
        "csrf": "required",
        "rate_limit": "edge_auth",
        "step_up": "not_required",
        "public_justification": "",
    },
    "auth.logout": {
        "endpoint": "auth.logout",
        "rule": "/auth/logout",
        "methods": {"POST"},
        "access": "public",
        "classification": "logout",
        "csrf": "required",
        "rate_limit": "edge_auth",
        "step_up": "not_required",
        "public_justification": "Logout is idempotent and clears only the caller's current session state.",
    },
    "auth.mfa_setup": {
        "endpoint": "auth.mfa_setup",
        "rule": "/auth/mfa/setup",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "",
    },
    "auth.mfa_setup_verify": {
        "endpoint": "auth.mfa_setup_verify",
        "rule": "/auth/mfa/setup/verify",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "",
    },
    "auth.mfa_replace_start": {
        "endpoint": "auth.mfa_replace_start",
        "rule": "/auth/mfa/replace/start",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "public_justification": "",
    },
    "auth.mfa_replace_verify": {
        "endpoint": "auth.mfa_replace_verify",
        "rule": "/auth/mfa/replace/verify",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "already_authorized_continuation",
        "public_justification": "",
    },
    "auth.mfa_recovery_codes_regenerate": {
        "endpoint": "auth.mfa_recovery_codes_regenerate",
        "rule": "/auth/mfa/recovery-codes/regenerate",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "public_justification": "",
    },
    "auth.mfa_verify": {
        "endpoint": "auth.mfa_verify",
        "rule": "/auth/mfa/verify",
        "methods": {"POST"},
        "access": "public",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "TOTP verification completes a pending login before a full user session exists.",
    },
    "auth.sessions_dashboard": {
        "endpoint": "auth.sessions_dashboard",
        "rule": "/auth/sessions",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "session",
        "csrf": "not_applicable",
        "rate_limit": "edge_auth",
        "step_up": "not_required",
        "public_justification": "",
    },
    "auth.session_extend": {
        "endpoint": "auth.session_extend",
        "rule": "/auth/session/extend",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "session",
        "csrf": "required",
        "rate_limit": "edge_auth",
        "step_up": "not_required",
        "public_justification": "",
    },
    "auth.terminate_session": {
        "endpoint": "auth.terminate_session",
        "rule": "/auth/sessions/<session_id>",
        "methods": {"DELETE"},
        "access": "authenticated",
        "classification": "session",
        "csrf": "required",
        "rate_limit": "edge_auth",
        "step_up": "not_required",
        "public_justification": "",
    },
    "auth.revoke_other_sessions": {
        "endpoint": "auth.revoke_other_sessions",
        "rule": "/auth/sessions/revoke-others",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "session",
        "csrf": "required",
        "rate_limit": "edge_auth",
        "step_up": "required",
        "public_justification": "",
    },
    "auth.freeze_account": {
        "endpoint": "auth.freeze_account",
        "rule": "/auth/account/freeze",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "account_freeze",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "public_justification": "",
    },
    "auth.password_change": {
        "endpoint": "auth.password_change",
        "rule": "/auth/password/change",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "password",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "public_justification": "",
    },
    "web.register_form": {
        "endpoint": "web.register_form",
        "rule": "/register",
        "methods": {"GET"},
        "access": "public",
        "classification": "registration",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "The registration form must be reachable before account creation.",
    },
    "web.register_otp_request": {
        "endpoint": "web.register_otp_request",
        "rule": "/register/otp/request",
        "methods": {"POST"},
        "access": "public",
        "classification": "registration",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Browser registration OTP requests must be reachable before account creation.",
    },
    "web.register_otp_verify": {
        "endpoint": "web.register_otp_verify",
        "rule": "/register/otp/verify",
        "methods": {"POST"},
        "access": "public",
        "classification": "registration",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Browser registration OTP verification must be reachable before account creation.",
    },
    "web.register_submit": {
        "endpoint": "web.register_submit",
        "rule": "/register",
        "methods": {"POST"},
        "access": "public",
        "classification": "registration",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Account creation must be reachable before authentication but requires a verified customer email OTP.",
    },
    "web.login": {
        "endpoint": "web.login",
        "rule": "/login",
        "methods": {"GET"},
        "access": "public",
        "classification": "login",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "Login form must be reachable before a user has a session.",
    },
    "web.login_submit": {
        "endpoint": "web.login_submit",
        "rule": "/login",
        "methods": {"POST"},
        "access": "public",
        "classification": "login",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Primary authentication must be reachable before a user has a session.",
    },
    "web.forgot_password": {
        "endpoint": "web.forgot_password",
        "rule": "/forgot-password",
        "methods": {"GET"},
        "access": "public",
        "classification": "password",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "Forgot-password form must be reachable before authentication.",
    },
    "web.forgot_password_submit": {
        "endpoint": "web.forgot_password_submit",
        "rule": "/forgot-password",
        "methods": {"POST"},
        "access": "public",
        "classification": "password",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Forgot-password submission must be reachable before authentication and returns a generic response.",
    },
    "web.reset_password_exchange": {
        "endpoint": "web.reset_password_exchange",
        "rule": "/reset-password",
        "methods": {"GET", "POST"},
        "access": "public",
        "classification": "password",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "reset_mfa",
        "public_justification": "GET renders a scanner-safe landing; CSRF-protected POST exchanges the one-time reset URL.",
    },
    "web.reset_password_continue": {
        "endpoint": "web.reset_password_continue",
        "rule": "/reset-password/continue",
        "methods": {"GET"},
        "access": "public",
        "classification": "password",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "reset_mfa",
        "public_justification": "The tokenless reset transaction page is scoped to reset cookie state before login.",
    },
    "web.reset_password_continue_submit": {
        "endpoint": "web.reset_password_continue_submit",
        "rule": "/reset-password/continue",
        "methods": {"POST"},
        "access": "public",
        "classification": "password",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "reset_mfa",
        "public_justification": "Reset MFA and password update submissions happen before a customer app session exists.",
    },
    "web.account_recovery": {
        "endpoint": "web.account_recovery",
        "rule": "/account-recovery",
        "methods": {"GET"},
        "access": "public",
        "classification": "account_recovery",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "Manual customer recovery request form must be reachable before authentication.",
    },
    "web.account_recovery_submit": {
        "endpoint": "web.account_recovery_submit",
        "rule": "/account-recovery",
        "methods": {"POST"},
        "access": "public",
        "classification": "account_recovery",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "Manual recovery submission creates only a pending request and must not change account state.",
    },
    "web.mfa_verify": {
        "endpoint": "web.mfa_verify",
        "rule": "/mfa/verify",
        "methods": {"GET"},
        "access": "public",
        "classification": "mfa",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "MFA form is reachable with a pending MFA session before full authentication.",
    },
    "web.mfa_verify_submit": {
        "endpoint": "web.mfa_verify_submit",
        "rule": "/mfa/verify",
        "methods": {"POST"},
        "access": "public",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "TOTP verification completes a pending login before a full user session exists.",
    },
    "web.dashboard": {
        "endpoint": "web.dashboard",
        "rule": "/dashboard",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "dashboard",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "web.security_keys": {
        "endpoint": "web.security_keys",
        "rule": "/security-keys",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "webauthn",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "web.security_keys_mfa_refresh": {
        "endpoint": "web.security_keys_mfa_refresh",
        "rule": "/security-keys/mfa/refresh",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "",
    },
    "web.security_key_revoke": {
        "endpoint": "web.security_key_revoke",
        "rule": "/security-keys/<credential_id>/revoke",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "webauthn",
        "csrf": "required",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "web.profile": {
        "endpoint": "web.profile",
        "rule": "/profile",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "profile",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "web.profile_submit": {
        "endpoint": "web.profile_submit",
        "rule": "/profile",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "profile",
        "csrf": "required",
        "rate_limit": "edge_app",
        "step_up": "required",
        "public_justification": "",
    },
    "web.mfa_setup": {
        "endpoint": "web.mfa_setup",
        "rule": "/mfa/setup",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "mfa",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "web.mfa_setup_submit": {
        "endpoint": "web.mfa_setup_submit",
        "rule": "/mfa/setup",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "mfa",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "conditional",
        "public_justification": "",
    },
    "web.password_change": {
        "endpoint": "web.password_change",
        "rule": "/password/change",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "password",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "web.password_change_submit": {
        "endpoint": "web.password_change_submit",
        "rule": "/password/change",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "password",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "public_justification": "",
    },
    "web.sessions_dashboard": {
        "endpoint": "web.sessions_dashboard",
        "rule": "/sessions",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "session",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "web.sessions_terminate_submit": {
        "endpoint": "web.sessions_terminate_submit",
        "rule": "/sessions/<session_ref>/terminate",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "session",
        "csrf": "required",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "web.sessions_revoke_others_submit": {
        "endpoint": "web.sessions_revoke_others_submit",
        "rule": "/sessions/revoke-others",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "session",
        "csrf": "required",
        "rate_limit": "edge_app",
        "step_up": "required",
        "public_justification": "",
    },
    "web.freeze_account": {
        "endpoint": "web.freeze_account",
        "rule": "/account/freeze",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "account_freeze",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "web.freeze_account_submit": {
        "endpoint": "web.freeze_account_submit",
        "rule": "/account/freeze",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "account_freeze",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "public_justification": "",
    },
    "web.logout": {
        "endpoint": "web.logout",
        "rule": "/logout",
        "methods": {"POST"},
        "access": "public",
        "classification": "logout",
        "csrf": "required",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "Logout is idempotent and clears only the caller's current session state.",
    },
    "banking.payees": {
        "endpoint": "banking.payees",
        "rule": "/banking/payees",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "payee_management",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "banking.payees_add": {
        "endpoint": "banking.payees_add",
        "rule": "/banking/payees/add",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "payee_management",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "banking.payees_add_submit": {
        "endpoint": "banking.payees_add_submit",
        "rule": "/banking/payees/add",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "payee_management",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "public_justification": "",
    },
    "banking.payees_confirm": {
        "endpoint": "banking.payees_confirm",
        "rule": "/banking/payees/confirm",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "payee_management",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "banking.payees_confirm_submit": {
        "endpoint": "banking.payees_confirm_submit",
        "rule": "/banking/payees/confirm",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "payee_management",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "already_authorized_continuation",
        "public_justification": "",
    },
    "banking.payees_remove": {
        "endpoint": "banking.payees_remove",
        "rule": "/banking/payees/<int:payee_id>/remove",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "payee_management",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "banking.payees_remove_submit": {
        "endpoint": "banking.payees_remove_submit",
        "rule": "/banking/payees/<int:payee_id>/remove",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "payee_management",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "public_justification": "",
    },
    "banking.transfer": {
        "endpoint": "banking.transfer",
        "rule": "/banking/transfer/<int:payee_id>",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "local_transfer",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "banking.transfer_submit": {
        "endpoint": "banking.transfer_submit",
        "rule": "/banking/transfer/<int:payee_id>",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "local_transfer",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "public_justification": "",
    },
    "banking.transfer_confirm": {
        "endpoint": "banking.transfer_confirm",
        "rule": "/banking/transfer/<int:payee_id>/confirm",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "local_transfer",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "already_authorized_continuation",
        "public_justification": "",
    },
    "banking.transfer_confirm_submit": {
        "endpoint": "banking.transfer_confirm_submit",
        "rule": "/banking/transfer/<int:payee_id>/confirm",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "local_transfer",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "already_authorized_continuation",
        "public_justification": "",
    },
    "banking.payup": {
        "endpoint": "banking.payup",
        "rule": "/banking/payup",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "payup_transfer",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "banking.payup_submit": {
        "endpoint": "banking.payup_submit",
        "rule": "/banking/payup",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "payup_transfer",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "public_justification": "",
    },
    "banking.payup_amount": {
        "endpoint": "banking.payup_amount",
        "rule": "/banking/payup/amount",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "payup_transfer",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "banking.payup_amount_submit": {
        "endpoint": "banking.payup_amount_submit",
        "rule": "/banking/payup/amount",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "payup_transfer",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "not_required",
        "public_justification": "",
    },
    "banking.payup_confirm": {
        "endpoint": "banking.payup_confirm",
        "rule": "/banking/payup/confirm",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "payup_transfer",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "banking.payup_confirm_submit": {
        "endpoint": "banking.payup_confirm_submit",
        "rule": "/banking/payup/confirm",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "payup_transfer",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "conditional",
        "public_justification": "",
    },
    "banking.transfer_limits": {
        "endpoint": "banking.transfer_limits",
        "rule": "/banking/settings/transfer-limits",
        "methods": {"GET"},
        "access": "authenticated",
        "classification": "transfer_limits",
        "csrf": "not_applicable",
        "rate_limit": "edge_app",
        "step_up": "not_required",
        "public_justification": "",
    },
    "banking.transfer_limits_submit": {
        "endpoint": "banking.transfer_limits_submit",
        "rule": "/banking/settings/transfer-limits",
        "methods": {"POST"},
        "access": "authenticated",
        "classification": "transfer_limits",
        "csrf": "required",
        "rate_limit": "per_route",
        "step_up": "required",
        "public_justification": "",
    },
}


def _actual_routes(app):
    routes = {}
    duplicate_routes = {}
    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        route = {
            "rule": rule.rule,
            "methods": set(rule.methods) - {"HEAD", "OPTIONS"},
        }
        if rule.endpoint in routes:
            duplicate_routes.setdefault(rule.endpoint, [routes[rule.endpoint]]).append(route)
            continue
        routes[rule.endpoint] = route
    assert not duplicate_routes, (
        "Route inventory keys by endpoint; model multiple rules explicitly "
        f"before reusing endpoint names: {duplicate_routes}"
    )
    return routes


def _decorator_name(decorator: ast.expr) -> str:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return ast.dump(target)


def _route_source_inventory():
    decorators = {}
    sources = {}
    for blueprint, path in ROUTE_MODULES.items():
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        tree = ast.parse(text)
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            names = {_decorator_name(decorator) for decorator in node.decorator_list}
            if names.intersection({"route", "get", "post", "put", "patch", "delete"}):
                endpoint = f"{blueprint}.{node.name}"
                decorators[endpoint] = names
                sources[endpoint] = "\n".join(lines[node.lineno - 1 : node.end_lineno])
    return decorators, sources


def test_route_inventory_matches_registered_flask_routes(app):
    actual = _actual_routes(app)
    expected = {
        endpoint: {
            "rule": entry["rule"],
            "methods": entry["methods"],
        }
        for endpoint, entry in ROUTE_SECURITY_INVENTORY.items()
    }

    assert actual == expected


def test_route_inventory_has_complete_security_decisions(app):
    actual = _actual_routes(app)
    decorators, sources = _route_source_inventory()

    for endpoint, entry in ROUTE_SECURITY_INVENTORY.items():
        assert entry["endpoint"] == endpoint
        assert entry["rule"] == actual[endpoint]["rule"]
        assert entry["methods"] == actual[endpoint]["methods"]
        assert entry["access"] in {"public", "authenticated"}
        assert entry["classification"]
        assert entry["rate_limit"] in RATE_LIMIT_DECISIONS
        assert entry["step_up"] in STEP_UP_DECISIONS

        route_decorators = decorators[endpoint]
        if entry["access"] == "authenticated":
            assert route_decorators.intersection(AUTH_DECORATORS), (
                f"{endpoint} is inventoried as authenticated but has no login decorator"
            )
            assert not entry["public_justification"]
        else:
            assert entry["public_justification"], f"{endpoint} needs a public route justification"
            assert not route_decorators.intersection(AUTH_DECORATORS), (
                f"{endpoint} is inventoried as public but has an auth decorator"
            )

        if entry["methods"].intersection(UNSAFE_METHODS):
            assert entry["csrf"] == "required", f"{endpoint} must have an unsafe-method CSRF decision"
            assert "exempt" not in route_decorators, f"{endpoint} must not be CSRF-exempt"
        else:
            assert entry["csrf"] == "not_applicable"

        if entry["classification"] in SENSITIVE_CLASSIFICATIONS:
            assert entry["rate_limit"] in RATE_LIMIT_DECISIONS, (
                f"{endpoint} is sensitive and needs an explicit rate-limit decision"
            )
        if entry["rate_limit"] == "per_route":
            assert "limit" in route_decorators, f"{endpoint} is expected to have Flask-Limiter decorators"

        source = sources[endpoint]
        if entry["step_up"] == "required":
            assert "stepup_token" in source or "verify_high_risk_authorization" in source, (
                f"{endpoint} is expected to require fresh MFA step-up"
            )
        if entry["step_up"] == "conditional":
            assert "stepup_token" in source, f"{endpoint} must document its conditional step-up branch"


def test_login_and_registration_have_method_level_security_decisions(app):
    actual = _actual_routes(app)

    assert actual["web.login"] == {"rule": "/login", "methods": {"GET"}}
    assert actual["web.login_submit"] == {"rule": "/login", "methods": {"POST"}}
    assert ROUTE_SECURITY_INVENTORY["web.login"]["csrf"] == "not_applicable"
    assert ROUTE_SECURITY_INVENTORY["web.login_submit"]["csrf"] == "required"
    assert ROUTE_SECURITY_INVENTORY["web.login_submit"]["rate_limit"] == "per_route"

    assert actual["web.register_form"] == {"rule": "/register", "methods": {"GET"}}
    assert actual["web.register_submit"] == {"rule": "/register", "methods": {"POST"}}
    assert ROUTE_SECURITY_INVENTORY["web.register_form"]["csrf"] == "not_applicable"
    assert ROUTE_SECURITY_INVENTORY["web.register_submit"]["csrf"] == "required"
    assert ROUTE_SECURITY_INVENTORY["web.register_submit"]["rate_limit"] == "per_route"
    assert "verified customer email OTP" in ROUTE_SECURITY_INVENTORY["web.register_submit"]["public_justification"]
