from __future__ import annotations

from flask import Blueprint, g, jsonify, request
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import generate_csrf
from marshmallow import Schema, ValidationError

from app.extensions import limiter
from app.security.rate_limits import mfa_principal, request_principal

from .decorators import login_required, not_frozen_required
from .forms import (
    CsrfOnlyForm,
    ForgotPasswordForm,
    LoginForm,
    ManualRecoveryForm,
    PasswordChangeForm,
    PasswordResetForm,
    RecoveryCodeForm,
    RegisterForm,
    StepUpTokenForm,
    TotpForm,
)
from .password_reset import (
    complete_password_reset,
    current_reset_transaction,
    request_manual_recovery,
    request_password_reset,
    reset_transaction_user_and_id,
    verify_recovery_code_for_reset,
    verify_reset_totp,
    exchange_reset_token,
)
from .schemas import (
    ForgotPasswordSchema,
    LoginSchema,
    ManualRecoverySchema,
    PasswordChangeSchema,
    PasswordResetSchema,
    RecoveryCodeSchema,
    RegisterSchema,
    ResetTokenExchangeSchema,
    StepUpTokenSchema,
    TerminateSessionSchema,
    TotpSchema,
)
from .schemas import (
    WebAuthnAuthenticationOptionsSchema,
    WebAuthnAuthenticationVerifySchema,
    WebAuthnCredentialReferenceSchema,
    WebAuthnRegistrationOptionsSchema,
    WebAuthnRegistrationVerifySchema,
    WebAuthnStepUpOptionsSchema,
    WebAuthnStepUpVerifySchema,
)
from .services import (
    AuthError,
    active_sessions_for_user,
    authenticate_primary,
    change_password,
    complete_pending_mfa,
    freeze_own_account,
    generate_mfa_replacement,
    generate_mfa_setup,
    logout_current_session,
    past_sessions_for_user,
    register_user,
    terminate_other_sessions_for_user,
    terminate_session_for_user,
    verify_high_risk_authorization,
    verify_mfa_replacement,
    verify_mfa_setup,
)
from .webauthn_services import (
    begin_step_up_options,
    begin_authentication_options,
    begin_password_reset_options,
    begin_registration_options,
    verify_step_up,
    list_credentials_for_user,
    revoke_credential,
    verify_authentication,
    verify_password_reset_assertion,
    verify_registration,
)


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

AUTH_MFA_ONBOARDING_ALLOWED_ENDPOINTS = {
    "auth.csrf_token",
    "auth.logout",
    "auth.mfa_setup",
    "auth.mfa_setup_verify",
    "auth.password_reset_request",
    "auth.password_reset_exchange",
    "auth.password_reset_transaction",
    "auth.password_reset_totp",
    "auth.password_reset_recovery_code",
    "auth.password_reset_webauthn_options",
    "auth.password_reset_webauthn_verify",
    "auth.password_reset_complete",
    "auth.manual_recovery_request",
}


@auth_bp.before_request
def enforce_api_mfa_onboarding():
    user = getattr(g, "current_user", None)
    if user is None or user.mfa_enabled:
        return None
    if request.endpoint in AUTH_MFA_ONBOARDING_ALLOWED_ENDPOINTS:
        return None
    return jsonify(
        {
            "error": "Authenticator MFA setup required",
            "code": "mfa_setup_required",
        }
    ), 403


def _load_payload(schema: Schema, form_cls) -> dict:
    if request.is_json:
        return schema.load(request.get_json(silent=False) or {})

    form = form_cls()
    if not form.validate_on_submit():
        raise ValidationError(form.errors)
    return {
        name: field.data
        for name, field in form._fields.items()
        if name != "csrf_token"
    }


@auth_bp.errorhandler(AuthError)
def handle_auth_error(error: AuthError):
    response = jsonify({"error": error.message})
    if error.retry_after is not None:
        response.headers["Retry-After"] = str(error.retry_after)
        response.headers["X-Auth-Retry-After"] = str(error.retry_after)
    return response, error.status_code


@auth_bp.errorhandler(ValidationError)
def handle_validation_error(error: ValidationError):
    return jsonify({"error": "Invalid request"}), 400


@auth_bp.get("/csrf-token")
def csrf_token():
    return jsonify({"csrf_token": generate_csrf()})


@auth_bp.post("/register")
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def register():
    data = _load_payload(RegisterSchema(), RegisterForm)
    user, warnings = register_user(data)
    return (
        jsonify(
            {
                "message": "Registration successful",
                "warnings": warnings,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "mfa_enabled": user.mfa_enabled,
                    "is_frozen": user.is_frozen,
                },
            }
        ),
        201,
    )


@auth_bp.post("/login")
@limiter.limit("50 per day", key_func=get_remote_address)
@limiter.limit("50 per day", key_func=request_principal)
@limiter.limit("5 per minute", key_func=get_remote_address)
@limiter.limit("5 per minute", key_func=request_principal)
def login():
    data = _load_payload(LoginSchema(), LoginForm)
    return jsonify(authenticate_primary(data["identifier"], data["password"]))


@auth_bp.post("/password-reset/request")
@limiter.limit("5 per 15 minutes", key_func=get_remote_address)
@limiter.limit("5 per 15 minutes", key_func=request_principal)
def password_reset_request():
    data = _load_payload(ForgotPasswordSchema(), ForgotPasswordForm)
    return jsonify(request_password_reset(data["email"]))


@auth_bp.post("/password-reset/exchange")
@limiter.limit("10 per 15 minutes", key_func=get_remote_address)
def password_reset_exchange():
    data = ResetTokenExchangeSchema().load(request.get_json(silent=False) or {})
    return jsonify(exchange_reset_token(data["token"]))


@auth_bp.get("/password-reset/transaction")
def password_reset_transaction():
    return jsonify(current_reset_transaction())


@auth_bp.post("/password-reset/mfa/totp")
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def password_reset_totp():
    data = _load_payload(TotpSchema(), TotpForm)
    return jsonify(verify_reset_totp(data["totp_code"]))


@auth_bp.post("/password-reset/mfa/recovery-code")
@limiter.limit("5 per 15 minutes", key_func=get_remote_address)
@limiter.limit("5 per 15 minutes", key_func=mfa_principal)
def password_reset_recovery_code():
    data = _load_payload(RecoveryCodeSchema(), RecoveryCodeForm)
    return jsonify(verify_recovery_code_for_reset(data["recovery_code"]))


@auth_bp.post("/password-reset/mfa/webauthn/options")
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def password_reset_webauthn_options():
    user, transaction_id = reset_transaction_user_and_id()
    return jsonify(begin_password_reset_options(user, transaction_id))


@auth_bp.post("/password-reset/mfa/webauthn/verify")
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def password_reset_webauthn_verify():
    user, transaction_id = reset_transaction_user_and_id()
    data = WebAuthnAuthenticationVerifySchema().load(request.get_json(silent=False) or {})
    return jsonify(verify_password_reset_assertion(user, transaction_id, data["credential"]))


@auth_bp.post("/password-reset/complete")
@limiter.limit("5 per 15 minutes", key_func=get_remote_address)
@limiter.limit("5 per 15 minutes", key_func=mfa_principal)
def password_reset_complete():
    data = _load_payload(PasswordResetSchema(), PasswordResetForm)
    return jsonify(complete_password_reset(data["new_password"], data["confirm_new_password"]))


@auth_bp.post("/account-recovery")
@limiter.limit("3 per hour", key_func=get_remote_address)
@limiter.limit("3 per hour", key_func=request_principal)
def manual_recovery_request():
    data = _load_payload(ManualRecoverySchema(), ManualRecoveryForm)
    return jsonify(request_manual_recovery(data["identifier"]))


@auth_bp.post("/webauthn/register/options")
@login_required
@not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def webauthn_register_options():
    data = WebAuthnRegistrationOptionsSchema().load(request.get_json(silent=False) or {})
    return jsonify(begin_registration_options(g.current_user, data["label"]))


@auth_bp.post("/webauthn/register/verify")
@login_required
@not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def webauthn_register_verify():
    data = WebAuthnRegistrationVerifySchema().load(request.get_json(silent=False) or {})
    return jsonify(verify_registration(g.current_user, data["credential"]))


@auth_bp.post("/webauthn/authenticate/options")
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def webauthn_authenticate_options():
    data = WebAuthnAuthenticationOptionsSchema().load(request.get_json(silent=False) or {})
    return jsonify(begin_authentication_options(data["identifier"]))


@auth_bp.post("/webauthn/authenticate/verify")
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def webauthn_authenticate_verify():
    data = WebAuthnAuthenticationVerifySchema().load(request.get_json(silent=False) or {})
    return jsonify(verify_authentication(data["credential"]))


@auth_bp.post("/webauthn/step-up/options")
@login_required
@not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def webauthn_step_up_options():
    data = WebAuthnStepUpOptionsSchema().load(request.get_json(silent=False) or {})
    return jsonify(begin_step_up_options(g.current_user, data["action"]))


@auth_bp.post("/webauthn/step-up/verify")
@login_required
@not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def webauthn_step_up_verify():
    data = WebAuthnStepUpVerifySchema().load(request.get_json(silent=False) or {})
    return jsonify(verify_step_up(g.current_user, data["action"], data["credential"]))


@auth_bp.get("/webauthn/credentials")
@login_required
def webauthn_credentials():
    return jsonify({"credentials": list_credentials_for_user(g.current_user)})


@auth_bp.delete("/webauthn/credentials/<credential_id>")
@login_required
@not_frozen_required
def webauthn_revoke_credential(credential_id: str):
    WebAuthnCredentialReferenceSchema().load({"credential_id": credential_id})
    payload = request.get_json(silent=True) or {}
    data = StepUpTokenSchema().load(payload)
    verify_high_risk_authorization(
        g.current_user,
        None,
        data.get("stepup_token"),
        "webauthn_revoke",
        rotate_session_on_success=False,
    )
    return jsonify(
        revoke_credential(
            g.current_user,
            credential_id,
            stepup_token=data.get("stepup_token"),
            stepup_already_consumed=True,
        )
    )


@auth_bp.post("/logout")
def logout():
    CsrfOnlyForm().validate()
    logout_current_session()
    return jsonify({"message": "Logged out"})


@auth_bp.post("/mfa/setup")
@login_required
@not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def mfa_setup():
    CsrfOnlyForm().validate()
    return jsonify(generate_mfa_setup(g.current_user))


@auth_bp.post("/mfa/setup/verify")
@login_required
@not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def mfa_setup_verify():
    data = _load_payload(TotpSchema(), TotpForm)
    return jsonify(verify_mfa_setup(g.current_user, data["totp_code"]))


@auth_bp.post("/mfa/replace/start")
@login_required
@not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def mfa_replace_start():
    data = StepUpTokenSchema().load(request.get_json(silent=False) or {})
    return jsonify(generate_mfa_replacement(g.current_user, None, data.get("stepup_token")))


@auth_bp.post("/mfa/replace/verify")
@login_required
@not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def mfa_replace_verify():
    data = _load_payload(TotpSchema(), TotpForm)
    return jsonify(verify_mfa_replacement(g.current_user, data["totp_code"]))


@auth_bp.post("/mfa/verify")
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def mfa_verify():
    data = _load_payload(TotpSchema(), TotpForm)
    return jsonify(complete_pending_mfa(data["totp_code"]))


@auth_bp.get("/sessions")
@login_required
def sessions_dashboard():
    return jsonify(
        {
            "sessions": active_sessions_for_user(g.current_user),
            "past_sessions": past_sessions_for_user(g.current_user),
        }
    )


@auth_bp.delete("/sessions/<session_id>")
@login_required
@not_frozen_required
def terminate_session(session_id: str):
    TerminateSessionSchema().load({"session_id": session_id})
    terminate_session_for_user(g.current_user, session_id)
    return jsonify({"message": "Session terminated"})


@auth_bp.post("/sessions/revoke-others")
@login_required
@not_frozen_required
def revoke_other_sessions():
    data = _load_payload(StepUpTokenSchema(), StepUpTokenForm)
    verify_high_risk_authorization(
        g.current_user,
        None,
        data.get("stepup_token"),
        "session_revoke_others",
    )
    revoked = terminate_other_sessions_for_user(g.current_user)
    return jsonify({"message": "Other sessions terminated", "revoked": revoked})


@auth_bp.post("/account/freeze")
@login_required
@not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def freeze_account():
    data = _load_payload(StepUpTokenSchema(), StepUpTokenForm)
    return jsonify(freeze_own_account(g.current_user, None, data.get("stepup_token")))


@auth_bp.post("/password/change")
@login_required
@not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def password_change():
    data = _load_payload(PasswordChangeSchema(), PasswordChangeForm)
    return jsonify(
        change_password(
            g.current_user,
            data["current_password"],
            data["new_password"],
            data["confirm_new_password"],
            None,
            data.get("stepup_token"),
        )
    )
