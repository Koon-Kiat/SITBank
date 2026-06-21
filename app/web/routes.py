from __future__ import annotations

from functools import wraps

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter.util import get_remote_address
from marshmallow import ValidationError

from app.auth.forms import (
    AuthenticationCodeForm,
    CsrfOnlyForm,
    ForgotPasswordForm,
    LoginForm,
    ManualRecoveryForm,
    MfaOrStepUpForm,
    PasswordChangeForm,
    PasswordResetForm,
    ProfileForm,
    RegisterForm,
    TotpForm,
)
from app.auth.password_reset import (
    complete_password_reset,
    current_reset_transaction,
    exchange_reset_token,
    request_manual_recovery,
    request_password_reset,
    verify_reset_totp,
)
from app.auth.schemas import TerminateSessionSchema
from app.auth.services import (
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
    pending_mfa_replacement,
    pending_mfa_setup,
    register_user,
    regenerate_totp_recovery_codes,
    terminate_other_sessions_for_user,
    terminate_session_for_user,
    update_profile_details,
    verify_fresh_mfa_for_action,
    verify_high_risk_authorization,
    verify_mfa_replacement,
    verify_mfa_setup,
)
from app.auth.webauthn_services import (
    list_credentials_for_user,
    revoke_credential,
    webauthn_credential_count,
)
from app.extensions import limiter
from app.auth.recovery_codes import RECOVERY_CODE_LOW_THRESHOLD, unused_recovery_code_count
from app.security.rate_limits import mfa_principal, request_principal
from app.security.sessions import (
    SESSION_RISK_REAUTH_REQUIRED_KEY,
    current_session_id,
    has_recent_fresh_mfa,
    public_session_reference,
    require_stable_session_for_sensitive_action,
)


web_bp = Blueprint("web", __name__)

WEB_MFA_ONBOARDING_ALLOWED_ENDPOINTS = {
    "web.forgot_password",
    "web.forgot_password_submit",
    "web.reset_password_exchange",
    "web.reset_password_continue",
    "web.reset_password_continue_submit",
    "web.account_recovery",
    "web.account_recovery_submit",
    "web.mfa_setup",
    "web.mfa_setup_submit",
    "web.logout",
}


@web_bp.before_request
def enforce_mfa_onboarding():
    user = getattr(g, "current_user", None)
    if user is None or user.mfa_enabled:
        return None
    if request.endpoint in WEB_MFA_ONBOARDING_ALLOWED_ENDPOINTS:
        return None
    flash("Set up authenticator MFA before continuing.", "warning")
    return redirect(url_for("web.mfa_setup"))


def web_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id") or getattr(g, "current_user", None) is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("web.login"))
        return view(*args, **kwargs)

    return wrapped


def web_not_frozen_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = getattr(g, "current_user", None)
        if user is not None and (user.is_frozen or user.security_locked_at is not None):
            flash("Account is frozen. This action is blocked pending review.", "error")
            return redirect(url_for("web.dashboard"))
        return view(*args, **kwargs)

    return wrapped


@web_bp.after_request
def prevent_sensitive_page_caching(response):
    if (
        session.get("user_id")
        or session.get("pending_mfa_user_id")
        or request.endpoint
        in {
            "web.forgot_password",
            "web.forgot_password_submit",
            "web.reset_password_exchange",
            "web.reset_password_continue",
            "web.reset_password_continue_submit",
            "web.account_recovery",
            "web.account_recovery_submit",
        }
    ):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@web_bp.get("/register")
def register_form():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("web.dashboard"))
    return render_template("register.html", form=RegisterForm())


@web_bp.post("/register")
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def register_submit():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("web.dashboard"))

    form = RegisterForm()
    if not form.validate_on_submit():
        return render_template("register.html", form=form), 400

    try:
        _user, warnings = register_user(
            {
                "username": form.username.data,
                "email": form.email.data,
                "password": form.password.data,
                "confirm_password": form.confirm_password.data,
            }
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template("register.html", form=form), exc.status_code

    for warning in warnings:
        flash(warning, "warning")
    flash("Registration successful. Please log in.", "success")
    return redirect(url_for("web.login"))


@web_bp.get("/login")
def login():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("web.dashboard"))
    return render_template("login.html", form=LoginForm())


@web_bp.post("/login")
@limiter.limit("50 per day", key_func=get_remote_address)
@limiter.limit("50 per day", key_func=request_principal)
@limiter.limit("5 per minute", key_func=get_remote_address)
@limiter.limit("5 per minute", key_func=request_principal)
def login_submit():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("web.dashboard"))

    form = LoginForm()
    if not form.validate_on_submit():
        return render_template("login.html", form=form), 400

    try:
        result = authenticate_primary(form.identifier.data, form.password.data)
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template("login.html", form=form), exc.status_code

    if result.get("mfa_required"):
        flash("Enter your authenticator code to finish signing in.", "info")
        return redirect(url_for("web.mfa_verify"))
    if result.get("mfa_setup_required"):
        flash("Set up authenticator MFA before continuing.", "warning")
        return redirect(url_for("web.mfa_setup"))

    flash("Login successful.", "success")
    return redirect(url_for("web.dashboard"))


@web_bp.get("/forgot-password")
def forgot_password():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("web.dashboard"))
    return render_template("forgot_password.html", form=ForgotPasswordForm())


@web_bp.post("/forgot-password")
@limiter.limit("5 per 15 minutes", key_func=get_remote_address)
@limiter.limit("5 per 15 minutes", key_func=request_principal)
def forgot_password_submit():
    form = ForgotPasswordForm()
    if not form.validate_on_submit():
        return render_template("forgot_password.html", form=form), 400
    result = request_password_reset(form.email.data)
    flash(result["message"], "success")
    return redirect(url_for("web.login"))


@web_bp.get("/reset-password")
@limiter.limit("10 per 15 minutes", key_func=get_remote_address)
def reset_password_exchange():
    token = request.args.get("token", "")
    try:
        exchange_reset_token(token)
    except AuthError as exc:
        flash(exc.message, "error")
        return redirect(url_for("web.forgot_password"))
    return redirect(url_for("web.reset_password_continue"))


@web_bp.get("/reset-password/continue")
def reset_password_continue():
    try:
        transaction = current_reset_transaction()
    except AuthError as exc:
        flash(exc.message, "error")
        return redirect(url_for("web.forgot_password"))
    return render_template(
        "reset_password.html",
        transaction=transaction,
        totp_form=AuthenticationCodeForm(),
        reset_form=PasswordResetForm(),
    )


@web_bp.post("/reset-password/continue")
@limiter.limit("5 per 15 minutes", key_func=get_remote_address)
@limiter.limit("5 per 15 minutes", key_func=mfa_principal)
def reset_password_continue_submit():
    action = request.form.get("action")
    try:
        transaction = current_reset_transaction()
    except AuthError as exc:
        flash(exc.message, "error")
        return redirect(url_for("web.forgot_password"))

    if action == "verify_totp":
        form = AuthenticationCodeForm()
        if not form.validate_on_submit():
            return _render_reset_continue(transaction, status_code=400)
        try:
            transaction = verify_reset_totp(form.totp_code.data)
        except AuthError as exc:
            flash(exc.message, "error")
            return _render_reset_continue(transaction, status_code=exc.status_code)
        flash("Authentication code verified.", "success")
        return _render_reset_continue(transaction)

    if action == "complete":
        form = PasswordResetForm()
        if not form.validate_on_submit():
            return _render_reset_continue(transaction, status_code=400)
        try:
            result = complete_password_reset(form.new_password.data, form.confirm_new_password.data)
        except AuthError as exc:
            flash(exc.message, "error")
            return _render_reset_continue(transaction, status_code=exc.status_code)
        for warning in result.get("warnings", []):
            flash(warning, "warning")
        flash(result["message"], "success")
        return redirect(url_for("web.login"))

    flash("Invalid password reset action.", "error")
    return _render_reset_continue(transaction, status_code=400)


def _render_reset_continue(transaction: dict, *, status_code: int = 200):
    return render_template(
        "reset_password.html",
        transaction=transaction,
        totp_form=AuthenticationCodeForm(),
        reset_form=PasswordResetForm(),
    ), status_code


@web_bp.get("/account-recovery")
def account_recovery():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("web.dashboard"))
    return render_template("account_recovery.html", form=ManualRecoveryForm())


@web_bp.post("/account-recovery")
@limiter.limit("3 per hour", key_func=get_remote_address)
@limiter.limit("3 per hour", key_func=request_principal)
def account_recovery_submit():
    form = ManualRecoveryForm()
    if not form.validate_on_submit():
        return render_template("account_recovery.html", form=form), 400
    result = request_manual_recovery(form.identifier.data)
    flash(result["message"], "success")
    return redirect(url_for("web.login"))


@web_bp.get("/mfa/verify")
def mfa_verify():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("web.dashboard"))
    if not session.get("pending_mfa_user_id"):
        flash("Please log in first.", "warning")
        return redirect(url_for("web.login"))
    return render_template("mfa_verify.html", form=AuthenticationCodeForm())


@web_bp.post("/mfa/verify")
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def mfa_verify_submit():
    if not session.get("pending_mfa_user_id"):
        flash("Please log in first.", "warning")
        return redirect(url_for("web.login"))

    form = AuthenticationCodeForm()
    if not form.validate_on_submit():
        return render_template("mfa_verify.html", form=form), 400

    try:
        complete_pending_mfa(form.totp_code.data)
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template("mfa_verify.html", form=form), exc.status_code

    flash("Login successful.", "success")
    return redirect(url_for("web.dashboard"))


@web_bp.get("/dashboard")
@web_login_required
def dashboard():
    recovery_codes_remaining = unused_recovery_code_count(g.current_user) if g.current_user.mfa_enabled else 0
    return render_template(
        "dashboard.html",
        user=g.current_user,
        credential_count=g.webauthn_credential_count,
        required_count=g.webauthn_required_count,
        recovery_codes_remaining=recovery_codes_remaining,
        recovery_codes_low=recovery_codes_remaining <= RECOVERY_CODE_LOW_THRESHOLD,
        logout_form=CsrfOnlyForm(),
    )


@web_bp.get("/security-keys")
@web_login_required
@web_not_frozen_required
def security_keys():
    credentials = list_credentials_for_user(g.current_user)
    required_count = current_app.config.get("WEBAUTHN_REQUIRED_CREDENTIALS", 1)
    return render_template(
        "security_keys.html",
        user=g.current_user,
        credentials=credentials,
        credential_count=webauthn_credential_count(g.current_user),
        required_count=required_count,
        recent_mfa=has_recent_fresh_mfa(),
        add_form=CsrfOnlyForm(),
        refresh_mfa_form=TotpForm(),
        revoke_form=MfaOrStepUpForm(),
    )


@web_bp.post("/security-keys/mfa/refresh")
@web_login_required
@web_not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def security_keys_mfa_refresh():
    if not g.current_user.mfa_enabled:
        flash("Set up authenticator MFA before registering passkeys.", "warning")
        return redirect(url_for("web.mfa_setup"))

    form = TotpForm()
    if not form.validate_on_submit():
        flash("Enter a valid authenticator code to continue.", "error")
        return redirect(url_for("web.security_keys"))

    try:
        require_stable_session_for_sensitive_action("webauthn_mfa_refresh")
        verify_fresh_mfa_for_action(
            g.current_user,
            form.totp_code.data,
            "webauthn_mfa_refresh",
        )
    except AuthError as exc:
        flash(exc.message, "error")
        if session.get(SESSION_RISK_REAUTH_REQUIRED_KEY):
            return redirect(url_for("web.login"))
        return redirect(url_for("web.security_keys"))

    flash("Authenticator code verified. You can register or manage passkeys now.", "success")
    return redirect(url_for("web.security_keys"))


@web_bp.post("/security-keys/<credential_id>/revoke")
@web_login_required
@web_not_frozen_required
def security_key_revoke(credential_id: str):
    form = MfaOrStepUpForm()
    if not form.validate_on_submit():
        flash("Complete MFA verification before revoking a passkey.", "error")
        return redirect(url_for("web.security_keys"))
    try:
        verify_high_risk_authorization(
            g.current_user,
            form.totp_code.data,
            form.stepup_token.data,
            "webauthn_revoke",
            rotate_session_on_success=False,
        )
        result = revoke_credential(
            g.current_user,
            credential_id,
            stepup_token=form.stepup_token.data,
            stepup_already_consumed=True,
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return redirect(url_for("web.security_keys"))
    if result.get("current_session_revoked"):
        flash("Security key revoked. Please sign in again.", "success")
        return redirect(url_for("web.login"))
    flash("Security key revoked.", "success")
    return redirect(url_for("web.security_keys"))


@web_bp.get("/profile")
@web_login_required
@web_not_frozen_required
def profile():
    form = ProfileForm()
    form.username.data = g.current_user.username
    form.email.data = g.current_user.email
    form.mfa_step_up_preference.data = g.current_user.mfa_step_up_preference
    return render_template(
        "profile.html",
        user=g.current_user,
        form=form,
        recent_mfa=has_recent_fresh_mfa(),
    )


@web_bp.post("/profile")
@web_login_required
@web_not_frozen_required
def profile_submit():
    form = ProfileForm()
    recent_mfa = has_recent_fresh_mfa()
    if not form.validate_on_submit():
        return render_template("profile.html", user=g.current_user, form=form, recent_mfa=recent_mfa), 400

    try:
        updated = update_profile_details(
            g.current_user,
            form.username.data,
            form.email.data,
            form.mfa_step_up_preference.data,
            form.totp_code.data,
            form.stepup_token.data,
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template("profile.html", user=g.current_user, form=form, recent_mfa=recent_mfa), exc.status_code

    flash("Profile updated." if updated else "No profile changes were needed.", "success")
    return redirect(url_for("web.profile"))


@web_bp.get("/mfa/setup")
@web_login_required
@web_not_frozen_required
def mfa_setup():
    setup = pending_mfa_setup(g.current_user)
    replacement = pending_mfa_replacement(g.current_user)
    recent_mfa = has_recent_fresh_mfa()
    recovery_codes_remaining = unused_recovery_code_count(g.current_user) if g.current_user.mfa_enabled else 0
    return render_template(
        "mfa_setup.html",
        user=g.current_user,
        setup=setup,
        replacement=replacement,
        recent_mfa=recent_mfa,
        recovery_codes=None,
        recovery_codes_remaining=recovery_codes_remaining,
        recovery_codes_low=recovery_codes_remaining <= RECOVERY_CODE_LOW_THRESHOLD,
        start_form=CsrfOnlyForm(),
        verify_form=TotpForm(),
        replace_start_form=MfaOrStepUpForm(),
        replace_verify_form=TotpForm(),
        recovery_regenerate_form=CsrfOnlyForm(),
    )


@web_bp.post("/mfa/setup")
@web_login_required
@web_not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def mfa_setup_submit():
    action = request.form.get("action")
    start_form = CsrfOnlyForm()
    verify_form = TotpForm()
    recent_mfa = has_recent_fresh_mfa()
    replace_start_form = MfaOrStepUpForm()
    replace_verify_form = TotpForm()
    recovery_regenerate_form = CsrfOnlyForm()

    def render_mfa_management(status_code: int = 200):
        recovery_codes_remaining = unused_recovery_code_count(g.current_user) if g.current_user.mfa_enabled else 0
        return render_template(
            "mfa_setup.html",
            user=g.current_user,
            setup=pending_mfa_setup(g.current_user),
            replacement=pending_mfa_replacement(g.current_user),
            recent_mfa=has_recent_fresh_mfa(),
            recovery_codes=None,
            recovery_codes_remaining=recovery_codes_remaining,
            recovery_codes_low=recovery_codes_remaining <= RECOVERY_CODE_LOW_THRESHOLD,
            start_form=start_form,
            verify_form=verify_form,
            replace_start_form=replace_start_form,
            replace_verify_form=replace_verify_form,
            recovery_regenerate_form=recovery_regenerate_form,
        ), status_code

    if action == "start":
        if not start_form.validate_on_submit():
            return render_mfa_management(400)
        try:
            setup = generate_mfa_setup(g.current_user)
        except AuthError as exc:
            flash(exc.message, "error")
            return redirect(url_for("web.dashboard"))
        flash("Scan the QR code, then enter the current code to enable MFA.", "info")
        return render_template(
            "mfa_setup.html",
            user=g.current_user,
            setup=setup,
            replacement=pending_mfa_replacement(g.current_user),
            recent_mfa=has_recent_fresh_mfa(),
            recovery_codes=None,
            recovery_codes_remaining=0,
            recovery_codes_low=False,
            start_form=CsrfOnlyForm(),
            verify_form=TotpForm(),
            replace_start_form=MfaOrStepUpForm(),
            replace_verify_form=TotpForm(),
            recovery_regenerate_form=CsrfOnlyForm(),
        )

    if action == "verify":
        if not verify_form.validate_on_submit():
            return render_mfa_management(400)
        try:
            result = verify_mfa_setup(g.current_user, verify_form.totp_code.data)
        except AuthError as exc:
            flash(exc.message, "error")
            return render_mfa_management(exc.status_code)
        flash("MFA is now enabled.", "success")
        return render_template(
            "mfa_setup.html",
            user=g.current_user,
            setup=None,
            replacement=None,
            recent_mfa=has_recent_fresh_mfa(),
            recovery_codes=result["recovery_codes"],
            recovery_codes_remaining=result["recovery_codes_remaining"],
            recovery_codes_low=result["recovery_codes_low"],
            start_form=CsrfOnlyForm(),
            verify_form=TotpForm(),
            replace_start_form=MfaOrStepUpForm(),
            replace_verify_form=TotpForm(),
            recovery_regenerate_form=CsrfOnlyForm(),
        )

    if action == "replace_start":
        if not replace_start_form.validate_on_submit():
            return render_mfa_management(400)
        try:
            replacement = generate_mfa_replacement(
                g.current_user,
                replace_start_form.totp_code.data,
                replace_start_form.stepup_token.data,
            )
        except AuthError as exc:
            flash(exc.message, "error")
            return render_mfa_management(exc.status_code)
        flash("Scan the replacement QR code, then verify the new authenticator code.", "info")
        return render_template(
            "mfa_setup.html",
            user=g.current_user,
            setup=pending_mfa_setup(g.current_user),
            replacement=replacement,
            recent_mfa=has_recent_fresh_mfa(),
            recovery_codes=None,
            recovery_codes_remaining=unused_recovery_code_count(g.current_user),
            recovery_codes_low=unused_recovery_code_count(g.current_user) <= RECOVERY_CODE_LOW_THRESHOLD,
            start_form=CsrfOnlyForm(),
            verify_form=TotpForm(),
            replace_start_form=MfaOrStepUpForm(),
            replace_verify_form=TotpForm(),
            recovery_regenerate_form=CsrfOnlyForm(),
        )

    if action == "replace_verify":
        if not replace_verify_form.validate_on_submit():
            return render_mfa_management(400)
        try:
            result = verify_mfa_replacement(g.current_user, replace_verify_form.totp_code.data)
        except AuthError as exc:
            flash(exc.message, "error")
            return render_mfa_management(exc.status_code)
        flash("Authenticator MFA replaced. Other sessions were revoked.", "success")
        return render_template(
            "mfa_setup.html",
            user=g.current_user,
            setup=None,
            replacement=None,
            recent_mfa=has_recent_fresh_mfa(),
            recovery_codes=result["recovery_codes"],
            recovery_codes_remaining=result["recovery_codes_remaining"],
            recovery_codes_low=result["recovery_codes_low"],
            start_form=CsrfOnlyForm(),
            verify_form=TotpForm(),
            replace_start_form=MfaOrStepUpForm(),
            replace_verify_form=TotpForm(),
            recovery_regenerate_form=CsrfOnlyForm(),
        )

    if action == "recovery_codes_regenerate":
        if not recovery_regenerate_form.validate_on_submit():
            return render_mfa_management(400)
        try:
            result = regenerate_totp_recovery_codes(g.current_user)
        except AuthError as exc:
            flash(exc.message, "error")
            return render_mfa_management(exc.status_code)
        flash("Recovery codes regenerated.", "success")
        return render_template(
            "mfa_setup.html",
            user=g.current_user,
            setup=None,
            replacement=pending_mfa_replacement(g.current_user),
            recent_mfa=has_recent_fresh_mfa(),
            recovery_codes=result["recovery_codes"],
            recovery_codes_remaining=result["recovery_codes_remaining"],
            recovery_codes_low=result["recovery_codes_low"],
            start_form=CsrfOnlyForm(),
            verify_form=TotpForm(),
            replace_start_form=MfaOrStepUpForm(),
            replace_verify_form=TotpForm(),
            recovery_regenerate_form=CsrfOnlyForm(),
        )

    flash("Invalid MFA setup action.", "error")
    return redirect(url_for("web.mfa_setup"))


@web_bp.get("/password/change")
@web_login_required
@web_not_frozen_required
def password_change():
    if not g.current_user.mfa_enabled:
        flash("Set up authenticator MFA before changing your password.", "warning")
        return redirect(url_for("web.mfa_setup"))
    return render_template(
        "password_change.html",
        form=PasswordChangeForm(),
        recent_mfa=has_recent_fresh_mfa(),
    )


@web_bp.post("/password/change")
@web_login_required
@web_not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def password_change_submit():
    if not g.current_user.mfa_enabled:
        flash("Set up authenticator MFA before changing your password.", "warning")
        return redirect(url_for("web.mfa_setup"))

    form = PasswordChangeForm()
    recent_mfa = has_recent_fresh_mfa()
    if not form.validate_on_submit():
        return render_template("password_change.html", form=form, recent_mfa=recent_mfa), 400

    try:
        result = change_password(
            g.current_user,
            form.current_password.data,
            form.new_password.data,
            form.confirm_new_password.data,
            form.totp_code.data,
            form.stepup_token.data,
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template("password_change.html", form=form, recent_mfa=recent_mfa), exc.status_code

    for warning in result.get("warnings", []):
        flash(warning, "warning")
    flash(f"Password changed. Terminated {result['revoked_other_sessions']} other session(s).", "success")
    return redirect(url_for("web.profile"))


@web_bp.get("/sessions")
@web_login_required
def sessions_dashboard():
    return render_template(
        "sessions.html",
        sessions=active_sessions_for_user(g.current_user),
        past_sessions=past_sessions_for_user(g.current_user),
        recent_mfa=has_recent_fresh_mfa(),
        revoke_others_csrf_form=CsrfOnlyForm(),
        revoke_others_form=MfaOrStepUpForm(),
        terminate_form=CsrfOnlyForm(),
    )


@web_bp.post("/sessions/<session_id>/terminate")
@web_login_required
@web_not_frozen_required
def terminate_session(session_id: str):
    form = CsrfOnlyForm()
    if not form.validate_on_submit():
        flash("Security token expired. Please try again.", "error")
        return redirect(url_for("web.sessions_dashboard"))

    try:
        TerminateSessionSchema().load({"session_id": session_id})
        current_sid = current_session_id()
        was_current = session_id == public_session_reference(current_sid)
        terminate_session_for_user(g.current_user, session_id)
    except (AuthError, ValidationError) as exc:
        message = exc.message if isinstance(exc, AuthError) else "Invalid session identifier."
        flash(message, "error")
        return redirect(url_for("web.sessions_dashboard"))

    if was_current:
        return redirect(url_for("web.login"))

    flash("Session terminated.", "success")
    return redirect(url_for("web.sessions_dashboard"))


@web_bp.post("/sessions/revoke-others")
@web_login_required
@web_not_frozen_required
def revoke_other_sessions():
    form = MfaOrStepUpForm()
    if not form.validate_on_submit():
        flash("Complete MFA or passkey step-up to terminate other sessions.", "error")
        return redirect(url_for("web.sessions_dashboard"))

    try:
        verify_high_risk_authorization(
            g.current_user,
            form.totp_code.data,
            form.stepup_token.data,
            "session_revoke_others",
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return redirect(url_for("web.sessions_dashboard"))

    revoked = terminate_other_sessions_for_user(g.current_user)
    flash(f"Terminated {revoked} other session(s).", "success")
    return redirect(url_for("web.sessions_dashboard"))


@web_bp.get("/account/freeze")
@web_login_required
@web_not_frozen_required
def freeze_account():
    return render_template("freeze.html", user=g.current_user, form=MfaOrStepUpForm())


@web_bp.post("/account/freeze")
@web_login_required
@web_not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def freeze_account_submit():
    form = MfaOrStepUpForm()
    if not form.validate_on_submit():
        return render_template("freeze.html", user=g.current_user, form=form), 400

    try:
        freeze_own_account(g.current_user, form.totp_code.data, form.stepup_token.data)
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template("freeze.html", user=g.current_user, form=form), exc.status_code

    flash("Account frozen. Unfreeze requires manual support review.", "success")
    return redirect(url_for("web.dashboard"))


@web_bp.post("/logout")
def logout():
    form = CsrfOnlyForm()
    if not form.validate_on_submit():
        flash("Security token expired. Please try again.", "error")
        return redirect(url_for("main.index"))

    logout_current_session()
    return redirect(url_for("web.login"))
