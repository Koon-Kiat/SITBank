from __future__ import annotations

from functools import wraps

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm

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
    RegisterDetailsForm,
    RegistrationOtpCodeForm,
    RegistrationOtpRequestForm,
    TotpForm,
)
from app.admin.services import is_customer_user
from app.auth.password_reset import (
    complete_password_reset,
    current_reset_transaction,
    exchange_reset_token,
    request_manual_recovery,
    request_password_reset,
    select_reset_mfa_method,
    verify_reset_totp,
    verify_reset_recovery_code,
)
from app.auth.mfa_policy import has_enrolled_mfa_method
from app.auth.registration_otp import (
    GENERIC_OTP_ERROR,
    RegistrationOtpError,
    VERIFY_CUSTOMER_EMAIL_MESSAGE,
    current_verified_registration_email,
    pending_registration_email,
    request_registration_otp,
    verify_registration_otp,
)
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
    pending_profile_email_change,
    register_user,
    regenerate_totp_recovery_codes,
    terminate_other_sessions_for_user,
    terminate_session_for_user,
    update_profile_details,
    verify_high_risk_authorization,
    verify_mfa_replacement,
    verify_mfa_setup,
)
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from app.banking.forms import TransactionDisputeForm
from app.extensions import db, limiter
from app.models import DISPUTE_OPEN_STATUSES, Transaction, TransactionDispute
from app.auth.recovery_codes import RECOVERY_CODE_LOW_THRESHOLD, unused_recovery_code_count
from app.security.audit import AuditWriteError, audit_event, audit_event_required, audit_reference
from app.security.rate_limits import (
    DurableRateLimitExceeded,
    consume_durable_rate_limit,
    mfa_principal,
    request_principal,
)
from app.security.http_errors import rate_limit_response
from app.security.sessions import (
    has_recent_fresh_mfa,
)
from app.security.turnstile import TurnstileError, require_turnstile


web_bp = Blueprint("web", __name__)

_FORGOT_PASSWORD_ENDPOINT = "web.forgot_password"
_RESET_PASSWORD_CONTINUE_ENDPOINT = "web.reset_password_continue"
_MFA_SETUP_ENDPOINT = "web.mfa_setup"
_LOGIN_ENDPOINT = "web.login"
_DASHBOARD_ENDPOINT = "web.dashboard"
_SESSIONS_ENDPOINT = "web.sessions_dashboard"
_MFA_VERIFY_TEMPLATE = "mfa_verify.html"
_MFA_SETUP_TEMPLATE = "mfa_setup.html"
_LOGIN_TEMPLATE = "login.html"
_FORGOT_PASSWORD_TEMPLATE = "forgot_password.html"
_PROFILE_TEMPLATE = "profile.html"
_PASSWORD_CHANGE_TEMPLATE = "password_change.html"
_FREEZE_TEMPLATE = "freeze.html"
_ACCOUNT_RECOVERY_TEMPLATE = "account_recovery.html"
_SECURITY_TOKEN_EXPIRED_MESSAGE = "Security token expired. Please try again."
_CHALLENGE_VERIFICATION_FAILED_MESSAGE = "Challenge verification failed"

WEB_MFA_ONBOARDING_ALLOWED_ENDPOINTS = {
    _FORGOT_PASSWORD_ENDPOINT,
    "web.forgot_password_submit",
    "web.reset_password_exchange",
    _RESET_PASSWORD_CONTINUE_ENDPOINT,
    "web.reset_password_continue_submit",
    "web.account_recovery",
    "web.account_recovery_submit",
    _MFA_SETUP_ENDPOINT,
    "web.mfa_setup_submit",
    "web.logout",
}


@web_bp.before_request
def enforce_mfa_onboarding():
    user = getattr(g, "current_user", None)
    if user is not None and not is_customer_user(user):
        session.clear()
        flash("Please log in with a customer account.", "warning")
        return redirect(url_for(_LOGIN_ENDPOINT))
    if user is None or has_enrolled_mfa_method(user):
        return None
    if request.endpoint in WEB_MFA_ONBOARDING_ALLOWED_ENDPOINTS:
        return None
    flash("Set up an authenticator app before continuing.", "warning")
    return redirect(url_for(_MFA_SETUP_ENDPOINT))


def web_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id") or getattr(g, "current_user", None) is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for(_LOGIN_ENDPOINT))
        if not is_customer_user(g.current_user):
            session.clear()
            flash("Please log in with a customer account.", "warning")
            return redirect(url_for(_LOGIN_ENDPOINT))
        return view(*args, **kwargs)

    return wrapped


def web_not_frozen_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = getattr(g, "current_user", None)
        if user is not None and (user.is_frozen or user.security_locked_at is not None):
            flash("Account is frozen. This action is blocked pending review.", "error")
            return redirect(url_for(_DASHBOARD_ENDPOINT))
        return view(*args, **kwargs)

    return wrapped


@web_bp.after_request
def prevent_sensitive_page_caching(response):
    if (
        session.get("user_id")
        or session.get("pending_mfa_user_id")
        or request.endpoint
        in {
            _FORGOT_PASSWORD_ENDPOINT,
            "web.forgot_password_submit",
            "web.reset_password_exchange",
            _RESET_PASSWORD_CONTINUE_ENDPOINT,
            "web.reset_password_continue_submit",
            "web.account_recovery",
            "web.account_recovery_submit",
            "web.register_form",
            "web.register_submit",
            "web.register_otp_request",
            "web.register_otp_verify",
        }
    ):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@web_bp.get("/register")
def register_form():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for(_DASHBOARD_ENDPOINT))
    verified_email = current_verified_registration_email()
    if verified_email:
        return _render_register_details_form(RegisterDetailsForm(), verified_email=verified_email)
    return _render_register_email_form()


@web_bp.post("/register/otp/request")
@limiter.limit("10 per hour", key_func=get_remote_address)
@limiter.limit("3 per 5 minutes", key_func=request_principal)
def register_otp_request():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for(_DASHBOARD_ENDPOINT))
    form = RegistrationOtpRequestForm()
    if not form.validate_on_submit():
        return _render_register_email_form(otp_request_form=form), 400
    try:
        require_turnstile("customer_register_otp")
        result = request_registration_otp(form.email.data)
    except TurnstileError:
        flash(_CHALLENGE_VERIFICATION_FAILED_MESSAGE, "error")
        return _render_register_email_form(otp_request_form=form), 400
    except RegistrationOtpError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return _render_register_email_form(otp_request_form=form, resend_cooldown=exc.retry_after if exc.status_code == 429 else None), exc.status_code
    flash(result["message"], "info")
    return _render_register_email_form(otp_request_form=form, resend_cooldown=60)


@web_bp.post("/register/otp/verify")
@limiter.limit("10 per hour", key_func=get_remote_address)
@limiter.limit("10 per 5 minutes", key_func=request_principal)
def register_otp_verify():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for(_DASHBOARD_ENDPOINT))
    form = RegistrationOtpCodeForm()
    request_form = RegistrationOtpRequestForm()
    pending_email = pending_registration_email()
    if pending_email:
        request_form.email.data = pending_email
    if not form.validate_on_submit():
        return _render_register_email_form(otp_request_form=request_form, otp_verify_form=form), 400
    if not pending_email:
        flash(GENERIC_OTP_ERROR, "error")
        return _render_register_email_form(otp_verify_form=form), 400
    try:
        result = verify_registration_otp(pending_email, form.otp_code.data)
    except RegistrationOtpError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return _render_register_email_form(otp_request_form=request_form, otp_verify_form=form), exc.status_code
    flash(result["message"], "success")
    return redirect(url_for("web.register_form"))


@web_bp.post("/register")
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=request_principal)
def register_submit():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for(_DASHBOARD_ENDPOINT))

    verified_email = current_verified_registration_email()
    if not verified_email:
        flash(VERIFY_CUSTOMER_EMAIL_MESSAGE, "error")
        return _render_register_email_form(), 400

    form = RegisterDetailsForm()
    if not form.validate_on_submit():
        return _render_register_details_form(form, verified_email=verified_email), 400

    try:
        require_turnstile("customer_register")
        _user, warnings = register_user(
            {
                "username": form.username.data,
                "full_name": form.full_name.data,
                "phone_number": form.phone_number.data,
                "password": form.password.data,
                "confirm_password": form.confirm_password.data,
            }
        )
    except TurnstileError:
        flash(_CHALLENGE_VERIFICATION_FAILED_MESSAGE, "error")
        return _render_register_details_form(form, verified_email=verified_email), 400
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        verified_email = current_verified_registration_email()
        if verified_email:
            return _render_register_details_form(form, verified_email=verified_email), exc.status_code
        return _render_register_email_form(), exc.status_code

    for warning in warnings:
        flash(warning, "warning")
    flash("Registration successful. Please log in.", "success")
    return redirect(url_for(_LOGIN_ENDPOINT))


def _render_register_email_form(
    *,
    otp_request_form: RegistrationOtpRequestForm | None = None,
    otp_verify_form: RegistrationOtpCodeForm | None = None,
    resend_cooldown: int | None = None,
):
    request_form = otp_request_form or RegistrationOtpRequestForm()
    if not request_form.email.data:
        request_form.email.data = pending_registration_email()
    return render_template(
        "register.html",
        step="email",
        form=None,
        verified_email=None,
        otp_request_form=request_form,
        otp_verify_form=otp_verify_form or RegistrationOtpCodeForm(),
        resend_cooldown=resend_cooldown or 0,
    )


def _render_register_details_form(
    form: RegisterDetailsForm,
    *,
    verified_email: str,
):
    return render_template(
        "register.html",
        step="details",
        form=form,
        verified_email=verified_email,
        otp_request_form=None,
        otp_verify_form=None,
    )


@web_bp.get("/login")
def login():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for(_DASHBOARD_ENDPOINT))
    if request.args.get("session_expired"):
        flash("Your session expired due to inactivity. Please log in again.", "warning")
    return render_template(_LOGIN_TEMPLATE, form=LoginForm())


@web_bp.post("/login")
@limiter.limit("50 per day", key_func=get_remote_address)
@limiter.limit("50 per day", key_func=request_principal)
@limiter.limit("5 per minute", key_func=get_remote_address)
@limiter.limit("5 per minute", key_func=request_principal)
def login_submit():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for(_DASHBOARD_ENDPOINT))

    form = LoginForm()
    if not form.validate_on_submit():
        return render_template(_LOGIN_TEMPLATE, form=form), 400

    try:
        require_turnstile("customer_login")
        result = authenticate_primary(form.identifier.data, form.password.data)
    except TurnstileError:
        flash(_CHALLENGE_VERIFICATION_FAILED_MESSAGE, "error")
        return render_template(_LOGIN_TEMPLATE, form=form), 400
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return render_template(_LOGIN_TEMPLATE, form=form), exc.status_code

    if result.get("mfa_required"):
        flash("Enter your authenticator code to finish signing in.", "info")
        return redirect(url_for("web.mfa_verify"))
    if result.get("mfa_setup_required"):
        flash("Set up authenticator MFA before continuing.", "warning")
        return redirect(url_for(_MFA_SETUP_ENDPOINT))

    flash("Login successful.", "success")
    return redirect(url_for(_DASHBOARD_ENDPOINT))


@web_bp.get("/forgot-password")
def forgot_password():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for(_DASHBOARD_ENDPOINT))
    return render_template(_FORGOT_PASSWORD_TEMPLATE, form=ForgotPasswordForm())


@web_bp.post("/forgot-password")
@limiter.limit("5 per 15 minutes", key_func=get_remote_address)
@limiter.limit("5 per 15 minutes", key_func=request_principal)
def forgot_password_submit():
    form = ForgotPasswordForm()
    if not form.validate_on_submit():
        return render_template(_FORGOT_PASSWORD_TEMPLATE, form=form), 400
    try:
        require_turnstile("customer_password_reset")
        result = request_password_reset(form.email.data)
    except TurnstileError:
        flash(_CHALLENGE_VERIFICATION_FAILED_MESSAGE, "error")
        return render_template(_FORGOT_PASSWORD_TEMPLATE, form=form), 400
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return render_template(_FORGOT_PASSWORD_TEMPLATE, form=form), exc.status_code
    flash(result["message"], "success")
    return redirect(url_for(_LOGIN_ENDPOINT))


@web_bp.route("/reset-password", methods=["GET", "POST"])
@limiter.limit("10 per 15 minutes", key_func=get_remote_address)
def reset_password_exchange():
    if request.method == "GET":
        return render_template(
            "reset_password_landing.html",
            form=CsrfOnlyForm(),
            token=request.args.get("token", ""),
        )
    form = CsrfOnlyForm()
    if not form.validate_on_submit():
        flash(_SECURITY_TOKEN_EXPIRED_MESSAGE, "error")
        return render_template(
            "reset_password_landing.html",
            form=form,
            token=request.form.get("token", ""),
        ), 400
    token = request.form.get("token", "")
    try:
        exchange_reset_token(token)
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return redirect(url_for(_FORGOT_PASSWORD_ENDPOINT))
    return redirect(url_for(_RESET_PASSWORD_CONTINUE_ENDPOINT))


@web_bp.get("/reset-password/continue")
def reset_password_continue():
    try:
        transaction = current_reset_transaction()
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return redirect(url_for(_FORGOT_PASSWORD_ENDPOINT))
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
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return redirect(url_for(_FORGOT_PASSWORD_ENDPOINT))

    handlers = {
        "verify_totp": _handle_reset_totp,
        "verify_recovery_code": _handle_reset_recovery_code,
        "select_mfa_method": _handle_reset_mfa_selection,
        "complete": _handle_reset_completion,
    }
    handler = handlers.get(action)
    if handler is not None:
        return handler(transaction)
    flash("Invalid password reset action.", "error")
    return _render_reset_continue(transaction, status_code=400)


def _handle_reset_totp(transaction: dict):
    form = AuthenticationCodeForm()
    if not form.validate_on_submit():
        return _render_reset_continue(transaction, status_code=400)
    try:
        transaction = verify_reset_totp(form.totp_code.data)
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return _render_reset_continue(transaction, status_code=exc.status_code)
    flash("Authentication code verified.", "success")
    return _render_reset_continue(transaction)


def _handle_reset_recovery_code(transaction: dict):
    form = AuthenticationCodeForm()
    if not form.validate_on_submit():
        return _render_reset_continue(transaction, status_code=400)
    try:
        transaction = verify_reset_recovery_code(form.totp_code.data)
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return _render_reset_continue(transaction, status_code=exc.status_code)
    flash("Recovery code verified.", "success")
    return _render_reset_continue(transaction)


def _handle_reset_mfa_selection(transaction: dict):
    form = CsrfOnlyForm()
    if not form.validate_on_submit():
        return _render_reset_continue(transaction, status_code=400)
    try:
        transaction = select_reset_mfa_method(request.form.get("mfa_method", ""))
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return _render_reset_continue(transaction, status_code=exc.status_code)
    flash("Verification method selected.", "success")
    return _render_reset_continue(transaction)


def _handle_reset_completion(transaction: dict):
    form = PasswordResetForm()
    if not form.validate_on_submit():
        return _render_reset_continue(transaction, status_code=400)
    try:
        result = complete_password_reset(
            form.new_password.data,
            form.confirm_new_password.data,
        )
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return _render_reset_continue(transaction, status_code=exc.status_code)
    for warning in result.get("warnings", []):
        flash(warning, "warning")
    flash(result["message"], "success")
    return redirect(url_for(_LOGIN_ENDPOINT))


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
        return redirect(url_for(_DASHBOARD_ENDPOINT))
    return render_template(_ACCOUNT_RECOVERY_TEMPLATE, form=ManualRecoveryForm())


@web_bp.post("/account-recovery")
@limiter.limit("3 per hour", key_func=get_remote_address)
@limiter.limit("3 per hour", key_func=request_principal)
def account_recovery_submit():
    form = ManualRecoveryForm()
    if not form.validate_on_submit():
        return render_template(_ACCOUNT_RECOVERY_TEMPLATE, form=form), 400
    try:
        require_turnstile("customer_manual_recovery")
        result = request_manual_recovery(form.identifier.data)
    except TurnstileError:
        flash(_CHALLENGE_VERIFICATION_FAILED_MESSAGE, "error")
        return render_template(_ACCOUNT_RECOVERY_TEMPLATE, form=form), 400
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return render_template(_ACCOUNT_RECOVERY_TEMPLATE, form=form), exc.status_code
    flash(result["message"], "success")
    return redirect(url_for(_LOGIN_ENDPOINT))


@web_bp.get("/mfa/verify")
def mfa_verify():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for(_DASHBOARD_ENDPOINT))
    if not session.get("pending_mfa_user_id"):
        flash("Please log in first.", "warning")
        return redirect(url_for(_LOGIN_ENDPOINT))
    return render_template(
        _MFA_VERIFY_TEMPLATE,
        form=AuthenticationCodeForm(),
    )


@web_bp.post("/mfa/verify")
@limiter.limit("30 per 5 minutes", key_func=get_remote_address)
@limiter.limit("30 per 5 minutes", key_func=mfa_principal)
def mfa_verify_submit():
    if not session.get("pending_mfa_user_id"):
        flash("Please log in first.", "warning")
        return redirect(url_for(_LOGIN_ENDPOINT))

    form = AuthenticationCodeForm()
    if not form.validate_on_submit():
        return render_template(_MFA_VERIFY_TEMPLATE, form=form), 400

    try:
        complete_pending_mfa(form.totp_code.data)
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return render_template(_MFA_VERIFY_TEMPLATE, form=form), exc.status_code

    flash("Login successful.", "success")
    return redirect(url_for(_DASHBOARD_ENDPOINT))


@web_bp.get("/dashboard")
@web_login_required
def dashboard():
    recent_txns = (
        db.session.execute(
            db.select(Transaction)
            .where(
                or_(
                    Transaction.sender_id == g.current_user.id,
                    Transaction.recipient_id == g.current_user.id,
                )
            )
            .order_by(Transaction.created_at.desc())
            .limit(5)
        )
        .scalars()
        .all()
    )
    return render_template(
        "dashboard.html",
        user=g.current_user,
        logout_form=CsrfOnlyForm(),
        transactions=recent_txns,
    )


_TRANSACTIONS_PER_PAGE = 20


def _bounded_page(value) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = 1
    return min(max(parsed, 1), 100000)


def _owned_transactions_statement():
    return db.select(Transaction).where(
        or_(
            Transaction.sender_id == g.current_user.id,
            Transaction.recipient_id == g.current_user.id,
        )
    )


@web_bp.get("/transactions")
@web_login_required
def transactions():
    page = _bounded_page(request.args.get("page"))
    statement = _owned_transactions_statement().order_by(
        Transaction.created_at.desc(), Transaction.id.desc()
    )
    total = db.session.execute(db.select(func.count()).select_from(statement.subquery())).scalar_one()
    txns = (
        db.session.execute(
            statement.limit(_TRANSACTIONS_PER_PAGE).offset((page - 1) * _TRANSACTIONS_PER_PAGE)
        )
        .scalars()
        .all()
    )
    total_pages = max(1, (int(total or 0) + _TRANSACTIONS_PER_PAGE - 1) // _TRANSACTIONS_PER_PAGE)
    return render_template(
        "transactions.html",
        user=g.current_user,
        transactions=txns,
        page=page,
        total_pages=total_pages,
    )


@web_bp.get("/transactions/<int:transaction_id>")
@web_login_required
def transaction_detail(transaction_id: int):
    # Ownership check — prevents IDOR
    txn = Transaction.query.filter(
        Transaction.id == transaction_id,
        or_(
            Transaction.sender_id == g.current_user.id,
            Transaction.recipient_id == g.current_user.id,
        ),
    ).first_or_404()
    my_disputes = (
        db.session.execute(
            db.select(TransactionDispute)
            .where(
                TransactionDispute.transaction_id == txn.id,
                TransactionDispute.reporter_id == g.current_user.id,
            )
            .order_by(TransactionDispute.created_at.desc())
        )
        .scalars()
        .all()
    )
    # Checked transaction-wide (not just this viewer's own reports) so the "Report an
    # Issue" link is hidden whenever a submission would be blocked server-side,
    # regardless of which party on the transaction filed the open dispute.
    has_open_dispute = _open_dispute_for_transaction(txn.id) is not None
    return render_template(
        "transaction_detail.html",
        user=g.current_user,
        transaction=txn,
        disputes=my_disputes,
        has_open_dispute=has_open_dispute,
    )


_DISPUTE_ALREADY_OPEN_MESSAGE = "An open issue report already exists for this transaction."
_DISPUTE_FORM_TEMPLATE = "transaction_dispute_form.html"
_TRANSACTION_DETAIL_ENDPOINT = "web.transaction_detail"


def _owned_transaction_or_404(transaction_id: int) -> Transaction:
    return Transaction.query.filter(
        Transaction.id == transaction_id,
        or_(
            Transaction.sender_id == g.current_user.id,
            Transaction.recipient_id == g.current_user.id,
        ),
    ).first_or_404()


def _open_dispute_for_transaction(transaction_id: int) -> TransactionDispute | None:
    return db.session.execute(
        db.select(TransactionDispute).where(
            TransactionDispute.transaction_id == transaction_id,
            TransactionDispute.status.in_(DISPUTE_OPEN_STATUSES),
        )
    ).scalar_one_or_none()


@web_bp.get("/transactions/<int:transaction_id>/dispute")
@web_login_required
@web_not_frozen_required
def transaction_dispute_new(transaction_id: int):
    # Ownership check — prevents IDOR
    txn = _owned_transaction_or_404(transaction_id)
    if _open_dispute_for_transaction(txn.id) is not None:
        flash(_DISPUTE_ALREADY_OPEN_MESSAGE, "warning")
        return redirect(url_for(_TRANSACTION_DETAIL_ENDPOINT, transaction_id=txn.id))
    form = TransactionDisputeForm()
    return render_template(_DISPUTE_FORM_TEMPLATE, form=form, transaction=txn)


@web_bp.post("/transactions/<int:transaction_id>/dispute")
@limiter.limit("10 per hour", key_func=mfa_principal)
@web_login_required
@web_not_frozen_required
def transaction_dispute_create(transaction_id: int):
    # A01: ownership re-checked independently of the GET step
    txn = _owned_transaction_or_404(transaction_id)
    form = TransactionDisputeForm()
    if not form.validate_on_submit():
        return render_template(_DISPUTE_FORM_TEMPLATE, form=form, transaction=txn), 400

    if _open_dispute_for_transaction(txn.id) is not None:
        flash(_DISPUTE_ALREADY_OPEN_MESSAGE, "warning")
        return redirect(url_for(_TRANSACTION_DETAIL_ENDPOINT, transaction_id=txn.id))

    try:
        consume_durable_rate_limit(
            "transaction_dispute_create",
            f"user:{g.current_user.id}",
            limit=5,
            window_seconds=24 * 60 * 60,
        )
    except DurableRateLimitExceeded as exc:
        audit_event(
            "transaction_dispute_create",
            "blocked",
            user=g.current_user,
            metadata={"reason": "durable_rate_limit", "retry_after": exc.retry_after},
        )
        flash("Too many issue reports submitted today. Please try again tomorrow.", "error")
        return redirect(url_for(_TRANSACTION_DETAIL_ENDPOINT, transaction_id=txn.id))

    dispute = TransactionDispute(
        transaction_id=txn.id,
        reporter_id=g.current_user.id,
        issue_type=form.issue_type.data,
        reason=form.reason.data.strip(),
        status="open",
    )
    try:
        db.session.add(dispute)
        db.session.flush([dispute])
        audit_event_required(
            "transaction_dispute_create",
            "success",
            user=g.current_user,
            metadata={
                "transaction_ref": audit_reference("transaction", txn.transaction_ref),
                "issue_type": dispute.issue_type,
                "reason_length": len(dispute.reason),
            },
        )
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash(_DISPUTE_ALREADY_OPEN_MESSAGE, "warning")
        return redirect(url_for(_TRANSACTION_DETAIL_ENDPOINT, transaction_id=txn.id))
    except AuditWriteError:
        db.session.rollback()
        raise

    flash("Issue reported. Our staff will review it shortly.", "success")
    return redirect(url_for(_TRANSACTION_DETAIL_ENDPOINT, transaction_id=txn.id))


@web_bp.get("/disputes")
@web_login_required
def my_disputes():
    disputes = (
        db.session.execute(
            db.select(TransactionDispute)
            .where(TransactionDispute.reporter_id == g.current_user.id)
            .order_by(TransactionDispute.created_at.desc())
        )
        .scalars()
        .all()
    )
    return render_template("my_disputes.html", disputes=disputes)


@web_bp.get("/profile")
@web_login_required
@web_not_frozen_required
def profile():
    form = ProfileForm()
    pending_email_change = pending_profile_email_change()
    form.email.data = pending_email_change["email"] if pending_email_change else g.current_user.email
    form.phone_number.data = g.current_user.phone_number
    return render_template(
        _PROFILE_TEMPLATE,
        user=g.current_user,
        form=form,
        recent_mfa=has_recent_fresh_mfa(),
        pending_email_change=pending_email_change,
    )


@web_bp.post("/profile")
@web_login_required
@web_not_frozen_required
def profile_submit():
    form = ProfileForm()
    recent_mfa = has_recent_fresh_mfa()
    pending_email_change = pending_profile_email_change()
    if not form.validate_on_submit():
        return render_template(
            _PROFILE_TEMPLATE,
            user=g.current_user,
            form=form,
            recent_mfa=recent_mfa,
            pending_email_change=pending_email_change,
        ), 400

    try:
        result = update_profile_details(
            g.current_user,
            g.current_user.username,
            form.email.data,
            form.phone_number.data,
            form.totp_code.data,
            form.email_verification_code.data,
        )
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return render_template(
            _PROFILE_TEMPLATE,
            user=g.current_user,
            form=form,
            recent_mfa=recent_mfa,
            pending_email_change=pending_profile_email_change(),
        ), exc.status_code

    if result.get("email_verification_pending"):
        flash("Verification code sent to the new email address.", "info")
        return render_template(
            _PROFILE_TEMPLATE,
            user=g.current_user,
            form=form,
            recent_mfa=has_recent_fresh_mfa(),
            pending_email_change=pending_profile_email_change(),
        )
    flash("Profile updated." if result.get("updated") else "No profile changes were needed.", "success")
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
        _MFA_SETUP_TEMPLATE,
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
        recovery_regenerate_form=MfaOrStepUpForm(),
    )


@web_bp.post("/mfa/setup")
@web_login_required
@web_not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def mfa_setup_submit():
    """Dispatch authenticator MFA management actions."""
    action = request.form.get("action")
    forms = _mfa_management_forms()
    handlers = {
        "start": _handle_mfa_setup_start,
        "verify": _handle_mfa_setup_verify,
        "replace_start": _handle_mfa_replace_start,
        "replace_verify": _handle_mfa_replace_verify,
        "recovery_codes_regenerate": _handle_recovery_code_regeneration,
    }
    handler = handlers.get(action)
    if handler is not None:
        return handler(forms)
    flash("Invalid MFA setup action.", "error")
    return redirect(url_for(_MFA_SETUP_ENDPOINT))


def _mfa_management_forms() -> dict[str, FlaskForm]:
    return {
        "start": CsrfOnlyForm(),
        "verify": TotpForm(),
        "replace_start": MfaOrStepUpForm(),
        "replace_verify": TotpForm(),
        "recovery_regenerate": MfaOrStepUpForm(),
    }


def _render_mfa_management(
    forms: dict[str, FlaskForm],
    *,
    status_code: int = 200,
    setup=None,
    replacement=None,
    recovery_codes=None,
    recovery_codes_remaining: int | None = None,
):
    if setup is None:
        setup = pending_mfa_setup(g.current_user)
    if replacement is None:
        replacement = pending_mfa_replacement(g.current_user)
    if recovery_codes_remaining is None:
        recovery_codes_remaining = (
            unused_recovery_code_count(g.current_user)
            if g.current_user.mfa_enabled
            else 0
        )
    return (
        render_template(
            _MFA_SETUP_TEMPLATE,
            user=g.current_user,
            setup=setup,
            replacement=replacement,
            recent_mfa=has_recent_fresh_mfa(),
            recovery_codes=recovery_codes,
            recovery_codes_remaining=recovery_codes_remaining,
            recovery_codes_low=(
                recovery_codes_remaining <= RECOVERY_CODE_LOW_THRESHOLD
            ),
            start_form=forms["start"],
            verify_form=forms["verify"],
            replace_start_form=forms["replace_start"],
            replace_verify_form=forms["replace_verify"],
            recovery_regenerate_form=forms["recovery_regenerate"],
        ),
        status_code,
    )


def _handle_mfa_setup_start(forms: dict[str, FlaskForm]):
    if not forms["start"].validate_on_submit():
        return _render_mfa_management(forms, status_code=400)
    try:
        setup = generate_mfa_setup(g.current_user)
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return redirect(url_for(_DASHBOARD_ENDPOINT))
    flash("Scan the QR code, then enter the current code to enable MFA.", "info")
    return _render_mfa_management(
        _mfa_management_forms(),
        setup=setup,
        recovery_codes_remaining=0,
    )


def _handle_mfa_setup_verify(forms: dict[str, FlaskForm]):
    verify_form = forms["verify"]
    if not verify_form.validate_on_submit():
        return _render_mfa_management(forms, status_code=400)
    try:
        result = verify_mfa_setup(g.current_user, verify_form.totp_code.data)
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return _render_mfa_management(forms, status_code=exc.status_code)
    flash("MFA is now enabled.", "success")
    return _render_mfa_result(result)


def _handle_mfa_replace_start(forms: dict[str, FlaskForm]):
    replace_form = forms["replace_start"]
    if not replace_form.validate_on_submit():
        return _render_mfa_management(forms, status_code=400)
    try:
        replacement = generate_mfa_replacement(
            g.current_user,
            replace_form.totp_code.data,
        )
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return _render_mfa_management(forms, status_code=exc.status_code)
    flash("Scan the replacement QR code, then verify the new authenticator code.", "info")
    return _render_mfa_management(
        _mfa_management_forms(),
        replacement=replacement,
    )


def _handle_mfa_replace_verify(forms: dict[str, FlaskForm]):
    verify_form = forms["replace_verify"]
    if not verify_form.validate_on_submit():
        return _render_mfa_management(forms, status_code=400)
    try:
        result = verify_mfa_replacement(g.current_user, verify_form.totp_code.data)
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return _render_mfa_management(forms, status_code=exc.status_code)
    flash("Authenticator MFA replaced. Other sessions were revoked.", "success")
    return _render_mfa_result(result)


def _handle_recovery_code_regeneration(forms: dict[str, FlaskForm]):
    if not CsrfOnlyForm().validate_on_submit():
        return _render_mfa_management(forms, status_code=400)
    regenerate_form = forms["recovery_regenerate"]
    try:
        result = regenerate_totp_recovery_codes(
            g.current_user,
            regenerate_form.totp_code.data,
        )
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return _render_mfa_management(forms, status_code=exc.status_code)
    flash("Recovery codes regenerated.", "success")
    return _render_mfa_result(
        result,
        replacement=pending_mfa_replacement(g.current_user),
    )


def _render_mfa_result(result: dict, *, replacement=None):
    return _render_mfa_management(
        _mfa_management_forms(),
        setup=False,
        replacement=replacement or False,
        recovery_codes=result["recovery_codes"],
        recovery_codes_remaining=result["recovery_codes_remaining"],
    )


@web_bp.get("/password/change")
@web_login_required
@web_not_frozen_required
def password_change():
    if not has_enrolled_mfa_method(g.current_user):
        flash("Set up MFA before changing your password.", "warning")
        return redirect(url_for(_MFA_SETUP_ENDPOINT))
    return render_template(
        _PASSWORD_CHANGE_TEMPLATE,
        form=PasswordChangeForm(),
        recent_mfa=has_recent_fresh_mfa(),
    )


@web_bp.post("/password/change")
@web_login_required
@web_not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def password_change_submit():
    if not has_enrolled_mfa_method(g.current_user):
        flash("Set up MFA before changing your password.", "warning")
        return redirect(url_for(_MFA_SETUP_ENDPOINT))

    form = PasswordChangeForm()
    recent_mfa = has_recent_fresh_mfa()
    if not form.validate_on_submit():
        return render_template(_PASSWORD_CHANGE_TEMPLATE, form=form, recent_mfa=recent_mfa), 400

    try:
        result = change_password(
            g.current_user,
            form.current_password.data,
            form.new_password.data,
            form.confirm_new_password.data,
            form.totp_code.data,
        )
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return render_template(_PASSWORD_CHANGE_TEMPLATE, form=form, recent_mfa=recent_mfa), exc.status_code

    for warning in result.get("warnings", []):
        flash(warning, "warning")
    flash("Password changed. Please log in again.", "success")
    return redirect(url_for(_LOGIN_ENDPOINT))


@web_bp.get("/sessions")
@web_login_required
def sessions_dashboard():
    return render_template(
        "sessions.html",
        sessions=active_sessions_for_user(g.current_user),
        past_sessions=past_sessions_for_user(g.current_user),
    )


@web_bp.post("/sessions/<session_ref>/terminate")
@web_login_required
@web_not_frozen_required
def sessions_terminate_submit(session_ref: str):
    if any(
        item["current"] and item["session_ref"] == session_ref
        for item in active_sessions_for_user(g.current_user)
    ):
        flash("Use Log Out to end the current browser session.", "warning")
        return redirect(url_for(_SESSIONS_ENDPOINT))
    form = CsrfOnlyForm()
    if not form.validate_on_submit():
        flash(_SECURITY_TOKEN_EXPIRED_MESSAGE, "error")
        return redirect(url_for(_SESSIONS_ENDPOINT))
    try:
        terminate_session_for_user(g.current_user, session_ref)
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return redirect(url_for(_SESSIONS_ENDPOINT)), exc.status_code
    flash("Session terminated.", "success")
    return redirect(url_for(_SESSIONS_ENDPOINT))


@web_bp.post("/sessions/revoke-others")
@web_login_required
@web_not_frozen_required
def sessions_revoke_others_submit():
    form = MfaOrStepUpForm()
    if not form.validate_on_submit():
        flash(_SECURITY_TOKEN_EXPIRED_MESSAGE, "error")
        return redirect(url_for(_SESSIONS_ENDPOINT))
    try:
        verify_high_risk_authorization(
            g.current_user,
            form.totp_code.data,
            "session_revoke_others",
        )
        revoked = terminate_other_sessions_for_user(g.current_user)
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return redirect(url_for(_SESSIONS_ENDPOINT)), exc.status_code
    flash(f"Terminated {revoked} other session(s).", "success")
    return redirect(url_for(_SESSIONS_ENDPOINT))


@web_bp.get("/account/freeze")
@web_login_required
@web_not_frozen_required
def freeze_account():
    return render_template(_FREEZE_TEMPLATE, user=g.current_user, form=MfaOrStepUpForm())


@web_bp.post("/account/freeze")
@web_login_required
@web_not_frozen_required
@limiter.limit("5 per 5 minutes", key_func=get_remote_address)
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
def freeze_account_submit():
    form = MfaOrStepUpForm()
    if not form.validate_on_submit():
        return render_template(_FREEZE_TEMPLATE, user=g.current_user, form=form), 400

    try:
        freeze_own_account(g.current_user, form.totp_code.data)
    except AuthError as exc:
        if exc.status_code == 429:
            return rate_limit_response()
        flash(exc.message, "error")
        return render_template(_FREEZE_TEMPLATE, user=g.current_user, form=form), exc.status_code

    flash("Account frozen. Unfreeze requires manual support review.", "success")
    return redirect(url_for(_DASHBOARD_ENDPOINT))


@web_bp.post("/logout")
def logout():
    form = CsrfOnlyForm()
    if not form.validate_on_submit():
        flash(_SECURITY_TOKEN_EXPIRED_MESSAGE, "error")
        return redirect(url_for("main.index"))

    logout_current_session()
    return redirect(url_for(_LOGIN_ENDPOINT))
