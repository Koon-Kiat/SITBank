from __future__ import annotations

import csv
import io
import os
import re
from datetime import datetime, timedelta, timezone
from math import ceil

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy.exc import IntegrityError

from decimal import Decimal, InvalidOperation

from app.auth.forms import CsrfOnlyForm, MfaOrStepUpForm
from app.auth.mfa_policy import has_enrolled_mfa_method
from app.auth.services import AuthError, verify_high_risk_authorization
from app.banking.forms import (
    AddPayeeForm,
    PayupAmountForm,
    PayupConfirmForm,
    PayupPhoneForm,
    TRANSFER_LIMIT_PRESETS,
    TransferForm,
    TransferLimitsForm,
)
from app.banking.schemas import MAX_TRANSACTION_AMOUNT, MIN_TRANSACTION_AMOUNT
from app.banking.services import (
    evaluate_payup_risk,
    execute_local_transfer,
    execute_payup_transfer,
    local_transfer_token_verifier,
    payup_amount_used_today,
    payup_transfer_token_verifier,
    resolve_transfer_limit_choice,
    statement_for_period,
)
from app.extensions import db, limiter
from app.models import Payee, PayupPendingTransfer, PendingTransfer, User
from app.security.audit import (
    AuditWriteError,
    audit_event,
    audit_event_required,
    audit_reference,
)
from app.security.rate_limits import DurableRateLimitExceeded, consume_durable_rate_limit
from app.security.rate_limits import mfa_principal
from app.security.sessions import current_session_id
from app.web.routes import web_login_required, web_not_frozen_required


banking_bp = Blueprint("banking", __name__, url_prefix="/banking")

_PENDING_PAYEE_TTL = 300  # seconds; user has 5 min to complete MFA after step 1
_PENDING_TRANSFER_TTL = 300  # seconds; user has 5 min to confirm after MFA step-up
_ACCOUNT_RE = re.compile(r"^\d{12}$", flags=re.ASCII)
_REQUEST_EXPIRED_MESSAGE = "Request expired. Please start again."
_NO_PENDING_TRANSFER_MESSAGE = "No pending transfer. Please start again."
_PAYEES_ENDPOINT = "banking.payees"
_PAYEES_ADD_ENDPOINT = "banking.payees_add"
_TRANSFER_TEMPLATE = "transfer.html"
_ADD_PAYEE_TEMPLATE = "add_payee.html"
_REMOVE_PAYEE_TEMPLATE = "remove_payee.html"
_DUPLICATE_PAYEE_MESSAGE = "This payee is already in your list."

_PAYUP_PENDING_RECIPIENT_TTL = 300  # seconds; time to complete amount entry after phone lookup
_PAYUP_PENDING_TRANSFER_TTL = 300  # seconds; time to confirm after amount step
_PAYUP_TEMPLATE = "payup.html"
_PAYUP_AMOUNT_TEMPLATE = "payup_amount.html"
_PAYUP_CONFIRM_TEMPLATE = "payup_confirm.html"
_PAYUP_ENDPOINT = "banking.payup"
_NO_PENDING_PAYUP_RECIPIENT_MESSAGE = "No pending PayUp request. Please start again."
_INVALID_PHONE_MESSAGE = "Invalid phone number."
_PAYUP_LOOKUP_FAILURE_LIMIT = 5
_PAYUP_LOOKUP_FAILURE_WINDOW_SECONDS = 60 * 60

_TRANSFER_LIMITS_TEMPLATE = "transfer_limits.html"
_TRANSFER_LIMITS_ENDPOINT = "banking.transfer_limits"


@banking_bp.before_request
def enforce_banking_mfa_onboarding():
    user = getattr(g, "current_user", None)
    if user is not None and not has_enrolled_mfa_method(user):
        flash("Set up an authenticator app before using banking features.", "warning")
        return redirect(url_for("web.mfa_setup"))
    return None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _format_cooldown_remaining(seconds: float) -> str:
    total_seconds = max(0, int(ceil(seconds)))
    days, remainder = divmod(total_seconds, 24 * 60 * 60)
    hours, remainder = divmod(remainder, 60 * 60)
    minutes, secs = divmod(remainder, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _cooldown_status(payee: Payee, cooldown_seconds: int) -> dict:
    now = datetime.now(timezone.utc)
    created_at = _as_utc(payee.created_at)
    elapsed = (now - created_at).total_seconds()
    if elapsed >= cooldown_seconds:
        return {
            "status": "active",
            "remaining": None,
            "expires_at": None,
            "available_at": None,
        }
    remaining = cooldown_seconds - elapsed
    expires_at = created_at + timedelta(seconds=cooldown_seconds)
    return {
        "status": "cooldown",
        "remaining": _format_cooldown_remaining(remaining),
        "expires_at": expires_at.isoformat(),
        "available_at": expires_at.strftime("%Y-%m-%d %H:%M UTC"),
    }


def _record_failed_payup_lookup(reason: str, phone_number: str) -> None:
    try:
        failure_count = consume_durable_rate_limit(
            "payup_lookup_failure",
            f"user:{g.current_user.id}",
            limit=_PAYUP_LOOKUP_FAILURE_LIMIT,
            window_seconds=_PAYUP_LOOKUP_FAILURE_WINDOW_SECONDS,
        )
    except DurableRateLimitExceeded as exc:
        audit_event(
            "payup_lookup",
            "blocked",
            user=g.current_user,
            metadata={
                "reason": "durable_rate_limit",
                "retry_after": exc.retry_after,
            },
        )
        raise AuthError(
            _INVALID_PHONE_MESSAGE,
            429,
            retry_after=exc.retry_after,
        ) from exc
    audit_event(
        "payup_lookup",
        "failure",
        user=g.current_user,
        metadata={
            "reason": reason,
            "phone_ref": audit_reference("payup_phone", phone_number),
            "failure_count": failure_count,
        },
    )


# ── Payee list ─────────────────────────────────────────────────────────────────

def _masked_payup_recipient_name(full_name: str) -> str:
    parts = [part for part in str(full_name or "").split() if part]
    if not parts:
        return "Registered recipient"
    return " ".join(
        part[0] + ("*" * min(max(len(part) - 1, 1), 8))
        for part in parts[:4]
    )


def _consume_payup_attempt_limits(phone_number: str, *, phase: str) -> None:
    if phase not in {"lookup", "confirm"}:
        raise AuthError("PayUp request could not be authorized.", 403)
    session_identifier = current_session_id()
    if not session_identifier:
        raise AuthError("Session verification required. Please sign in again.", 401)
    window_seconds = int(current_app.config["PAYUP_RATE_LIMIT_WINDOW_SECONDS"])
    dimensions = (
        (
            "account",
            f"user:{g.current_user.id}",
            int(current_app.config["PAYUP_RATE_LIMIT_ACCOUNT"]),
        ),
        (
            "session",
            session_identifier,
            int(current_app.config["PAYUP_RATE_LIMIT_SESSION"]),
        ),
        (
            "ip",
            request.remote_addr or "unknown",
            int(current_app.config["PAYUP_RATE_LIMIT_IP"]),
        ),
        (
            "recipient",
            phone_number,
            int(current_app.config["PAYUP_RATE_LIMIT_RECIPIENT"]),
        ),
    )
    for dimension, principal, limit in dimensions:
        try:
            consume_durable_rate_limit(
                f"payup_{phase}_{dimension}",
                principal,
                limit=limit,
                window_seconds=window_seconds,
            )
        except DurableRateLimitExceeded as exc:
            audit_event(
                "payup_rate_limit",
                "blocked",
                user=g.current_user,
                metadata={
                    "dimension": dimension,
                    "phase": phase,
                    "retry_after": exc.retry_after,
                    "phone_ref": audit_reference("payup_phone", phone_number),
                },
            )
            raise AuthError(
                "PayUp request could not be authorized.",
                429,
                retry_after=exc.retry_after,
            ) from exc


def _pending_payup_recipient(pending: dict | None) -> User | None:
    if not isinstance(pending, dict):
        return None
    try:
        recipient_id = int(pending["recipient_user_id"])
        expires_at = datetime.fromisoformat(str(pending["expires_at"]))
    except (KeyError, TypeError, ValueError):
        return None
    if datetime.now(timezone.utc) > _as_utc(expires_at):
        return None
    recipient = db.session.get(User, recipient_id)
    if not _payup_recipient_is_available(recipient):
        return None
    return recipient


def _payup_recipient_is_available(recipient: User | None) -> bool:
    return bool(
        recipient is not None
        and recipient.id != g.current_user.id
        and recipient.account_status == "active"
        and not recipient.is_frozen
        and recipient.phone_number
    )


def _payup_recipient_display(recipient: User) -> dict[str, str]:
    return {
        "recipient_name": _masked_payup_recipient_name(recipient.full_name),
        "recipient_phone": str(recipient.phone_number or ""),
    }


@banking_bp.get("/payees")
@web_login_required
@web_not_frozen_required
def payees():
    cooldown_seconds = current_app.config.get("PAYEE_COOLDOWN_SECONDS", 60)
    payees_list = (
        Payee.query.filter_by(user_id=g.current_user.id)
        .order_by(Payee.created_at.asc())
        .all()
    )
    payee_rows = [
        {"payee": p, **_cooldown_status(p, cooldown_seconds)} for p in payees_list
    ]
    return render_template("payees.html", payee_rows=payee_rows)


# ── Add payee: step 1 — form ────────────────────────────────────────────────────

@banking_bp.get("/payees/add")
@web_login_required
@web_not_frozen_required
def payees_add():
    return render_template(_ADD_PAYEE_TEMPLATE, form=AddPayeeForm())


@banking_bp.post("/payees/add")
@limiter.limit("10 per hour", key_func=mfa_principal)
@web_login_required
@web_not_frozen_required
def payees_add_submit():
    form = AddPayeeForm()
    if not form.validate_on_submit():
        return render_template(_ADD_PAYEE_TEMPLATE, form=form), 400

    nickname = form.nickname.data.strip()[:64]
    account_number = form.account_number.data.strip()

    # Belt-and-suspenders: re-check format server-side even after WTForms
    if not _ACCOUNT_RE.fullmatch(account_number):
        flash("Invalid account number format.", "error")
        return render_template(_ADD_PAYEE_TEMPLATE, form=form), 400

    if account_number == g.current_user.account_number:
        flash("You cannot add your own account as a payee.", "error")
        return render_template(_ADD_PAYEE_TEMPLATE, form=form), 400

    # Authorize before lookup so recipient identity is not revealed pre-step-up.
    try:
        verify_high_risk_authorization(
            g.current_user,
            form.totp_code.data,
            "payee_add",
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template(_ADD_PAYEE_TEMPLATE, form=form), exc.status_code

    recipient = User.query.filter_by(account_number=account_number).first()
    if not recipient:
        try:
            failed_count = consume_durable_rate_limit(
                "payee_lookup_failure",
                f"user:{g.current_user.id}",
                limit=5,
                window_seconds=60 * 60,
            )
        except DurableRateLimitExceeded as exc:
            audit_event(
                "payee_lookup",
                "blocked",
                user=g.current_user,
                metadata={"reason": "durable_rate_limit", "retry_after": exc.retry_after},
            )
            flash("Could not add that payee. Check the details and try again.", "error")
            return render_template(_ADD_PAYEE_TEMPLATE, form=form), 429
        audit_event(
            "payee_lookup",
            "failure",
            user=g.current_user,
            metadata={
                "reason": "recipient_not_found",
                "account_ref": audit_reference("payee_account", account_number),
                "failed_lookup_count": failed_count,
            },
        )
        flash("Could not add that payee. Check the details and try again.", "error")
        return render_template(_ADD_PAYEE_TEMPLATE, form=form), 400

    existing = Payee.query.filter_by(
        user_id=g.current_user.id,
        account_number=account_number,
    ).first()
    if existing:
        flash(_DUPLICATE_PAYEE_MESSAGE, "error")
        return render_template(_ADD_PAYEE_TEMPLATE, form=form), 400

    # Store pending state server-side; client never controls the recipient name
    session["pending_payee"] = {
        "nickname": nickname,
        "account_number": account_number,
        "recipient_name": recipient.full_name,  # fetched from DB
        "authorization_action": "payee_add",
        "authorized_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (
            datetime.now(timezone.utc) + timedelta(seconds=_PENDING_PAYEE_TTL)
        ).isoformat(),
    }
    return redirect(url_for("banking.payees_confirm"))


# ── Add payee: step 2 — confirmation ───────────────────────────────────────────

@banking_bp.get("/payees/confirm")
@web_login_required
@web_not_frozen_required
def payees_confirm():
    pending = session.get("pending_payee")
    if not pending:
        flash("No pending payee. Please start again.", "warning")
        return redirect(url_for(_PAYEES_ADD_ENDPOINT))

    if datetime.now(timezone.utc) > datetime.fromisoformat(pending["expires_at"]):
        session.pop("pending_payee", None)
        flash(_REQUEST_EXPIRED_MESSAGE, "warning")
        return redirect(url_for(_PAYEES_ADD_ENDPOINT))

    return render_template("confirm_payee.html", form=CsrfOnlyForm(), pending=pending)


@banking_bp.post("/payees/confirm")
@limiter.limit("5 per 15 minutes", key_func=mfa_principal)
@web_login_required
@web_not_frozen_required
def payees_confirm_submit():
    form = CsrfOnlyForm()

    # Consume pending payee now — prevents replay attacks
    pending = session.pop("pending_payee", None)
    if not pending:
        flash("No pending payee. Please start again.", "warning")
        return redirect(url_for(_PAYEES_ADD_ENDPOINT))

    if datetime.now(timezone.utc) > datetime.fromisoformat(pending["expires_at"]):
        flash(_REQUEST_EXPIRED_MESSAGE, "warning")
        return redirect(url_for(_PAYEES_ADD_ENDPOINT))

    if pending.get("authorization_action") != "payee_add" or not pending.get("authorized_at"):
        flash("Payee authorization expired. Please start again.", "warning")
        return redirect(url_for(_PAYEES_ADD_ENDPOINT))

    if not form.validate_on_submit():
        session["pending_payee"] = pending
        return render_template("confirm_payee.html", form=form, pending=pending), 400

    # Re-validate everything server-side — state may have changed since step 1
    account_number = pending["account_number"]

    if account_number == g.current_user.account_number:
        flash("Cannot add your own account.", "error")
        return redirect(url_for(_PAYEES_ADD_ENDPOINT))

    recipient = User.query.filter_by(account_number=account_number).first()
    if not recipient:
        flash("Account no longer found. Please start again.", "error")
        return redirect(url_for(_PAYEES_ADD_ENDPOINT))

    existing = Payee.query.filter_by(
        user_id=g.current_user.id,
        account_number=account_number,
    ).first()
    if existing:
        flash(_DUPLICATE_PAYEE_MESSAGE, "error")
        return redirect(url_for(_PAYEES_ENDPOINT))

    # Insert using server-fetched name — client never supplied this
    payee = Payee(
        user_id=g.current_user.id,
        nickname=pending["nickname"],
        account_number=account_number,
        recipient_name=recipient.full_name,
    )
    try:
        db.session.add(payee)
        db.session.flush([payee])
        audit_event_required(
            "payee_add",
            "success",
            user=g.current_user,
            metadata={
                "payee_account_ref": audit_reference(
                    "payee_account",
                    account_number,
                )
            },
        )
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash(_DUPLICATE_PAYEE_MESSAGE, "error")
        return redirect(url_for(_PAYEES_ENDPOINT))
    except AuditWriteError:
        db.session.rollback()
        raise

    cooldown_seconds = current_app.config.get("PAYEE_COOLDOWN_SECONDS", 60)
    cooldown_label = _format_cooldown_remaining(cooldown_seconds)
    flash(f"Payee added. Transfers available in {cooldown_label}.", "success")
    return redirect(url_for(_PAYEES_ENDPOINT))


# ── Remove payee ────────────────────────────────────────────────────────────────

@banking_bp.get("/payees/<int:payee_id>/remove")
@web_login_required
@web_not_frozen_required
def payees_remove(payee_id: int):
    # Ownership check — prevents IDOR
    payee = Payee.query.filter_by(id=payee_id, user_id=g.current_user.id).first_or_404()
    return render_template(_REMOVE_PAYEE_TEMPLATE, form=MfaOrStepUpForm(), payee=payee)


@banking_bp.post("/payees/<int:payee_id>/remove")
@limiter.limit("10 per hour", key_func=mfa_principal)
@web_login_required
@web_not_frozen_required
def payees_remove_submit(payee_id: int):
    # Ownership check before processing anything
    payee = Payee.query.filter_by(id=payee_id, user_id=g.current_user.id).first_or_404()

    form = MfaOrStepUpForm()
    if not form.validate_on_submit():
        return render_template(_REMOVE_PAYEE_TEMPLATE, form=form, payee=payee), 400

    try:
        verify_high_risk_authorization(
            g.current_user,
            form.totp_code.data,
            "payee_remove",
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template(_REMOVE_PAYEE_TEMPLATE, form=form, payee=payee), exc.status_code

    try:
        db.session.delete(payee)
        audit_event_required(
            "payee_remove",
            "success",
            user=g.current_user,
            metadata={
                "payee_account_ref": audit_reference(
                    "payee_account",
                    payee.account_number,
                ),
                "nickname_present": bool(payee.nickname),
                "nickname_length": len(payee.nickname or ""),
            },
        )
        db.session.commit()
    except AuditWriteError:
        db.session.rollback()
        raise

    flash("Payee removed.", "success")
    return redirect(url_for(_PAYEES_ENDPOINT))


# ── Local Transfer: step 1 — amount + MFA step-up ──────────────────────────────

@banking_bp.get("/transfer/<int:payee_id>")
@web_login_required
@web_not_frozen_required
def transfer(payee_id: int):
    # A01: ownership check prevents IDOR
    payee = Payee.query.filter_by(id=payee_id, user_id=g.current_user.id).first_or_404()
    cooldown_seconds = current_app.config.get("PAYEE_COOLDOWN_SECONDS", 60)
    status = _cooldown_status(payee, cooldown_seconds)
    if status["status"] != "active":
        flash(f"This payee is still in cooldown. Available in {status['remaining']}.", "warning")
        return redirect(url_for(_PAYEES_ENDPOINT))
    return render_template(_TRANSFER_TEMPLATE, form=TransferForm(), payee=payee)


@banking_bp.post("/transfer/<int:payee_id>")
@limiter.limit("5 per hour", key_func=mfa_principal)
@web_login_required
@web_not_frozen_required
def transfer_submit(payee_id: int):
    # A01: ownership check before processing anything
    payee = Payee.query.filter_by(id=payee_id, user_id=g.current_user.id).first_or_404()
    cooldown_seconds = current_app.config.get("PAYEE_COOLDOWN_SECONDS", 60)
    if _cooldown_status(payee, cooldown_seconds)["status"] != "active":
        flash("Payee is still in cooldown.", "error")
        return redirect(url_for(_PAYEES_ENDPOINT))

    form = TransferForm()
    if not form.validate_on_submit():
        return render_template(_TRANSFER_TEMPLATE, form=form, payee=payee), 400

    # A03: parse as Decimal — never float — to avoid precision errors
    try:
        amount = Decimal(form.amount.data.strip())
    except InvalidOperation:
        flash("Invalid amount.", "error")
        return render_template(_TRANSFER_TEMPLATE, form=form, payee=payee), 400

    if amount < MIN_TRANSACTION_AMOUNT or amount > MAX_TRANSACTION_AMOUNT:
        flash(
            f"Amount must be between SGD {MIN_TRANSACTION_AMOUNT} and SGD {MAX_TRANSACTION_AMOUNT}.",
            "error",
        )
        return render_template(_TRANSFER_TEMPLATE, form=form, payee=payee), 400

    # A07: MFA step-up required before pending state is created
    try:
        verify_high_risk_authorization(
            g.current_user,
            form.totp_code.data,
            "transfer",
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template(_TRANSFER_TEMPLATE, form=form, payee=payee), exc.status_code

    # A08: create a server-side pending transfer record bound to this user, payee,
    # amount, and reference. Store only the opaque token in the session so the
    # client never controls the transfer parameters.
    token = os.urandom(32).hex()
    pending_tfr = PendingTransfer(
        token=local_transfer_token_verifier(token),
        user_id=g.current_user.id,
        payee_id=payee_id,
        amount=amount,
        reference=(form.reference.data or "").strip()[:128],
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=_PENDING_TRANSFER_TTL),
    )
    db.session.add(pending_tfr)
    db.session.commit()
    session["pending_transfer_token"] = token
    return redirect(url_for("banking.transfer_confirm", payee_id=payee_id))


# ── Local Transfer: step 2 — confirmation ──────────────────────────────────────

@banking_bp.get("/transfer/<int:payee_id>/confirm")
@web_login_required
@web_not_frozen_required
def transfer_confirm(payee_id: int):
    token = session.get("pending_transfer_token")
    if not token:
        flash(_NO_PENDING_TRANSFER_MESSAGE, "warning")
        return redirect(url_for(_PAYEES_ENDPOINT))

    pending_tfr = PendingTransfer.query.filter_by(
        token=local_transfer_token_verifier(token),
        user_id=g.current_user.id,
        payee_id=payee_id,
        consumed_at=None,
    ).first()
    if not pending_tfr:
        session.pop("pending_transfer_token", None)
        flash(_NO_PENDING_TRANSFER_MESSAGE, "warning")
        return redirect(url_for(_PAYEES_ENDPOINT))

    if _as_utc(pending_tfr.expires_at) < datetime.now(timezone.utc):
        session.pop("pending_transfer_token", None)
        flash(_REQUEST_EXPIRED_MESSAGE, "warning")
        return redirect(url_for(_PAYEES_ENDPOINT))

    pending = {
        "payee_id": payee_id,
        "recipient_name": pending_tfr.payee.recipient_name,
        "payee_account_number": pending_tfr.payee.account_number,
        "amount": str(pending_tfr.amount),
        "reference": pending_tfr.reference,
    }
    return render_template("confirm_transfer.html", form=CsrfOnlyForm(), pending=pending)


@banking_bp.post("/transfer/<int:payee_id>/confirm")
@limiter.limit("5 per 15 minutes", key_func=mfa_principal)
@web_login_required
@web_not_frozen_required
def transfer_confirm_submit(payee_id: int):
    form = CsrfOnlyForm()

    # A04: consume session token immediately — prevents session-layer replay
    token = session.pop("pending_transfer_token", None)
    if not token:
        flash(_NO_PENDING_TRANSFER_MESSAGE, "warning")
        return redirect(url_for(_PAYEES_ENDPOINT))

    if not form.validate_on_submit():
        flash("Request validation failed. Please start again.", "error")
        return redirect(url_for(_PAYEES_ENDPOINT))

    # A01: re-fetch payee server-side — re-validates ownership at execution time
    payee = Payee.query.filter_by(id=payee_id, user_id=g.current_user.id).first_or_404()

    try:
        txn_ref = execute_local_transfer(
            sender=g.current_user,
            payee=payee,
            confirmation_token=token,
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return redirect(url_for(_PAYEES_ENDPOINT))

    amount_display = PendingTransfer.query.filter_by(
        consumed_transaction_ref=txn_ref,
    ).with_entities(PendingTransfer.amount).scalar() or ""
    flash(
        f"Transfer of SGD {amount_display} to {payee.recipient_name} is complete. Ref: {txn_ref[:8].upper()}",
        "success",
    )
    return redirect(url_for(_PAYEES_ENDPOINT))


# ── PayUp: step 1 — phone lookup ────────────────────────────────────────────────

@banking_bp.get("/payup")
@web_login_required
@web_not_frozen_required
def payup():
    return render_template(_PAYUP_TEMPLATE, form=PayupPhoneForm())


@banking_bp.post("/payup")
@web_login_required
@web_not_frozen_required
def payup_submit():
    form = PayupPhoneForm()
    if not form.validate_on_submit():
        return render_template(_PAYUP_TEMPLATE, form=form), 400

    phone_number = form.phone_number.data.strip()

    try:
        _consume_payup_attempt_limits(phone_number, phase="lookup")
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template(_PAYUP_TEMPLATE, form=form), exc.status_code
    audit_event(
        "payup_lookup",
        "attempted",
        user=g.current_user,
        metadata={"phone_ref": audit_reference("payup_phone", phone_number)},
    )

    recipient = User.query.filter_by(phone_number=phone_number).first()
    if (
        not recipient
        or recipient.id == g.current_user.id
        or recipient.account_status != "active"
        or recipient.is_frozen
    ):
        try:
            _record_failed_payup_lookup("recipient_unavailable", phone_number)
        except AuthError as exc:
            flash(exc.message, "error")
            return render_template(_PAYUP_TEMPLATE, form=form), exc.status_code
        flash(_INVALID_PHONE_MESSAGE, "error")
        return render_template(_PAYUP_TEMPLATE, form=form), 400

    audit_event(
        "payup_lookup",
        "success",
        user=g.current_user,
        metadata={"phone_ref": audit_reference("payup_phone", phone_number)},
    )
    # Store only a server-resolved user id and expiry in the signed server-side
    # session. Recipient display data is reloaded for every subsequent step.
    session["pending_payup_recipient"] = {
        "recipient_user_id": recipient.id,
        "expires_at": (
            datetime.now(timezone.utc) + timedelta(seconds=_PAYUP_PENDING_RECIPIENT_TTL)
        ).isoformat(),
    }
    return redirect(url_for("banking.payup_amount"))


# ── PayUp: step 2 — amount + daily limit ────────────────────────────────────────

@banking_bp.get("/payup/amount")
@web_login_required
@web_not_frozen_required
def payup_amount():
    pending = session.get("pending_payup_recipient")
    recipient = _pending_payup_recipient(pending)
    if recipient is None:
        session.pop("pending_payup_recipient", None)
        flash(_NO_PENDING_PAYUP_RECIPIENT_MESSAGE, "warning")
        return redirect(url_for(_PAYUP_ENDPOINT))

    daily_limit = Decimal(str(g.current_user.payup_daily_limit))
    remaining = max(Decimal("0.00"), daily_limit - payup_amount_used_today(g.current_user))
    return render_template(
        _PAYUP_AMOUNT_TEMPLATE,
        form=PayupAmountForm(),
        pending=_payup_recipient_display(recipient),
        daily_limit=daily_limit,
        remaining=remaining,
    )


@banking_bp.post("/payup/amount")
@web_login_required
@web_not_frozen_required
def payup_amount_submit():
    pending = session.get("pending_payup_recipient")
    recipient = _pending_payup_recipient(pending)
    if recipient is None:
        session.pop("pending_payup_recipient", None)
        flash(_NO_PENDING_PAYUP_RECIPIENT_MESSAGE, "warning")
        return redirect(url_for(_PAYUP_ENDPOINT))

    daily_limit = Decimal(str(g.current_user.payup_daily_limit))
    remaining = max(Decimal("0.00"), daily_limit - payup_amount_used_today(g.current_user))

    form = PayupAmountForm()
    if not form.validate_on_submit():
        return render_template(
            _PAYUP_AMOUNT_TEMPLATE,
            form=form,
            pending=_payup_recipient_display(recipient),
            daily_limit=daily_limit,
            remaining=remaining,
        ), 400

    try:
        amount = Decimal(form.amount.data.strip())
    except InvalidOperation:
        flash("Invalid amount.", "error")
        return render_template(
            _PAYUP_AMOUNT_TEMPLATE,
            form=form,
            pending=_payup_recipient_display(recipient),
            daily_limit=daily_limit,
            remaining=remaining,
        ), 400

    if amount < MIN_TRANSACTION_AMOUNT or amount > MAX_TRANSACTION_AMOUNT:
        flash(
            f"Amount must be between SGD {MIN_TRANSACTION_AMOUNT} and SGD {MAX_TRANSACTION_AMOUNT}.",
            "error",
        )
        return render_template(
            _PAYUP_AMOUNT_TEMPLATE,
            form=form,
            pending=_payup_recipient_display(recipient),
            daily_limit=daily_limit,
            remaining=remaining,
        ), 400

    if amount > remaining:
        flash(
            f"This transfer would exceed your daily PayUp limit. Remaining today: SGD {remaining}.",
            "error",
        )
        return render_template(
            _PAYUP_AMOUNT_TEMPLATE,
            form=form,
            pending=_payup_recipient_display(recipient),
            daily_limit=daily_limit,
            remaining=remaining,
        ), 400

    if amount > Decimal(str(g.current_user.balance)):
        flash("Insufficient balance for this transfer.", "error")
        return render_template(
            _PAYUP_AMOUNT_TEMPLATE,
            form=form,
            pending=_payup_recipient_display(recipient),
            daily_limit=daily_limit,
            remaining=remaining,
        ), 400

    token = os.urandom(32).hex()
    pending_tfr = PayupPendingTransfer(
        token=payup_transfer_token_verifier(token),
        user_id=g.current_user.id,
        recipient_user_id=recipient.id,
        amount=amount,
        reference=(form.reference.data or "").strip()[:128],
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=_PAYUP_PENDING_TRANSFER_TTL),
    )
    db.session.add(pending_tfr)
    db.session.commit()
    session.pop("pending_payup_recipient", None)
    session["pending_payup_token"] = token
    return redirect(url_for("banking.payup_confirm"))


# ── PayUp: step 3 — confirmation (conditional MFA step-up) ──────────────────────

@banking_bp.get("/payup/confirm")
@web_login_required
@web_not_frozen_required
def payup_confirm():
    token = session.get("pending_payup_token")
    if not token:
        flash(_NO_PENDING_TRANSFER_MESSAGE, "warning")
        return redirect(url_for(_PAYUP_ENDPOINT))

    pending_tfr = PayupPendingTransfer.query.filter_by(
        token=payup_transfer_token_verifier(token),
        user_id=g.current_user.id,
        consumed_at=None,
    ).first()
    if not pending_tfr:
        session.pop("pending_payup_token", None)
        flash(_NO_PENDING_TRANSFER_MESSAGE, "warning")
        return redirect(url_for(_PAYUP_ENDPOINT))

    if _as_utc(pending_tfr.expires_at) < datetime.now(timezone.utc):
        session.pop("pending_payup_token", None)
        flash(_REQUEST_EXPIRED_MESSAGE, "warning")
        return redirect(url_for(_PAYUP_ENDPOINT))

    if not _payup_recipient_is_available(pending_tfr.recipient_user):
        session.pop("pending_payup_token", None)
        audit_event(
            "payup_transfer",
            "blocked",
            user=g.current_user,
            metadata={"reason": "recipient_unavailable"},
        )
        flash("PayUp could not authorize this transfer.", "error")
        return redirect(url_for(_PAYUP_ENDPOINT))

    amount = Decimal(str(pending_tfr.amount))
    risk = evaluate_payup_risk(g.current_user, amount)
    if risk.blocked:
        session.pop("pending_payup_token", None)
        audit_event(
            "payup_transfer",
            "blocked",
            user=g.current_user,
            metadata={"risk_reasons": list(risk.reasons)},
        )
        flash("PayUp could not authorize this transfer. Please sign in again or contact support.", "error")
        return redirect(url_for(_PAYUP_ENDPOINT))
    pending = {
        "recipient_name": _masked_payup_recipient_name(
            pending_tfr.recipient_user.full_name
        ),
        "recipient_phone": pending_tfr.recipient_user.phone_number,
        "amount": str(amount.quantize(Decimal("0.01"))),
        "reference": pending_tfr.reference,
        "requires_step_up": risk.requires_step_up,
    }
    return render_template(_PAYUP_CONFIRM_TEMPLATE, form=PayupConfirmForm(), pending=pending)


@banking_bp.post("/payup/confirm")
@web_login_required
@web_not_frozen_required
def payup_confirm_submit():
    form = PayupConfirmForm()

    # A04: consume session token immediately — prevents session-layer replay
    token = session.pop("pending_payup_token", None)
    if not token:
        flash(_NO_PENDING_TRANSFER_MESSAGE, "warning")
        return redirect(url_for(_PAYUP_ENDPOINT))

    if not form.validate_on_submit():
        flash("Request validation failed. Please start again.", "error")
        return redirect(url_for(_PAYUP_ENDPOINT))

    pending_tfr = PayupPendingTransfer.query.filter_by(
        token=payup_transfer_token_verifier(token),
        user_id=g.current_user.id,
        consumed_at=None,
    ).first()
    if not pending_tfr:
        flash(_NO_PENDING_TRANSFER_MESSAGE, "warning")
        return redirect(url_for(_PAYUP_ENDPOINT))

    if not _payup_recipient_is_available(pending_tfr.recipient_user):
        audit_event(
            "payup_transfer",
            "blocked",
            user=g.current_user,
            metadata={"reason": "recipient_unavailable"},
        )
        flash("PayUp could not authorize this transfer.", "error")
        return redirect(url_for(_PAYUP_ENDPOINT))

    amount = Decimal(str(pending_tfr.amount))
    recipient_phone = str(pending_tfr.recipient_user.phone_number or "")
    try:
        _consume_payup_attempt_limits(recipient_phone, phase="confirm")
    except AuthError as exc:
        audit_event(
            "payup_transfer",
            "blocked",
            user=g.current_user,
            metadata={"reason": "rate_limit"},
        )
        flash(exc.message, "error")
        return redirect(url_for(_PAYUP_ENDPOINT))

    risk = evaluate_payup_risk(g.current_user, amount)
    audit_event(
        "payup_transfer",
        "attempted",
        user=g.current_user,
        metadata={
            "risk_decision": risk.decision,
            "risk_reasons": list(risk.reasons),
            "phone_ref": audit_reference("payup_phone", recipient_phone),
        },
    )

    authorized = False
    if risk.requires_step_up:
        audit_event(
            "payup_mfa_challenge",
            "required",
            user=g.current_user,
            metadata={"risk_reasons": list(risk.reasons)},
        )
        try:
            verify_high_risk_authorization(
                g.current_user,
                form.totp_code.data,
                "payup_transfer",
            )
            authorized = True
            audit_event(
                "payup_mfa_challenge",
                "completed",
                user=g.current_user,
                metadata={"risk_reasons": list(risk.reasons)},
            )
        except AuthError as exc:
            audit_event(
                "payup_mfa_challenge",
                "failure",
                user=g.current_user,
                metadata={"reason": "invalid_or_missing_step_up"},
            )
            flash(exc.message, "error")
            session["pending_payup_token"] = token
            pending = {
                "recipient_name": _masked_payup_recipient_name(
                    pending_tfr.recipient_user.full_name
                ),
                "recipient_phone": recipient_phone,
                "amount": str(amount.quantize(Decimal("0.01"))),
                "reference": pending_tfr.reference,
                "requires_step_up": True,
            }
            return render_template(_PAYUP_CONFIRM_TEMPLATE, form=form, pending=pending), exc.status_code

    try:
        txn_ref = execute_payup_transfer(
            sender=g.current_user,
            confirmation_token=token,
            authorized=authorized,
        )
    except AuthError as exc:
        audit_event(
            "payup_transfer",
            "blocked" if exc.status_code in {401, 403, 409, 429} else "failure",
            user=g.current_user,
            metadata={"reason": "execution_policy"},
        )
        flash(exc.message, "error")
        return redirect(url_for(_PAYUP_ENDPOINT))

    recipient_name = _masked_payup_recipient_name(
        pending_tfr.recipient_user.full_name
    )
    audit_event(
        "payup_transfer",
        "success",
        user=g.current_user,
        metadata={
            "step_up_used": authorized,
            "transaction_ref": audit_reference("transaction_reference", txn_ref),
        },
    )
    flash(
        f"Transfer of SGD {amount.quantize(Decimal('0.01'))} to {recipient_name} is complete. "
        f"Ref: {txn_ref[:8].upper()}",
        "success",
    )
    return redirect(url_for("web.dashboard"))


# ── Settings: Daily Transfer Limit ──────────────────────────────────────────────

def _prefill_transfer_limits_form(form: TransferLimitsForm) -> None:
    current = Decimal(str(g.current_user.payup_daily_limit))
    for preset in TRANSFER_LIMIT_PRESETS:
        if current == Decimal(preset):
            form.payup_limit.data = preset
            return
    form.payup_limit.data = "custom"
    form.payup_limit_custom.data = str(current.quantize(Decimal("0.01")))


@banking_bp.get("/settings/transfer-limits")
@web_login_required
@web_not_frozen_required
def transfer_limits():
    form = TransferLimitsForm()
    _prefill_transfer_limits_form(form)
    return render_template(_TRANSFER_LIMITS_TEMPLATE, form=form)


@banking_bp.post("/settings/transfer-limits")
@limiter.limit("5 per 5 minutes", key_func=mfa_principal)
@web_login_required
@web_not_frozen_required
def transfer_limits_submit():
    form = TransferLimitsForm()
    if not form.validate_on_submit():
        return render_template(_TRANSFER_LIMITS_TEMPLATE, form=form), 400

    try:
        payup_limit = resolve_transfer_limit_choice(form.payup_limit.data, form.payup_limit_custom.data)
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template(_TRANSFER_LIMITS_TEMPLATE, form=form), exc.status_code

    try:
        verify_high_risk_authorization(
            g.current_user,
            form.totp_code.data,
            "transfer_limits_change",
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template(_TRANSFER_LIMITS_TEMPLATE, form=form), exc.status_code

    g.current_user.payup_daily_limit = payup_limit
    db.session.commit()

    audit_event(
        "transfer_limits_change",
        "success",
        user=g.current_user,
        metadata={"payup_daily_limit": str(payup_limit)},
    )
    flash("Daily transfer limits updated.", "success")
    return redirect(url_for(_TRANSFER_LIMITS_ENDPOINT))


# ── Monthly statement ───────────────────────────────────────────────────────────

_STATEMENT_TEMPLATE = "statement.html"
_STATEMENT_ENDPOINT = "banking.statement"
_SGT_STATEMENT_OFFSET = timezone(timedelta(hours=8))


def _bounded_int(value, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, minimum), maximum)


def _requested_statement_period() -> tuple[int, int]:
    now_sgt = datetime.now(timezone.utc).astimezone(_SGT_STATEMENT_OFFSET)
    year = _bounded_int(request.args.get("year"), default=now_sgt.year, minimum=2000, maximum=now_sgt.year)
    month = _bounded_int(request.args.get("month"), default=now_sgt.month, minimum=1, maximum=12)
    return year, month


_CSV_FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@")
_CSV_LEADING_NEUTRAL_RE = re.compile(r"^[\s\x00-\x1f\x7f]*")


def _csv_safe(value: str) -> str:
    """Neutralize spreadsheet formula injection (OWASP A03) in exported cell values.

    Trigger characters hidden behind leading whitespace or control characters
    (e.g. a leading tab or CR) still start a formula in common spreadsheet
    parsers, so the check strips those before testing for a trigger.
    """
    text = str(value or "")
    unmasked = _CSV_LEADING_NEUTRAL_RE.sub("", text)
    if unmasked.startswith(_CSV_FORMULA_TRIGGER_CHARS):
        return "'" + text
    return text


def _adjacent_period(year: int, month: int, *, delta: int) -> tuple[int, int]:
    zero_based = (year * 12 + (month - 1)) + delta
    return zero_based // 12, zero_based % 12 + 1


@banking_bp.get("/statement")
@web_login_required
@web_not_frozen_required
def statement():
    year, month = _requested_statement_period()
    try:
        data = statement_for_period(g.current_user, year, month)
    except AuthError as exc:
        flash(exc.message, "error")
        data = None
    now_sgt = datetime.now(timezone.utc).astimezone(_SGT_STATEMENT_OFFSET)
    prev_year, prev_month = _adjacent_period(year, month, delta=-1)
    next_year, next_month = _adjacent_period(year, month, delta=1)
    has_next_period = (year, month) < (now_sgt.year, now_sgt.month)
    return render_template(
        _STATEMENT_TEMPLATE,
        user=g.current_user,
        statement=data,
        year=year,
        month=month,
        prev_year=prev_year,
        prev_month=prev_month,
        next_year=next_year,
        next_month=next_month,
        has_next_period=has_next_period,
    )


@banking_bp.get("/statement/download")
@limiter.limit("10 per hour", key_func=mfa_principal)
@web_login_required
@web_not_frozen_required
def statement_download():
    year, month = _requested_statement_period()
    try:
        data = statement_for_period(g.current_user, year, month)
    except AuthError as exc:
        flash(exc.message, "error")
        return redirect(url_for(_STATEMENT_ENDPOINT, year=year, month=month))

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Date", "Type", "Counterparty", "Reference", "Amount (SGD)", "Status"])
    for txn in data["transactions"]:
        is_sender = txn.sender_id == g.current_user.id
        counterparty = txn.recipient if is_sender else txn.sender
        counterparty_name = (counterparty.full_name or counterparty.username) if counterparty else ""
        writer.writerow(
            [
                txn.created_at.astimezone(_SGT_STATEMENT_OFFSET).strftime("%Y-%m-%d %H:%M"),
                "PayUp" if txn.transaction_type == "payup" else "Local Transfer",
                _csv_safe(counterparty_name),
                _csv_safe(txn.reference or ""),
                f"-{txn.amount}" if is_sender else f"{txn.amount}",
                txn.status,
            ]
        )

    try:
        audit_event_required(
            "statement_export",
            "success",
            user=g.current_user,
            metadata={"period_ref": audit_reference("statement_period", f"{year:04d}-{month:02d}")},
        )
        db.session.commit()
    except AuditWriteError:
        db.session.rollback()
        raise

    filename = f"sitbank-statement-{year:04d}-{month:02d}.csv"
    response = Response(buffer.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
