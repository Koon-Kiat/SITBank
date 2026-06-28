from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from math import ceil

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    session,
    url_for,
)
from sqlalchemy.exc import IntegrityError

from decimal import Decimal, InvalidOperation

from app.auth.forms import CsrfOnlyForm, MfaOrStepUpForm
from app.auth.mfa_policy import has_enrolled_mfa_method
from app.auth.services import AuthError, verify_high_risk_authorization
from app.banking.forms import AddPayeeForm, TransferForm
from app.banking.schemas import MAX_TRANSACTION_AMOUNT, MIN_TRANSACTION_AMOUNT
from app.banking.services import execute_local_transfer
from app.extensions import db, limiter
from app.models import Payee, User
from app.security.audit import audit_event, audit_reference
from app.security.rate_limits import mfa_principal
from app.web.routes import web_login_required, web_not_frozen_required


banking_bp = Blueprint("banking", __name__, url_prefix="/banking")

_PENDING_PAYEE_TTL = 300  # seconds; user has 5 min to complete MFA after step 1
_PENDING_TRANSFER_TTL = 300  # seconds; user has 5 min to confirm after MFA step-up
_ACCOUNT_RE = re.compile(r"^[0-9]{9}$")


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


# ── Payee list ─────────────────────────────────────────────────────────────────

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
    return render_template("add_payee.html", form=AddPayeeForm())


@banking_bp.post("/payees/add")
@limiter.limit("10 per hour", key_func=mfa_principal)
@web_login_required
@web_not_frozen_required
def payees_add_submit():
    form = AddPayeeForm()
    if not form.validate_on_submit():
        return render_template("add_payee.html", form=form), 400

    nickname = form.nickname.data.strip()[:64]
    account_number = form.account_number.data.strip()

    # Belt-and-suspenders: re-check format server-side even after WTForms
    if not _ACCOUNT_RE.fullmatch(account_number):
        flash("Invalid account number format.", "error")
        return render_template("add_payee.html", form=form), 400

    if account_number == g.current_user.account_number:
        flash("You cannot add your own account as a payee.", "error")
        return render_template("add_payee.html", form=form), 400

    # Authorize before lookup so recipient identity is not revealed pre-step-up.
    try:
        verify_high_risk_authorization(
            g.current_user,
            form.totp_code.data,
            form.stepup_token.data,
            "payee_add",
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template("add_payee.html", form=form), exc.status_code

    recipient = User.query.filter_by(account_number=account_number).first()
    if not recipient:
        audit_event(
            "payee_lookup",
            "failure",
            user=g.current_user,
            metadata={
                "reason": "recipient_not_found",
                "account_ref": audit_reference("payee_account", account_number),
            },
        )
        flash("Could not add that payee. Check the details and try again.", "error")
        return render_template("add_payee.html", form=form), 400

    existing = Payee.query.filter_by(
        user_id=g.current_user.id,
        account_number=account_number,
    ).first()
    if existing:
        flash("This payee is already in your list.", "error")
        return render_template("add_payee.html", form=form), 400

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
        return redirect(url_for("banking.payees_add"))

    if datetime.now(timezone.utc) > datetime.fromisoformat(pending["expires_at"]):
        session.pop("pending_payee", None)
        flash("Request expired. Please start again.", "warning")
        return redirect(url_for("banking.payees_add"))

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
        return redirect(url_for("banking.payees_add"))

    if datetime.now(timezone.utc) > datetime.fromisoformat(pending["expires_at"]):
        flash("Request expired. Please start again.", "warning")
        return redirect(url_for("banking.payees_add"))

    if pending.get("authorization_action") != "payee_add" or not pending.get("authorized_at"):
        flash("Payee authorization expired. Please start again.", "warning")
        return redirect(url_for("banking.payees_add"))

    if not form.validate_on_submit():
        session["pending_payee"] = pending
        return render_template("confirm_payee.html", form=form, pending=pending), 400

    # Re-validate everything server-side — state may have changed since step 1
    account_number = pending["account_number"]

    if account_number == g.current_user.account_number:
        flash("Cannot add your own account.", "error")
        return redirect(url_for("banking.payees_add"))

    recipient = User.query.filter_by(account_number=account_number).first()
    if not recipient:
        flash("Account no longer found. Please start again.", "error")
        return redirect(url_for("banking.payees_add"))

    existing = Payee.query.filter_by(
        user_id=g.current_user.id,
        account_number=account_number,
    ).first()
    if existing:
        flash("This payee is already in your list.", "error")
        return redirect(url_for("banking.payees"))

    # Insert using server-fetched name — client never supplied this
    payee = Payee(
        user_id=g.current_user.id,
        nickname=pending["nickname"],
        account_number=account_number,
        recipient_name=recipient.full_name,
    )
    try:
        db.session.add(payee)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("This payee is already in your list.", "error")
        return redirect(url_for("banking.payees"))

    audit_event(
        "payee_add",
        "success",
        user=g.current_user,
        metadata={"account_number": account_number},
    )

    cooldown_seconds = current_app.config.get("PAYEE_COOLDOWN_SECONDS", 60)
    cooldown_label = _format_cooldown_remaining(cooldown_seconds)
    flash(f"Payee added. Transfers available in {cooldown_label}.", "success")
    return redirect(url_for("banking.payees"))


# ── Remove payee ────────────────────────────────────────────────────────────────

@banking_bp.get("/payees/<int:payee_id>/remove")
@web_login_required
@web_not_frozen_required
def payees_remove(payee_id: int):
    # Ownership check — prevents IDOR
    payee = Payee.query.filter_by(id=payee_id, user_id=g.current_user.id).first_or_404()
    return render_template("remove_payee.html", form=MfaOrStepUpForm(), payee=payee)


@banking_bp.post("/payees/<int:payee_id>/remove")
@limiter.limit("10 per hour", key_func=mfa_principal)
@web_login_required
@web_not_frozen_required
def payees_remove_submit(payee_id: int):
    # Ownership check before processing anything
    payee = Payee.query.filter_by(id=payee_id, user_id=g.current_user.id).first_or_404()

    form = MfaOrStepUpForm()
    if not form.validate_on_submit():
        return render_template("remove_payee.html", form=form, payee=payee), 400

    try:
        verify_high_risk_authorization(
            g.current_user,
            form.totp_code.data,
            form.stepup_token.data,
            "payee_remove",
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template("remove_payee.html", form=form, payee=payee), exc.status_code

    audit_event(
        "payee_remove",
        "success",
        user=g.current_user,
        metadata={"account_number": payee.account_number, "nickname": payee.nickname},
    )
    db.session.delete(payee)
    db.session.commit()

    flash("Payee removed.", "success")
    return redirect(url_for("banking.payees"))


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
        return redirect(url_for("banking.payees"))
    return render_template("transfer.html", form=TransferForm(), payee=payee)


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
        return redirect(url_for("banking.payees"))

    form = TransferForm()
    if not form.validate_on_submit():
        return render_template("transfer.html", form=form, payee=payee), 400

    # A03: parse as Decimal — never float — to avoid precision errors
    try:
        amount = Decimal(form.amount.data.strip())
    except InvalidOperation:
        flash("Invalid amount.", "error")
        return render_template("transfer.html", form=form, payee=payee), 400

    if amount < MIN_TRANSACTION_AMOUNT or amount > MAX_TRANSACTION_AMOUNT:
        flash(
            f"Amount must be between SGD {MIN_TRANSACTION_AMOUNT} and SGD {MAX_TRANSACTION_AMOUNT}.",
            "error",
        )
        return render_template("transfer.html", form=form, payee=payee), 400

    # A07: MFA step-up required before pending state is stored
    try:
        verify_high_risk_authorization(
            g.current_user,
            form.totp_code.data,
            form.stepup_token.data,
            "transfer",
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template("transfer.html", form=form, payee=payee), exc.status_code

    # A08: all sensitive fields sourced from DB, not client; pending state stored server-side
    session["pending_transfer"] = {
        "payee_id": payee_id,
        "payee_account_number": payee.account_number,
        "recipient_name": payee.recipient_name,
        "amount": str(amount),
        "reference": (form.reference.data or "").strip()[:128],
        "authorization_action": "transfer",
        "authorized_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (
            datetime.now(timezone.utc) + timedelta(seconds=_PENDING_TRANSFER_TTL)
        ).isoformat(),
    }
    return redirect(url_for("banking.transfer_confirm", payee_id=payee_id))


# ── Local Transfer: step 2 — confirmation ──────────────────────────────────────

@banking_bp.get("/transfer/<int:payee_id>/confirm")
@web_login_required
@web_not_frozen_required
def transfer_confirm(payee_id: int):
    pending = session.get("pending_transfer")
    if not pending or pending.get("payee_id") != payee_id:
        flash("No pending transfer. Please start again.", "warning")
        return redirect(url_for("banking.payees"))
    if datetime.now(timezone.utc) > datetime.fromisoformat(pending["expires_at"]):
        session.pop("pending_transfer", None)
        flash("Request expired. Please start again.", "warning")
        return redirect(url_for("banking.payees"))
    return render_template("confirm_transfer.html", form=CsrfOnlyForm(), pending=pending)


@banking_bp.post("/transfer/<int:payee_id>/confirm")
@limiter.limit("5 per 15 minutes", key_func=mfa_principal)
@web_login_required
@web_not_frozen_required
def transfer_confirm_submit(payee_id: int):
    form = CsrfOnlyForm()

    # A04: consume pending state immediately — prevents replay even if commit fails
    pending = session.pop("pending_transfer", None)
    if not pending or pending.get("payee_id") != payee_id:
        flash("No pending transfer. Please start again.", "warning")
        return redirect(url_for("banking.payees"))
    if datetime.now(timezone.utc) > datetime.fromisoformat(pending["expires_at"]):
        flash("Request expired. Please start again.", "warning")
        return redirect(url_for("banking.payees"))
    if pending.get("authorization_action") != "transfer" or not pending.get("authorized_at"):
        flash("Transfer authorization missing. Please start again.", "warning")
        return redirect(url_for("banking.payees"))

    if not form.validate_on_submit():
        session["pending_transfer"] = pending
        return render_template("confirm_transfer.html", form=form, pending=pending), 400

    try:
        amount = Decimal(pending["amount"])
    except (InvalidOperation, KeyError):
        flash("Invalid transfer amount. Please start again.", "error")
        return redirect(url_for("banking.payees"))

    # A01: re-fetch payee server-side — re-validates ownership and cooldown at execution time
    payee = Payee.query.filter_by(id=payee_id, user_id=g.current_user.id).first_or_404()
    cooldown_seconds = current_app.config.get("PAYEE_COOLDOWN_SECONDS", 60)
    if _cooldown_status(payee, cooldown_seconds)["status"] != "active":
        flash("Payee is still in cooldown.", "error")
        return redirect(url_for("banking.payees"))

    try:
        txn_ref = execute_local_transfer(
            sender=g.current_user,
            payee=payee,
            amount=amount,
            reference=pending.get("reference", ""),
        )
    except AuthError as exc:
        flash(exc.message, "error")
        return redirect(url_for("banking.payees"))

    flash(
        f"Transfer of SGD {amount:.2f} to {payee.recipient_name} is complete. Ref: {txn_ref[:8].upper()}",
        "success",
    )
    return redirect(url_for("banking.payees"))
