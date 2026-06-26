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

from app.auth.forms import MfaOrStepUpForm
from app.auth.services import AuthError, verify_high_risk_authorization
from app.banking.forms import AddPayeeForm
from app.extensions import db, limiter
from app.models import Payee, User
from app.security.audit import audit_event
from app.security.rate_limits import mfa_principal
from app.web.routes import web_login_required, web_not_frozen_required


banking_bp = Blueprint("banking", __name__, url_prefix="/banking")

_PENDING_PAYEE_TTL = 300  # seconds; user has 5 min to complete MFA after step 1
_ACCOUNT_RE = re.compile(r"^[0-9]{9}$")


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

    # Server-side lookup — recipient name comes from DB, never from client input
    recipient = User.query.filter_by(account_number=account_number).first()
    if not recipient:
        flash("Account not found. Please check the account number.", "error")
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
        "expires_at": (
            datetime.now(timezone.utc) + timedelta(seconds=_PENDING_PAYEE_TTL)
        ).isoformat(),
    }
    return redirect(url_for("banking.payees_confirm"))


# ── Add payee: step 2 — confirmation + MFA ──────────────────────────────────────

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

    return render_template("confirm_payee.html", form=MfaOrStepUpForm(), pending=pending)


@banking_bp.post("/payees/confirm")
@limiter.limit("5 per 15 minutes", key_func=mfa_principal)
@web_login_required
@web_not_frozen_required
def payees_confirm_submit():
    form = MfaOrStepUpForm()

    # Consume pending payee now — prevents replay attacks
    pending = session.pop("pending_payee", None)
    if not pending:
        flash("No pending payee. Please start again.", "warning")
        return redirect(url_for("banking.payees_add"))

    if datetime.now(timezone.utc) > datetime.fromisoformat(pending["expires_at"]):
        flash("Request expired. Please start again.", "warning")
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

    # MFA verified server-side
    try:
        verify_high_risk_authorization(
            g.current_user,
            form.totp_code.data,
            form.stepup_token.data,
            "payee_add",
        )
    except AuthError as exc:
        flash(exc.message, "error")
        # Put pending payee back so user can retry without re-entering account number
        session["pending_payee"] = {
            **pending,
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(seconds=_PENDING_PAYEE_TTL)
            ).isoformat(),
        }
        return render_template("confirm_payee.html", form=form, pending=pending), exc.status_code

    # Insert using server-fetched name — client never supplied this
    payee = Payee(
        user_id=g.current_user.id,
        nickname=pending["nickname"],
        account_number=account_number,
        recipient_name=pending["recipient_name"],
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
