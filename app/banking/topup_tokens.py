from __future__ import annotations

import hmac
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from flask import current_app

from app.extensions import db
from app.models import TopUpApprovalRequest
from app.security.session_hmac import active_hmac_hex
from app.time_display import as_utc


def generate_topup_token(user_id: int, amount: Decimal) -> tuple[str, TopUpApprovalRequest]:
    selector = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    ttl_seconds = int(current_app.config["TOPUP_APPROVAL_TTL_SECONDS"])
    request_row = TopUpApprovalRequest(
        selector=selector,
        verifier_hmac=_topup_token_hmac(verifier),
        user_id=user_id,
        amount=amount,
        status="pending",
        failure_count=0,
        expires_at=now + timedelta(seconds=ttl_seconds),
        created_at=now,
    )
    db.session.add(request_row)
    db.session.commit()
    return f"{selector}.{verifier}", request_row


def load_topup_request_for_approval(raw_token: str, *, lock: bool = False) -> TopUpApprovalRequest | None:
    """Resolve a scanned QR token to its pending approval request.

    Requires both the selector (lookup key) and verifier (bearer secret) to
    match, mirroring the password-reset selector/verifier token scheme.
    Returns None for anything not currently pending (expired/completed/
    failed/unknown/tampered) without distinguishing why, to avoid leaking
    token-guessing feedback.
    """

    selector, separator, verifier = str(raw_token or "").partition(".")
    if separator != "." or not selector or not verifier or len(selector) > 64 or len(verifier) > 128:
        return None

    request_row = _topup_request_by_selector(selector, lock=lock)
    if request_row is None:
        return None
    if not hmac.compare_digest(request_row.verifier_hmac, _topup_token_hmac(verifier)):
        return None

    _lazily_expire(request_row)
    if request_row.status != "pending":
        return None
    return request_row


def load_topup_request_for_owner(selector: str, user_id: int) -> TopUpApprovalRequest | None:
    """Resolve a request by selector for the original (logged-in) device's status poll.

    No verifier is required here: ownership is proven by the caller's login
    session (checked against user_id), not by possession of the QR token.
    """

    request_row = _topup_request_by_selector(selector, lock=False)
    if request_row is None or request_row.user_id != user_id:
        return None
    _lazily_expire(request_row)
    return request_row


def _lazily_expire(request_row: TopUpApprovalRequest) -> None:
    if request_row.status == "pending" and as_utc(request_row.expires_at) <= datetime.now(timezone.utc):
        request_row.status = "expired"
        db.session.commit()


def _topup_request_by_selector(selector: str, *, lock: bool) -> TopUpApprovalRequest | None:
    statement = db.select(TopUpApprovalRequest).where(TopUpApprovalRequest.selector == selector)
    if lock:
        statement = statement.with_for_update()
    return db.session.execute(statement).scalar_one_or_none()


def _topup_token_hmac(verifier: str) -> str:
    return active_hmac_hex(f"topup-approval-token:{verifier}", length=64)
