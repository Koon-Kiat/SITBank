"""New-device-login detection for customer sign-in.

Customer-only: do not wire this into app/admin/* login paths.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from flask import current_app, request, session

from app.extensions import db
from app.models import KnownDevice, User
from app.security.audit import audit_event
from app.security.email import EMAIL_CLOSING, EMAIL_GREETING, EMAIL_SIGN_OFF, send_security_email
from app.security.session_hmac import active_hmac_hex, matches_hmac
from app.security.sessions import display_ip_address, summarize_user_agent
from app.time_display import as_utc, sgt_date, sgt_time


@dataclass(frozen=True)
class DeviceCheckResult:
    is_new_device: bool
    device_token: str


def device_token_hash(raw_token: str) -> str:
    return active_hmac_hex(f"device-token:{raw_token}", length=64)


def check_and_register_device(user: User, raw_cookie_token: str | None) -> DeviceCheckResult:
    """Resolve whether the presented device cookie is known for this user.

    Scoped to this user's own rows only: a cookie minted for a different
    user (shared browser, logout, login as someone else) simply never
    matches here and correctly falls through to "new device" for this user,
    rather than erroring or leaking whether the hash exists elsewhere.
    """
    now = datetime.now(timezone.utc)
    max_age = timedelta(seconds=int(current_app.config["DEVICE_COOKIE_MAX_AGE_SECONDS"]))

    if raw_cookie_token:
        candidates = (
            db.session.execute(db.select(KnownDevice).where(KnownDevice.user_id == user.id))
            .scalars()
            .all()
        )
        for row in candidates:
            if as_utc(row.expires_at) <= now:
                continue
            if matches_hmac(row.device_token_hash, f"device-token:{raw_cookie_token}", length=64):
                row.last_seen_at = now
                row.expires_at = now + max_age
                db.session.commit()
                return DeviceCheckResult(is_new_device=False, device_token=raw_cookie_token)

    new_token = secrets.token_urlsafe(32)
    db.session.add(
        KnownDevice(
            user_id=user.id,
            device_token_hash=device_token_hash(new_token),
            created_at=now,
            last_seen_at=now,
            expires_at=now + max_age,
        )
    )
    db.session.commit()
    return DeviceCheckResult(is_new_device=True, device_token=new_token)


def send_new_device_login_email(
    user: User,
    *,
    ip_address: str,
    user_agent: str,
    login_at: datetime,
) -> bool:
    body = "\n".join(
        [
            EMAIL_GREETING,
            "",
            (
                f"We detected a new sign-in to your e-banking account on "
                f"{summarize_user_agent(user_agent)} on {sgt_date(login_at)} at "
                f"{sgt_time(login_at)} from IP address {display_ip_address(ip_address)}. "
                "If this was you, you don't need to do anything. If not, log in "
                "immediately to terminate the current session and either change your "
                "password, reset your MFA, or freeze your account (with a valid reason)."
            ),
            "",
            "For your security, please do not delay in taking action if you did not initiate this sign-in.",
            "",
            EMAIL_CLOSING,
            "",
            EMAIL_SIGN_OFF,
        ]
    )
    try:
        send_security_email(user.email, "SITBank new device sign-in", body)
    except Exception as exc:
        current_app.logger.warning("new_device_login_notification_failed error=%s", type(exc).__name__)
        audit_event(
            "new_device_login_notification",
            "failure",
            user=user,
            metadata={"reason": "email_delivery_failed"},
        )
        return False
    audit_event("new_device_login_notification", "queued", user=user)
    return True


def forget_known_device_token(user: User, raw_token: str) -> None:
    token_hash = device_token_hash(raw_token)
    db.session.execute(
        db.delete(KnownDevice).where(
            KnownDevice.user_id == user.id,
            KnownDevice.device_token_hash == token_hash,
        )
    )
    db.session.commit()


def resolve_freshly_authenticated_user() -> User | None:
    """Resolve the user who just completed authentication in this request.

    g.current_user is populated by a before_request hook that runs before
    the view executes, so it is stale for a login that only just established
    the session mid-request. session["user_id"] is set synchronously by
    establish_authenticated_session before these callers return, so read
    from there instead.
    """
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.session.get(User, user_id)


def handle_new_device_login(user: User, *, ip_address: str, user_agent: str) -> str:
    """Single entry point for all login-completion call sites.

    Returns the raw device token to set as the cookie. Fires the mandatory
    new-device email exactly once, only when the device is new. Never
    raises: a bookkeeping failure degrades to "treat as new device again
    next time" rather than breaking an already-successful login.
    """
    cookie_name = current_app.config["DEVICE_COOKIE_NAME"]
    raw_cookie_token = request.cookies.get(cookie_name)
    try:
        result = check_and_register_device(user, raw_cookie_token)
    except Exception as exc:
        current_app.logger.warning("device_recognition_check_failed error=%s", type(exc).__name__)
        db.session.rollback()
        return secrets.token_urlsafe(32)

    if result.is_new_device:
        delivered = send_new_device_login_email(
            user,
            ip_address=ip_address,
            user_agent=user_agent,
            login_at=datetime.now(timezone.utc),
        )
        if not delivered:
            try:
                forget_known_device_token(user, result.device_token)
            except Exception as exc:
                current_app.logger.warning("known_device_retry_state_cleanup_failed error=%s", type(exc).__name__)
                db.session.rollback()
    return result.device_token


def apply_device_cookie(response, raw_token: str):
    response.set_cookie(
        current_app.config["DEVICE_COOKIE_NAME"],
        raw_token,
        max_age=current_app.config["DEVICE_COOKIE_MAX_AGE_SECONDS"],
        httponly=True,
        secure=True,
        samesite="Strict",
        path="/",
    )
    return response
