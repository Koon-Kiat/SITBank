from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from flask import current_app, request, session
from sqlalchemy import func, or_

from app.extensions import db
from app.models import ManualRecoveryRequest, PasswordResetToken, User
from app.security.audit import audit_event, audit_event_required, audit_reference, principal_reference
from app.security.email import send_security_email
from app.security.passwords import PasswordPolicyError, hash_password, validate_password_policy, verify_password
from app.security.rate_limits import AuthBackoffRequired, apply_exponential_backoff, clear_failures, record_failure
from app.security.session_hmac import active_hmac_hex
from app.security.sessions import revoke_all_sessions, rotate_session_id

from .recovery_codes import (
    consume_recovery_code,
    generate_recovery_codes_for_user,
    send_recovery_code_used_notification,
)
from .services import AuthError, _verify_totp_for_user


GENERIC_FORGOT_PASSWORD_MESSAGE = "If an account exists for that email, a reset link has been sent."
GENERIC_MANUAL_RECOVERY_MESSAGE = "If the account can be reviewed, a recovery request has been recorded."
GENERIC_RESET_ERROR = "Password reset link is invalid or expired"
RESET_TRANSACTION_SESSION_KEY = "password_reset_transaction_id"
RESET_TRANSACTION_PREFIX = "ospbank:password_reset_transaction:"
GENERIC_AUTHENTICATION_CODE_ERROR = "Invalid authentication code."


def request_password_reset(identifier: str) -> dict[str, str]:
    normalized = _normalize(identifier)
    user = _find_customer_user(normalized)
    audit_event(
        "password_reset_requested",
        "success",
        user=user,
        metadata={"principal_ref": principal_reference(identifier)},
    )

    if not current_app.config.get("PASSWORD_RESET_ENABLED", True):
        audit_event("password_reset_failed", "blocked", user=user, metadata={"reason": "password_reset_disabled"})
        return {"message": GENERIC_FORGOT_PASSWORD_MESSAGE}

    if user is None or _is_admin_like_user(user) or _account_reset_blocked(user):
        if user is not None and _is_admin_like_user(user):
            audit_event("password_reset_failed", "blocked", user=user, metadata={"reason": "admin_out_of_scope"})
        return {"message": GENERIC_FORGOT_PASSWORD_MESSAGE}

    token, reset_url, expires_at = _create_reset_token(user)
    try:
        _send_password_reset_email(user, reset_url, expires_at)
    except Exception as exc:
        current_app.logger.warning("password_reset_email_failed error=%s", type(exc).__name__)
        audit_event("password_reset_failed", "failure", user=user, metadata={"reason": "email_delivery_failed"})
        return {"message": GENERIC_FORGOT_PASSWORD_MESSAGE}

    audit_event(
        "password_reset_token_created",
        "success",
        user=user,
        metadata={"token_ref": audit_reference("password_reset_selector", token.selector)},
    )
    return {"message": GENERIC_FORGOT_PASSWORD_MESSAGE}


def exchange_reset_token(raw_token: str) -> dict[str, Any]:
    selector, verifier = _split_reset_token(raw_token)
    token = _token_by_selector(selector, lock=True)
    if token is None:
        audit_event("password_reset_failed", "failure", metadata={"reason": "invalid_selector"})
        raise AuthError(GENERIC_RESET_ERROR, 401)

    now = _utcnow()
    user = db.session.get(User, token.user_id)
    if (
        user is None
        or token.purpose != "password_reset"
        or token.used_at is not None
        or token.exchanged_at is not None
        or _as_utc_datetime(token.expires_at) <= now
        or not hmac.compare_digest(token.verifier_hmac, _token_hmac(verifier))
        or _is_admin_like_user(user)
        or _account_reset_blocked(user)
    ):
        reason = _token_failure_reason(token, now, verifier, user)
        if reason == "reused":
            audit_event("password_reset_token_reused", "failure", user=user)
        elif reason == "expired":
            audit_event("password_reset_token_expired", "expired", user=user)
        else:
            audit_event("password_reset_failed", "failure", user=user, metadata={"reason": reason})
        raise AuthError(GENERIC_RESET_ERROR, 401)

    token.exchanged_at = now
    db.session.commit()
    audit_event(
        "password_reset_token_validated",
        "success",
        user=user,
        metadata={"token_ref": audit_reference("password_reset_selector", selector)},
    )
    transaction = _create_reset_transaction(user, token)
    session.clear()
    session.permanent = True
    session[RESET_TRANSACTION_SESSION_KEY] = transaction["transaction_id"]
    session["last_activity_at"] = int(time.time())
    rotate_session_id()
    audit_event(
        "password_reset_token_exchanged",
        "success",
        user=user,
        metadata={
            "token_ref": audit_reference("password_reset_selector", selector),
            "transaction_ref": audit_reference("password_reset_transaction", transaction["transaction_id"]),
        },
    )
    audit_event(
        "password_reset_transaction_created",
        "success",
        user=user,
        metadata={"mfa_required": transaction["mfa_required"]},
    )
    if transaction["mfa_required"] != "none":
        audit_event("password_reset_mfa_required", "required", user=user, metadata={"factor": transaction["mfa_required"]})
    return _public_transaction(transaction)


def current_reset_transaction() -> dict[str, Any]:
    transaction = _load_current_transaction()
    return _public_transaction(transaction)


def verify_reset_totp(code: str) -> dict[str, Any]:
    return _verify_reset_authentication_code(code, submitted_factor="authentication_code")


def _verify_reset_authentication_code(code: str, *, submitted_factor: str) -> dict[str, Any]:
    transaction = _load_current_transaction()
    user = _transaction_user(transaction)
    if transaction["mfa_required"] != "totp":
        audit_event(
            "password_reset_mfa_failed",
            "failure",
            user=user,
            metadata={
                "reason": "wrong_factor",
                "submitted_factor": submitted_factor,
                "required_factor": transaction["mfa_required"],
            },
        )
        raise AuthError(GENERIC_AUTHENTICATION_CODE_ERROR, 400)

    if _is_totp_code(code):
        if not _verify_totp_for_user(user, code, "password_reset_mfa"):
            _record_transaction_failure(transaction, "totp_failed")
            audit_event("password_reset_mfa_failed", "failure", user=user, metadata={"factor": "totp"})
            raise AuthError(GENERIC_AUTHENTICATION_CODE_ERROR, 401)
        factor = "totp"
    else:
        _enforce_reset_backoff("password_reset_recovery_code", transaction["transaction_id"])
        if not consume_recovery_code(user, code, commit=False):
            record_failure("password_reset_recovery_code", transaction["transaction_id"])
            _record_transaction_failure(transaction, "recovery_code_failed")
            audit_event("password_reset_mfa_failed", "failure", user=user, metadata={"factor": "recovery_code"})
            raise AuthError(GENERIC_AUTHENTICATION_CODE_ERROR, 401)
        clear_failures("password_reset_recovery_code", transaction["transaction_id"])
        transaction["recovery_code_verified"] = True
        factor = "recovery_code"

    audit_event_required("password_reset_mfa_verified", "success", user=user, metadata={"factor": factor})
    db.session.commit()
    if factor == "recovery_code":
        _send_recovery_code_used_notification(user)
    transaction["mfa_verified"] = True
    transaction["mfa_verified_at"] = _now_timestamp()
    _store_transaction(transaction)
    return _public_transaction(transaction)


def mark_reset_webauthn_verified(transaction_id: str, user_id: int) -> dict[str, Any]:
    transaction = _load_transaction(transaction_id)
    if int(transaction["user_id"]) != int(user_id) or transaction["mfa_required"] != "webauthn":
        audit_event("password_reset_webauthn_failed", "failure", user_id=user_id, metadata={"reason": "transaction_mismatch"})
        raise AuthError("Security key verification failed", 401)
    transaction["mfa_verified"] = True
    transaction["mfa_verified_at"] = _now_timestamp()
    _store_transaction(transaction)
    return _public_transaction(transaction)


def complete_password_reset(new_password: str, confirm_new_password: str) -> dict[str, Any]:
    transaction = _load_current_transaction()
    user = _transaction_user(transaction)
    if transaction["mfa_required"] != "none" and not transaction.get("mfa_verified"):
        audit_event("password_reset_failed", "failure", user=user, metadata={"reason": "missing_mfa"})
        raise AuthError("MFA verification is required before resetting the password", 403)
    if new_password != confirm_new_password:
        audit_event("password_reset_failed", "failure", user=user, metadata={"reason": "password_mismatch"})
        raise AuthError("Passwords must match", 400)
    if verify_password(new_password, user.password_hash):
        audit_event("password_reset_failed", "failure", user=user, metadata={"reason": "password_reuse"})
        raise AuthError("New password must be different from the current password", 400)

    try:
        password_policy_warnings = validate_password_policy(new_password)
    except PasswordPolicyError as exc:
        audit_event("password_reset_failed", "failure", user=user, metadata={"reason": "password_policy"})
        raise AuthError(str(exc), 400) from exc

    now = _utcnow()
    user.password_hash = hash_password(new_password)
    user.failed_login_count = 0
    for token in db.session.execute(
        db.select(PasswordResetToken).where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        )
    ).scalars():
        token.used_at = now

    revoked = revoke_all_sessions(user.id, ended_reason="password_reset")
    audit_event_required(
        "password_reset_completed",
        "success",
        user=user,
        metadata={
            "revoked_sessions": revoked,
            "mfa_required": transaction["mfa_required"],
            "recovery_code_used": bool(transaction.get("recovery_code_verified")),
            "password_screening": "local_only_fallback" if password_policy_warnings else "local_and_live",
        },
    )
    db.session.commit()
    _clear_reset_transaction(transaction)
    session.clear()
    clear_failures("login", _auth_principal(user.username))
    clear_failures("login", _auth_principal(user.email))
    try:
        _send_password_reset_notification(user)
    except Exception as exc:
        current_app.logger.warning("password_reset_notification_failed error=%s", type(exc).__name__)
        audit_event("password_reset_notification", "failure", user=user, metadata={"reason": "email_delivery_failed"})
    return {
        "message": "Password reset completed. Please log in.",
        "revoked_sessions": revoked,
        "warnings": password_policy_warnings,
    }


def request_manual_recovery(identifier: str) -> dict[str, str]:
    user = _find_customer_user(identifier)
    identifier_ref = principal_reference(identifier) or active_hmac_hex(
        f"manual-recovery:{_normalize(identifier)}",
        length=32,
    )
    linked_user = user if user is not None and not _is_admin_like_user(user) else None
    request_record = ManualRecoveryRequest(
        identifier_ref=identifier_ref,
        user_id=linked_user.id if linked_user is not None else None,
        status="pending",
        requested_ip=_client_ip(),
        requested_user_agent=_user_agent(),
    )
    db.session.add(request_record)
    db.session.commit()
    audit_event(
        "manual_recovery_requested",
        "pending",
        user=linked_user,
        metadata={"principal_ref": identifier_ref},
    )
    return {"message": GENERIC_MANUAL_RECOVERY_MESSAGE}


def reset_transaction_user_and_id() -> tuple[User, str]:
    transaction = _load_current_transaction()
    return _transaction_user(transaction), transaction["transaction_id"]


def reset_transaction_id() -> str:
    return str(session.get(RESET_TRANSACTION_SESSION_KEY) or "")


def clear_current_reset_transaction() -> None:
    tx_id = reset_transaction_id()
    if tx_id:
        _delete_transaction_id(tx_id)
    session.pop(RESET_TRANSACTION_SESSION_KEY, None)
    session.modified = True


def _create_reset_token(user: User) -> tuple[PasswordResetToken, str, datetime]:
    selector = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(32)
    expires_at = _utcnow() + timedelta(seconds=int(current_app.config["PASSWORD_RESET_TOKEN_TTL_SECONDS"]))
    token = PasswordResetToken(
        selector=selector,
        verifier_hmac=_token_hmac(verifier),
        user_id=user.id,
        purpose="password_reset",
        expires_at=expires_at,
        requested_ip=_client_ip(),
        requested_user_agent=_user_agent(),
    )
    db.session.add(token)
    db.session.commit()
    raw_token = f"{selector}.{verifier}"
    return token, f"{_base_url()}/reset-password?token={quote(raw_token, safe='')}", expires_at


def _send_password_reset_email(user: User, reset_url: str, expires_at: datetime) -> None:
    expires_text = expires_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = (
        "Use this SITBank password reset link to continue your account recovery:\n\n"
        f"{reset_url}\n\n"
        f"This link expires at {expires_text}. "
        "If you did not request it, ignore this email and keep your MFA enrolled."
    )
    send_security_email(user.email, "SITBank password reset", body)


def _send_password_reset_notification(user: User) -> None:
    body = (
        "Your SITBank password was reset. If this was not you, contact support immediately. "
        "This message does not contain account recovery secrets."
    )
    send_security_email(user.email, "SITBank password reset completed", body)


def _create_reset_transaction(user: User, token: PasswordResetToken) -> dict[str, Any]:
    mfa_required = _mfa_requirement(user)
    transaction = {
        "transaction_id": secrets.token_urlsafe(32),
        "token_id": token.id,
        "user_id": user.id,
        "purpose": "password_reset",
        "mfa_required": mfa_required,
        "mfa_verified": mfa_required == "none",
        "recovery_code_verified": False,
        "no_mfa_user": mfa_required == "none",
        "created_at": _now_timestamp(),
        "failure_count": 0,
    }
    _store_transaction(transaction)
    return transaction


def _store_transaction(transaction: dict[str, Any]) -> None:
    ttl = int(current_app.config["PASSWORD_RESET_TRANSACTION_TTL_SECONDS"])
    _redis().set(_transaction_key(transaction["transaction_id"]), json.dumps(transaction, separators=(",", ":")), ex=ttl)


def _load_current_transaction() -> dict[str, Any]:
    transaction_id = str(session.get(RESET_TRANSACTION_SESSION_KEY) or "")
    if not transaction_id:
        raise AuthError("No active password reset transaction", 401)
    return _load_transaction(transaction_id)


def _load_transaction(transaction_id: str) -> dict[str, Any]:
    raw = _redis().get(_transaction_key(transaction_id))
    if not raw:
        clear_current_reset_transaction()
        raise AuthError("Password reset transaction expired", 401)
    try:
        transaction = json.loads(raw)
    except json.JSONDecodeError as exc:
        _delete_transaction_id(transaction_id)
        raise AuthError("Password reset transaction expired", 401) from exc
    if not isinstance(transaction, dict) or transaction.get("purpose") != "password_reset":
        _delete_transaction_id(transaction_id)
        raise AuthError("Password reset transaction expired", 401)
    if transaction.get("transaction_id") != transaction_id:
        _delete_transaction_id(transaction_id)
        raise AuthError("Password reset transaction expired", 401)
    return transaction


def _clear_reset_transaction(transaction: dict[str, Any]) -> None:
    tx_id = str(transaction.get("transaction_id") or "")
    if tx_id:
        _delete_transaction_id(tx_id)
        _redis().delete(f"ospbank:password_reset_webauthn:{tx_id}")


def _delete_transaction_id(transaction_id: str) -> None:
    _redis().delete(_transaction_key(transaction_id))


def _record_transaction_failure(transaction: dict[str, Any], reason: str) -> None:
    transaction["failure_count"] = int(transaction.get("failure_count") or 0) + 1
    transaction["last_failure_reason"] = reason
    if transaction["failure_count"] >= 5:
        _clear_reset_transaction(transaction)
        session.pop(RESET_TRANSACTION_SESSION_KEY, None)
        session.modified = True
        raise AuthError("Password reset transaction expired", 401)
    _store_transaction(transaction)


def _transaction_user(transaction: dict[str, Any]) -> User:
    user = db.session.get(User, int(transaction["user_id"]))
    if user is None or _is_admin_like_user(user) or _account_reset_blocked(user):
        _clear_reset_transaction(transaction)
        raise AuthError("Password reset transaction expired", 401)
    return user


def _public_transaction(transaction: dict[str, Any]) -> dict[str, Any]:
    return {
        "message": "Password reset transaction active",
        "mfa_required": transaction["mfa_required"],
        "mfa_verified": bool(transaction.get("mfa_verified")),
        "recovery_code_verified": bool(transaction.get("recovery_code_verified")),
        "no_mfa_user": bool(transaction.get("no_mfa_user")),
        "expires_in": int(current_app.config["PASSWORD_RESET_TRANSACTION_TTL_SECONDS"]),
    }


def _mfa_requirement(user: User) -> str:
    if user.mfa_enabled:
        return "totp"
    from app.auth.webauthn_services import webauthn_credential_count

    if webauthn_credential_count(user) > 0:
        return "webauthn"
    return "none"


def _find_customer_user(identifier: str) -> User | None:
    normalized = _normalize(identifier)
    if not normalized:
        return None
    return db.session.execute(
        db.select(User).where(
            or_(
                func.lower(User.username) == normalized,
                func.lower(User.email) == normalized,
            )
        )
    ).scalar_one_or_none()


def _token_by_selector(selector: str, *, lock: bool) -> PasswordResetToken | None:
    statement = db.select(PasswordResetToken).where(PasswordResetToken.selector == selector)
    if lock and db.engine.dialect.name == "postgresql":
        statement = statement.with_for_update()
    return db.session.execute(statement).scalar_one_or_none()


def _token_failure_reason(token: PasswordResetToken, now: datetime, verifier: str, user: User | None) -> str:
    if token.used_at is not None or token.exchanged_at is not None:
        return "reused"
    if _as_utc_datetime(token.expires_at) <= now:
        return "expired"
    if user is None:
        return "missing_user"
    if _is_admin_like_user(user):
        return "admin_out_of_scope"
    if _account_reset_blocked(user):
        return "account_unavailable"
    if not hmac.compare_digest(token.verifier_hmac, _token_hmac(verifier)):
        return "invalid_verifier"
    return "invalid"


def _split_reset_token(raw_token: str) -> tuple[str, str]:
    selector, separator, verifier = str(raw_token or "").partition(".")
    if separator != "." or not selector or not verifier or len(selector) > 64 or len(verifier) > 128:
        raise AuthError(GENERIC_RESET_ERROR, 401)
    return selector, verifier


def _token_hmac(verifier: str) -> str:
    return active_hmac_hex(f"password-reset-token:{verifier}", length=64)


def _account_reset_blocked(user: User) -> bool:
    return bool(user.is_frozen or user.security_locked_at is not None)


def _is_admin_like_user(user: User) -> bool:
    username = str(user.username or "").strip().casefold()
    email = str(user.email or "").strip().casefold()
    local, _separator, domain = email.partition("@")
    admin_names = {"admin", "administrator", "root", "superuser"}
    return username in admin_names or local in admin_names or domain.startswith("admin.")


def _enforce_reset_backoff(scope: str, principal: str) -> None:
    try:
        apply_exponential_backoff(scope, principal)
    except AuthBackoffRequired as exc:
        audit_event("auth_backoff", "blocked", metadata={"scope": scope, "retry_after": exc.retry_after})
        raise AuthError("Too many attempts. Please try again later.", 429, retry_after=exc.retry_after) from exc


def _is_totp_code(code: str) -> bool:
    text = str(code or "")
    return len(text) == 6 and text.isdigit()


def _send_recovery_code_used_notification(user: User) -> None:
    try:
        send_recovery_code_used_notification(user)
    except Exception as exc:
        current_app.logger.warning("recovery_code_notification_failed error=%s", type(exc).__name__)
        audit_event("recovery_code_notification", "failure", user=user, metadata={"reason": "email_delivery_failed"})


def _auth_principal(identifier: str) -> str:
    return f"{_client_ip()}:{_normalize(identifier)}"


def _normalize(value: str) -> str:
    return str(value or "").strip().casefold()


def _base_url() -> str:
    return str(current_app.config["PASSWORD_RESET_BASE_URL"]).rstrip("/")


def _client_ip() -> str:
    return request.remote_addr or "unknown"


def _user_agent() -> str:
    return (request.user_agent.string or "unknown")[:256]


def _redis():
    return current_app.extensions["redis"]


def _transaction_key(transaction_id: str) -> str:
    digest = hashlib.sha256(transaction_id.encode("utf-8")).hexdigest()
    return f"{RESET_TRANSACTION_PREFIX}{digest}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _now_timestamp() -> int:
    return int(time.time())
