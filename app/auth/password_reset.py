from __future__ import annotations

import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from flask import current_app, has_request_context, request, session
from sqlalchemy import func, or_

from app.extensions import db
from app.models import ManualRecoveryRequest, PasswordResetToken, PasswordResetTransaction, User, WebAuthnCredential
from app.security.audit import (
    audit_event,
    audit_event_required,
    audit_reference,
    audit_system_event,
    principal_reference,
)
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
RESET_TRANSACTION_EXPIRED_ERROR = "Password reset transaction expired"
RESET_TRANSACTION_SESSION_KEY = "password_reset_transaction_id"
GENERIC_AUTHENTICATION_CODE_ERROR = "Invalid authentication code."
GENERIC_VERIFICATION_METHOD_ERROR = "Invalid verification method."
RESET_MFA_TOTP = "totp"
RESET_MFA_MANUAL_RECOVERY = "manual_recovery"
RESET_MFA_NONE = "none"
RESET_MFA_METHODS = frozenset({RESET_MFA_TOTP})
RESET_MFA_PUBLIC_METHODS = frozenset({RESET_MFA_TOTP, RESET_MFA_MANUAL_RECOVERY})
RESET_MFA_METHOD_ALIASES = {
    "authenticator": RESET_MFA_TOTP,
    RESET_MFA_TOTP: RESET_MFA_TOTP,
}
MANUAL_RECOVERY_STATUS_PENDING = "pending"
MANUAL_RECOVERY_STATUS_UNDER_REVIEW = "under_review"
MANUAL_RECOVERY_STATUS_APPROVED = "approved"
MANUAL_RECOVERY_STATUS_DENIED = "denied"
MANUAL_RECOVERY_STATUS_EXPIRED = "expired"
MANUAL_RECOVERY_STATUS_CANCELLED = "cancelled"
MANUAL_RECOVERY_STATUS_COMPLETED = "completed"
MANUAL_RECOVERY_STATUSES = frozenset(
    {
        MANUAL_RECOVERY_STATUS_PENDING,
        MANUAL_RECOVERY_STATUS_UNDER_REVIEW,
        MANUAL_RECOVERY_STATUS_APPROVED,
        MANUAL_RECOVERY_STATUS_DENIED,
        MANUAL_RECOVERY_STATUS_EXPIRED,
        MANUAL_RECOVERY_STATUS_CANCELLED,
        MANUAL_RECOVERY_STATUS_COMPLETED,
    }
)
MANUAL_RECOVERY_ACTIVE_STATUSES = frozenset(
    {
        MANUAL_RECOVERY_STATUS_PENDING,
        MANUAL_RECOVERY_STATUS_UNDER_REVIEW,
        MANUAL_RECOVERY_STATUS_APPROVED,
    }
)
MANUAL_RECOVERY_ALLOWED_TRANSITIONS = {
    MANUAL_RECOVERY_STATUS_PENDING: frozenset(
        {
            MANUAL_RECOVERY_STATUS_UNDER_REVIEW,
            MANUAL_RECOVERY_STATUS_DENIED,
            MANUAL_RECOVERY_STATUS_EXPIRED,
            MANUAL_RECOVERY_STATUS_CANCELLED,
        }
    ),
    MANUAL_RECOVERY_STATUS_UNDER_REVIEW: frozenset(
        {
            MANUAL_RECOVERY_STATUS_APPROVED,
            MANUAL_RECOVERY_STATUS_DENIED,
            MANUAL_RECOVERY_STATUS_EXPIRED,
            MANUAL_RECOVERY_STATUS_CANCELLED,
        }
    ),
    MANUAL_RECOVERY_STATUS_APPROVED: frozenset(
        {
            MANUAL_RECOVERY_STATUS_COMPLETED,
            MANUAL_RECOVERY_STATUS_EXPIRED,
            MANUAL_RECOVERY_STATUS_CANCELLED,
        }
    ),
}


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


def select_reset_mfa_method(method: str) -> dict[str, Any]:
    transaction = _load_current_transaction()
    user = _transaction_user(transaction)
    selected = _normalize_reset_mfa_method(method)
    available_methods = _available_reset_mfa_methods_for_user(user)
    if selected not in available_methods:
        transaction["available_mfa_methods"] = available_methods
        _store_transaction(transaction)
        audit_event(
            "password_reset_mfa_failed",
            "failure",
            user=user,
            metadata={"reason": "unavailable_factor", "requested_factor": selected},
        )
        raise AuthError(GENERIC_VERIFICATION_METHOD_ERROR, 400)

    current_method = str(transaction.get("mfa_required") or RESET_MFA_NONE)
    if transaction.get("mfa_verified") and current_method != selected:
        audit_event(
            "password_reset_mfa_failed",
            "failure",
            user=user,
            metadata={"reason": "already_verified", "requested_factor": selected},
        )
        raise AuthError(GENERIC_VERIFICATION_METHOD_ERROR, 400)

    transaction["available_mfa_methods"] = available_methods
    transaction["mfa_required"] = selected
    if current_method != selected:
        transaction["mfa_verified"] = False
        transaction["recovery_code_verified"] = False
    _store_transaction(transaction)
    audit_event("password_reset_mfa_method_selected", "success", user=user, metadata={"factor": selected})
    return _public_transaction(transaction)


def _verify_reset_authentication_code(code: str, *, submitted_factor: str) -> dict[str, Any]:
    transaction = _load_current_transaction()
    user = _transaction_user(transaction)
    _require_selected_reset_mfa_method(
        transaction,
        user,
        RESET_MFA_TOTP,
        submitted_factor=submitted_factor,
        error_message=GENERIC_AUTHENTICATION_CODE_ERROR,
    )

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


def complete_password_reset(new_password: str, confirm_new_password: str) -> dict[str, Any]:
    transaction = _load_current_transaction()
    user = _transaction_user(transaction)
    if transaction["mfa_required"] != "none" and not transaction.get("mfa_verified"):
        audit_event("password_reset_failed", "failure", user=user, metadata={"reason": "missing_mfa"})
        if transaction["mfa_required"] == RESET_MFA_MANUAL_RECOVERY:
            raise AuthError("Manual account recovery is required before resetting the password", 403)
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
    now = _utcnow()
    user = _find_customer_user(identifier)
    identifier_ref = principal_reference(identifier) or active_hmac_hex(
        f"manual-recovery:{_normalize(identifier)}",
        length=32,
    )
    linked_user = user if user is not None and not _is_admin_like_user(user) else None
    expire_manual_recovery_requests(identifier_ref=identifier_ref, now=now)
    existing_request = _active_manual_recovery_request(identifier_ref, now)
    if existing_request is not None:
        existing_request.request_count = int(existing_request.request_count or 1) + 1
        existing_request.requested_ip = _client_ip()
        existing_request.requested_user_agent = _user_agent()
        existing_request.last_submitted_at = now
        existing_request.updated_at = now
        db.session.commit()
        audit_event(
            "manual_recovery_requested",
            "deduped",
            user=linked_user,
            metadata={
                "principal_ref": identifier_ref,
                "request_ref": _manual_recovery_request_ref(existing_request),
                "status": existing_request.status,
            },
        )
        return {"message": GENERIC_MANUAL_RECOVERY_MESSAGE}

    request_record = ManualRecoveryRequest(
        identifier_ref=identifier_ref,
        user_id=linked_user.id if linked_user is not None else None,
        status=MANUAL_RECOVERY_STATUS_PENDING,
        requested_ip=_client_ip(),
        requested_user_agent=_user_agent(),
        request_count=1,
        created_at=now,
        updated_at=now,
        last_submitted_at=now,
        expires_at=_manual_recovery_expires_at(now),
        status_changed_at=now,
    )
    db.session.add(request_record)
    db.session.commit()
    audit_event(
        "manual_recovery_requested",
        "pending",
        user=linked_user,
        metadata={
            "principal_ref": identifier_ref,
            "request_ref": _manual_recovery_request_ref(request_record),
            "expires_at": _utc_iso(request_record.expires_at),
        },
    )
    if linked_user is not None:
        _send_manual_recovery_requested_notification(linked_user, request_record.expires_at)
    return {"message": GENERIC_MANUAL_RECOVERY_MESSAGE}


def transition_manual_recovery_request(
    request_id: int,
    new_status: str,
    *,
    reason: str | None = None,
) -> dict[str, Any]:
    request_record = _manual_recovery_request_or_error(request_id)
    now = _utcnow()
    old_status = request_record.status
    if _expire_manual_recovery_if_stale(request_record, now):
        db.session.commit()
        _audit_manual_recovery_transition(
            request_record,
            old_status,
            MANUAL_RECOVERY_STATUS_EXPIRED,
            reason="expired_before_transition",
        )
        raise AuthError("Manual recovery request is expired", 409)

    normalized_status = _normalize_manual_recovery_status(new_status)
    old_status = request_record.status
    if normalized_status == old_status:
        return _public_manual_recovery_request(request_record)

    allowed = MANUAL_RECOVERY_ALLOWED_TRANSITIONS.get(old_status, frozenset())
    if normalized_status not in allowed:
        _audit_manual_recovery_transition(
            request_record,
            old_status,
            normalized_status,
            outcome="failure",
            reason="invalid_transition",
        )
        raise AuthError("Invalid manual recovery status transition", 409)

    _set_manual_recovery_status(request_record, normalized_status, now)
    db.session.commit()
    _audit_manual_recovery_transition(request_record, old_status, normalized_status, reason=reason)
    return _public_manual_recovery_request(request_record)


def complete_manual_recovery_request(request_id: int, *, reason: str | None = None) -> dict[str, Any]:
    request_record = _manual_recovery_request_or_error(request_id)
    now = _utcnow()
    old_status = request_record.status
    if _expire_manual_recovery_if_stale(request_record, now):
        db.session.commit()
        _audit_manual_recovery_transition(
            request_record,
            old_status,
            MANUAL_RECOVERY_STATUS_EXPIRED,
            reason="expired_before_completion",
        )
        raise AuthError("Manual recovery request is expired", 409)
    if request_record.status != MANUAL_RECOVERY_STATUS_APPROVED:
        _audit_manual_recovery_transition(
            request_record,
            request_record.status,
            MANUAL_RECOVERY_STATUS_COMPLETED,
            outcome="failure",
            reason="completion_requires_approval",
        )
        raise AuthError("Manual recovery request must be approved before completion", 409)

    user = db.session.get(User, int(request_record.user_id)) if request_record.user_id else None
    if user is None or _is_admin_like_user(user) or _account_reset_blocked(user):
        _audit_manual_recovery_transition(
            request_record,
            request_record.status,
            MANUAL_RECOVERY_STATUS_COMPLETED,
            outcome="failure",
            reason="completion_user_unavailable",
        )
        raise AuthError("Manual recovery request cannot be completed", 409)

    removed_credentials = list(
        db.session.execute(
            db.select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id)
        ).scalars()
    )
    for credential in removed_credentials:
        db.session.delete(credential)
    user.mfa_enabled = False
    user.mfa_secret_nonce = None
    user.mfa_secret_ciphertext = None
    revoked_sessions = revoke_all_sessions(user.id, ended_reason="manual_recovery")
    old_status = request_record.status
    _set_manual_recovery_status(request_record, MANUAL_RECOVERY_STATUS_COMPLETED, now)
    request_record.completed_at = now

    metadata = {
        "request_ref": _manual_recovery_request_ref(request_record),
        "previous_status": old_status,
        "new_status": MANUAL_RECOVERY_STATUS_COMPLETED,
        "reason": reason,
        "revoked_sessions": revoked_sessions,
        "removed_legacy_passkey_credentials": len(removed_credentials),
        "mfa_reenrollment_required": True,
    }
    if has_request_context():
        audit_event_required("manual_recovery_completed", "success", user=user, metadata=metadata)
        db.session.commit()
    else:
        db.session.commit()
        audit_system_event("manual_recovery_completed", "success", user_id=user.id, metadata=metadata)

    _send_manual_recovery_completed_notification(user)
    result = _public_manual_recovery_request(request_record)
    result.update(
        {
            "revoked_sessions": revoked_sessions,
            "removed_legacy_passkey_credentials": len(removed_credentials),
            "mfa_reenrollment_required": True,
        }
    )
    return result


def expire_manual_recovery_requests(
    *,
    now: datetime | None = None,
    identifier_ref: str | None = None,
    limit: int | None = None,
) -> int:
    current_time = now or _utcnow()
    statement = (
        db.select(ManualRecoveryRequest)
        .where(
            ManualRecoveryRequest.status.in_(MANUAL_RECOVERY_ACTIVE_STATUSES),
            ManualRecoveryRequest.expires_at <= current_time,
        )
        .order_by(ManualRecoveryRequest.expires_at.asc(), ManualRecoveryRequest.id.asc())
    )
    if identifier_ref is not None:
        statement = statement.where(ManualRecoveryRequest.identifier_ref == identifier_ref)
    if limit is not None:
        statement = statement.limit(max(1, int(limit)))

    expired_records = list(db.session.execute(statement).scalars())
    previous_statuses: dict[int, str] = {}
    for request_record in expired_records:
        previous_statuses[int(request_record.id)] = request_record.status
        _set_manual_recovery_status(request_record, MANUAL_RECOVERY_STATUS_EXPIRED, current_time)
    if expired_records:
        db.session.commit()
        for request_record in expired_records:
            _audit_manual_recovery_transition(
                request_record,
                previous_statuses[int(request_record.id)],
                MANUAL_RECOVERY_STATUS_EXPIRED,
                reason="ttl_expired",
            )
    return len(expired_records)


def reset_transaction_user_and_id(*, required_method: str | None = None) -> tuple[User, str]:
    transaction = _load_current_transaction()
    user = _transaction_user(transaction)
    if required_method is not None:
        _require_selected_reset_mfa_method(
            transaction,
            user,
            required_method,
            submitted_factor=required_method,
            error_message="Security key verification failed",
        )
    return user, transaction["transaction_id"]


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


def _send_manual_recovery_requested_notification(user: User, expires_at: datetime) -> None:
    expires_text = expires_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = (
        "A manual SITBank account recovery review was requested for your account. "
        f"This request expires at {expires_text}. "
        "If you did not request it, contact support immediately. "
        "This message does not contain account recovery secrets."
    )
    try:
        send_security_email(user.email, "SITBank manual recovery requested", body)
    except Exception as exc:
        current_app.logger.warning("manual_recovery_request_notification_failed error=%s", type(exc).__name__)
        audit_event("manual_recovery_notification", "failure", user=user, metadata={"reason": "email_delivery_failed"})


def _send_manual_recovery_completed_notification(user: User) -> None:
    body = (
        "Manual SITBank account recovery was completed for your account. "
        "Your existing MFA methods were reset and you must re-enroll MFA before normal account use. "
        "If this was not you, contact support immediately."
    )
    try:
        send_security_email(user.email, "SITBank manual recovery completed", body)
    except Exception as exc:
        current_app.logger.warning("manual_recovery_completed_notification_failed error=%s", type(exc).__name__)
        audit_event("manual_recovery_notification", "failure", user=user, metadata={"reason": "email_delivery_failed"})


def _active_manual_recovery_request(identifier_ref: str, now: datetime) -> ManualRecoveryRequest | None:
    return db.session.execute(
        db.select(ManualRecoveryRequest)
        .where(
            ManualRecoveryRequest.identifier_ref == identifier_ref,
            ManualRecoveryRequest.status.in_(MANUAL_RECOVERY_ACTIVE_STATUSES),
            ManualRecoveryRequest.expires_at > now,
        )
        .order_by(ManualRecoveryRequest.created_at.desc(), ManualRecoveryRequest.id.desc())
        .limit(1)
    ).scalar_one_or_none()


def _manual_recovery_request_or_error(request_id: int) -> ManualRecoveryRequest:
    request_record = db.session.get(ManualRecoveryRequest, int(request_id))
    if request_record is None:
        raise AuthError("Manual recovery request not found", 404)
    return request_record


def _manual_recovery_expires_at(now: datetime) -> datetime:
    return now + timedelta(seconds=int(current_app.config["MANUAL_RECOVERY_REQUEST_TTL_SECONDS"]))


def _normalize_manual_recovery_status(status: str) -> str:
    normalized = str(status or "").strip().casefold()
    if normalized not in MANUAL_RECOVERY_STATUSES:
        raise AuthError("Invalid manual recovery status", 400)
    return normalized


def _expire_manual_recovery_if_stale(request_record: ManualRecoveryRequest, now: datetime) -> bool:
    if request_record.status not in MANUAL_RECOVERY_ACTIVE_STATUSES:
        return False
    if _as_utc_datetime(request_record.expires_at) > now:
        return False
    _set_manual_recovery_status(request_record, MANUAL_RECOVERY_STATUS_EXPIRED, now)
    return True


def _set_manual_recovery_status(request_record: ManualRecoveryRequest, status: str, now: datetime) -> None:
    request_record.status = status
    request_record.updated_at = now
    request_record.status_changed_at = now
    if status == MANUAL_RECOVERY_STATUS_COMPLETED:
        request_record.completed_at = now


def _manual_recovery_request_ref(request_record: ManualRecoveryRequest) -> str | None:
    return audit_reference("manual_recovery_request", request_record.id)


def _public_manual_recovery_request(request_record: ManualRecoveryRequest) -> dict[str, Any]:
    return {
        "id": request_record.id,
        "status": request_record.status,
        "expires_at": _utc_iso(request_record.expires_at),
        "request_count": int(request_record.request_count or 0),
        "completed": request_record.completed_at is not None,
    }


def _audit_manual_recovery_transition(
    request_record: ManualRecoveryRequest,
    previous_status: str,
    new_status: str,
    *,
    outcome: str = "success",
    reason: str | None = None,
) -> None:
    metadata = {
        "request_ref": _manual_recovery_request_ref(request_record),
        "previous_status": previous_status,
        "new_status": new_status,
        "reason": reason,
    }
    event_type = "manual_recovery_status_changed"
    if new_status == MANUAL_RECOVERY_STATUS_EXPIRED and outcome == "success":
        event_type = "manual_recovery_expired"
        outcome = "expired"
    if has_request_context():
        audit_event(event_type, outcome, user_id=request_record.user_id, metadata=metadata)
    else:
        audit_system_event(event_type, outcome, user_id=request_record.user_id, metadata=metadata)


def _create_reset_transaction(user: User, token: PasswordResetToken) -> dict[str, Any]:
    mfa_policy = _reset_mfa_policy(user)
    mfa_required = mfa_policy["default_method"]
    transaction = {
        "transaction_id": secrets.token_urlsafe(32),
        "token_id": token.id,
        "user_id": user.id,
        "purpose": "password_reset",
        "mfa_required": mfa_required,
        "available_mfa_methods": mfa_policy["available_methods"],
        "preferred_mfa_method": mfa_policy["preferred_method"],
        "default_mfa_method": mfa_policy["default_method"],
        "mfa_verified": mfa_required == RESET_MFA_NONE,
        "recovery_code_verified": False,
        "no_mfa_user": mfa_required == RESET_MFA_NONE,
        "created_at": _now_timestamp(),
        "failure_count": 0,
    }
    _store_transaction(transaction)
    return transaction


def _store_transaction(transaction: dict[str, Any]) -> None:
    ttl = int(current_app.config["PASSWORD_RESET_TRANSACTION_TTL_SECONDS"])
    now = _utcnow()
    lookup_hash = _transaction_lookup_hash(transaction["transaction_id"])
    record = db.session.execute(
        db.select(PasswordResetTransaction).where(
            PasswordResetTransaction.transaction_lookup_hash == lookup_hash
        )
    ).scalar_one_or_none()
    if record is None:
        record = PasswordResetTransaction(transaction_lookup_hash=lookup_hash)
        db.session.add(record)
    record.token_id = int(transaction["token_id"])
    record.user_id = int(transaction["user_id"])
    record.purpose = str(transaction.get("purpose") or "password_reset")
    record.mfa_required = str(transaction.get("mfa_required") or RESET_MFA_NONE)
    record.available_mfa_methods_json = list(transaction.get("available_mfa_methods") or [])
    record.preferred_mfa_method = transaction.get("preferred_mfa_method")
    record.default_mfa_method = transaction.get("default_mfa_method")
    record.mfa_verified = bool(transaction.get("mfa_verified"))
    record.recovery_code_verified = bool(transaction.get("recovery_code_verified"))
    record.no_mfa_user = bool(transaction.get("no_mfa_user"))
    record.failure_count = int(transaction.get("failure_count") or 0)
    record.last_failure_reason = transaction.get("last_failure_reason")
    record.mfa_verified_at = transaction.get("mfa_verified_at")
    record.expires_at = now + timedelta(seconds=ttl)
    record.used_at = None
    record.updated_at = now
    db.session.commit()


def _load_current_transaction() -> dict[str, Any]:
    transaction_id = str(session.get(RESET_TRANSACTION_SESSION_KEY) or "")
    if not transaction_id:
        raise AuthError("No active password reset transaction", 401)
    return _load_transaction(transaction_id)


def _load_transaction(transaction_id: str) -> dict[str, Any]:
    record = db.session.execute(
        db.select(PasswordResetTransaction).where(
            PasswordResetTransaction.transaction_lookup_hash == _transaction_lookup_hash(transaction_id)
        )
    ).scalar_one_or_none()
    if record is None:
        clear_current_reset_transaction()
        raise AuthError(RESET_TRANSACTION_EXPIRED_ERROR, 401)
    if (
        record.purpose != "password_reset"
        or record.used_at is not None
        or _as_utc_datetime(record.expires_at) <= _utcnow()
    ):
        _delete_transaction_id(transaction_id)
        raise AuthError(RESET_TRANSACTION_EXPIRED_ERROR, 401)
    return _transaction_from_record(record, transaction_id)


def _clear_reset_transaction(transaction: dict[str, Any]) -> None:
    tx_id = str(transaction.get("transaction_id") or "")
    if tx_id:
        _delete_transaction_id(tx_id)


def _delete_transaction_id(transaction_id: str) -> None:
    record = db.session.execute(
        db.select(PasswordResetTransaction).where(
            PasswordResetTransaction.transaction_lookup_hash == _transaction_lookup_hash(transaction_id)
        )
    ).scalar_one_or_none()
    if record is not None:
        db.session.delete(record)
        db.session.commit()


def _record_transaction_failure(transaction: dict[str, Any], reason: str) -> None:
    transaction["failure_count"] = int(transaction.get("failure_count") or 0) + 1
    transaction["last_failure_reason"] = reason
    if transaction["failure_count"] >= 5:
        _clear_reset_transaction(transaction)
        session.pop(RESET_TRANSACTION_SESSION_KEY, None)
        session.modified = True
        raise AuthError(RESET_TRANSACTION_EXPIRED_ERROR, 401)
    _store_transaction(transaction)


def _transaction_user(transaction: dict[str, Any]) -> User:
    user = db.session.get(User, int(transaction["user_id"]))
    if user is None or _is_admin_like_user(user) or _account_reset_blocked(user):
        _clear_reset_transaction(transaction)
        raise AuthError(RESET_TRANSACTION_EXPIRED_ERROR, 401)
    return user


def _public_transaction(transaction: dict[str, Any]) -> dict[str, Any]:
    available_methods = _available_reset_mfa_methods_from_transaction(transaction)
    return {
        "message": "Password reset transaction active",
        "mfa_required": transaction["mfa_required"],
        "available_mfa_methods": available_methods,
        "preferred_mfa_method": _public_reset_mfa_method(transaction.get("preferred_mfa_method")),
        "default_mfa_method": _public_reset_mfa_method(transaction.get("default_mfa_method")),
        "mfa_verified": bool(transaction.get("mfa_verified")),
        "recovery_code_verified": bool(transaction.get("recovery_code_verified")),
        "no_mfa_user": bool(transaction.get("no_mfa_user")),
        "expires_in": _transaction_expires_in(transaction),
    }


def _mfa_requirement(user: User) -> str:
    return _reset_mfa_policy(user)["default_method"]


def _reset_mfa_policy(user: User) -> dict[str, Any]:
    available_methods = _available_reset_mfa_methods_for_user(user)
    preferred_method = _profile_preference_to_reset_method(user.mfa_step_up_preference)
    if preferred_method not in available_methods:
        preferred_method = None
    default_method = preferred_method or _fallback_reset_mfa_method(available_methods)
    return {
        "available_methods": available_methods,
        "preferred_method": preferred_method,
        "default_method": default_method,
    }


def _available_reset_mfa_methods_for_user(user: User) -> list[str]:
    methods: list[str] = []
    if user.mfa_enabled:
        methods.append(RESET_MFA_TOTP)
    elif _legacy_passkey_credential_count(user) > 0:
        methods.append(RESET_MFA_MANUAL_RECOVERY)
    return methods


def _legacy_passkey_credential_count(user: User) -> int:
    if user.id is None:
        return 0
    return int(
        db.session.execute(
            db.select(func.count(WebAuthnCredential.id)).where(WebAuthnCredential.user_id == user.id)
        ).scalar_one()
    )


def _available_reset_mfa_methods_from_transaction(transaction: dict[str, Any]) -> list[str]:
    raw_methods = transaction.get("available_mfa_methods")
    if isinstance(raw_methods, list):
        methods: list[str] = []
        for raw_method in raw_methods:
            method = _public_reset_mfa_method(raw_method)
            if method in RESET_MFA_PUBLIC_METHODS and method not in methods:
                methods.append(method)
        return methods
    required = _public_reset_mfa_method(transaction.get("mfa_required"))
    return [required] if required in RESET_MFA_PUBLIC_METHODS else []


def _fallback_reset_mfa_method(available_methods: list[str]) -> str:
    if RESET_MFA_TOTP in available_methods:
        return RESET_MFA_TOTP
    if RESET_MFA_MANUAL_RECOVERY in available_methods:
        return RESET_MFA_MANUAL_RECOVERY
    return RESET_MFA_NONE


def _profile_preference_to_reset_method(value: str | None) -> str | None:
    normalized = str(value or "").strip().casefold()
    return RESET_MFA_METHOD_ALIASES.get(normalized)


def _normalize_reset_mfa_method(value: str | None) -> str:
    normalized = str(value or "").strip().casefold()
    method = RESET_MFA_METHOD_ALIASES.get(normalized)
    if method not in RESET_MFA_METHODS:
        raise AuthError(GENERIC_VERIFICATION_METHOD_ERROR, 400)
    return method


def _public_reset_mfa_method(value: Any) -> str | None:
    if str(value or "").strip().casefold() == RESET_MFA_MANUAL_RECOVERY:
        return RESET_MFA_MANUAL_RECOVERY
    method = _profile_preference_to_reset_method(str(value or ""))
    return method if method in RESET_MFA_METHODS else None


def _require_selected_reset_mfa_method(
    transaction: dict[str, Any],
    user: User,
    required_method: str,
    *,
    submitted_factor: str,
    error_message: str,
) -> None:
    selected = _normalize_reset_mfa_method(required_method)
    available_methods = _available_reset_mfa_methods_for_user(user)
    transaction["available_mfa_methods"] = available_methods
    if selected not in available_methods or transaction.get("mfa_required") != selected:
        _store_transaction(transaction)
        audit_event(
            "password_reset_mfa_failed",
            "failure",
            user=user,
            metadata={
                "reason": "wrong_factor",
                "submitted_factor": submitted_factor,
                "required_factor": transaction.get("mfa_required"),
            },
        )
        raise AuthError(error_message, 400)


def _find_customer_user(identifier: str) -> User | None:
    normalized = _normalize(identifier)
    if not normalized:
        return None
    return db.session.execute(
        db.select(User).where(
            or_(
                func.lower(User.username) == normalized,
                func.lower(User.email) == normalized,
            ),
            User.account_type == "customer",
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
    if getattr(user, "account_type", "customer") != "customer":
        return True
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


def _transaction_lookup_hash(transaction_id: str) -> str:
    return active_hmac_hex(f"password-reset-transaction:{transaction_id}", length=64)


def _transaction_from_record(record: PasswordResetTransaction, transaction_id: str) -> dict[str, Any]:
    return {
        "transaction_id": transaction_id,
        "token_id": record.token_id,
        "user_id": record.user_id,
        "purpose": record.purpose,
        "mfa_required": record.mfa_required,
        "available_mfa_methods": list(record.available_mfa_methods_json or []),
        "preferred_mfa_method": record.preferred_mfa_method,
        "default_mfa_method": record.default_mfa_method,
        "mfa_verified": bool(record.mfa_verified),
        "recovery_code_verified": bool(record.recovery_code_verified),
        "no_mfa_user": bool(record.no_mfa_user),
        "failure_count": int(record.failure_count or 0),
        "last_failure_reason": record.last_failure_reason,
        "mfa_verified_at": record.mfa_verified_at,
        "created_at": int(record.created_at.timestamp()),
        "expires_at": int(_as_utc_datetime(record.expires_at).timestamp()),
    }


def _transaction_expires_in(transaction: dict[str, Any]) -> int:
    expires_at = transaction.get("expires_at")
    try:
        return max(0, int(expires_at) - _now_timestamp())
    except (TypeError, ValueError):
        return int(current_app.config["PASSWORD_RESET_TRANSACTION_TTL_SECONDS"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utc_iso(value: datetime) -> str:
    return _as_utc_datetime(value).isoformat()


def _now_timestamp() -> int:
    return int(time.time())
