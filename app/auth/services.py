from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidTag
import pyotp
import qrcode
from flask import current_app, request, session
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import User
from app.auth.registration_otp import (
    RegistrationOtpError,
    consume_verified_registration_email,
    require_verified_registration_email,
)
from app.auth.mfa_policy import (
    PASSWORD_BOOTSTRAP_AUTH_CONTEXT,
    enrolled_webauthn_credential_count,
    has_enrolled_mfa_method,
)
from app.security.audit import audit_event, audit_event_required, principal_reference
from app.security.crypto import decrypt_mfa_secret, encrypt_mfa_secret
from app.security.passwords import (
    PasswordPolicyError,
    hash_password,
    is_password_raw_length_safe,
    password_hash_needs_rehash,
    validate_password_policy,
    verify_password,
)
from app.security.rate_limits import AuthBackoffRequired, apply_exponential_backoff, clear_failures, record_failure
from app.security.sessions import (
    begin_password_authenticated_session,
    current_session_id,
    establish_authenticated_session,
    has_recent_fresh_mfa,
    list_active_sessions,
    list_past_sessions,
    mark_fresh_mfa,
    public_session_reference,
    require_stable_session_for_sensitive_action,
    revoke_all_sessions,
    revoke_current_session,
    revoke_other_sessions,
    revoke_session,
    resolve_session_reference_for_user,
    rotate_authenticated_session_after_mfa,
)

from .recovery_codes import (
    RECOVERY_CODE_LOW_THRESHOLD,
    consume_recovery_code,
    generate_recovery_codes_for_user,
    send_recovery_code_used_notification,
    unused_recovery_code_count,
)


GENERIC_LOGIN_ERROR = "Invalid username or password"
GENERIC_MFA_ERROR = "Invalid authentication code."
AUTH_BACKOFF_ERROR = "Too many attempts. Please try again later."
ACCOUNT_AUTH_UNAVAILABLE_ERROR = "Authentication unavailable for this account"
AUTH_LOCK_THRESHOLD = 10
AUTH_LOCK_WINDOW_SECONDS = 15 * 60
MFA_REPLACEMENT_NONCE_KEY = "mfa_replacement_secret_nonce"
MFA_REPLACEMENT_CIPHERTEXT_KEY = "mfa_replacement_secret_ciphertext"
MFA_REPLACEMENT_STARTED_AT_KEY = "mfa_replacement_started_at"


class AuthError(ValueError):
    def __init__(self, message: str, status_code: int = 400, *, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.retry_after = retry_after


class FrozenAccountError(AuthError):
    pass


def _redis():
    return current_app.extensions["redis"]


def _normalize(value: str) -> str:
    return value.strip().casefold()


def _normalize_step_up_preference(value: str | None) -> str:
    normalized = str(value or "totp").strip().casefold()
    if normalized not in {"totp", "passkey"}:
        raise AuthError("Invalid verification preference", 400)
    return normalized


def _client_ip() -> str:
    return request.remote_addr or "unknown"


def _auth_principal(identifier: str) -> str:
    return f"{_client_ip()}:{_normalize(identifier)}"


def _enforce_auth_backoff(scope: str, principal: str) -> None:
    try:
        apply_exponential_backoff(scope, principal)
    except AuthBackoffRequired as exc:
        audit_event(
            "auth_backoff",
            "blocked",
            metadata={"scope": scope, "retry_after": exc.retry_after},
        )
        raise AuthError(AUTH_BACKOFF_ERROR, 429, retry_after=exc.retry_after) from exc


def _dummy_password_hash() -> str:
    config_fingerprint = hashlib.sha256(
        (
            f"{current_app.config['PASSWORD_PBKDF2_ITERATIONS']}:"
            f"{current_app.config['PASSWORD_PEPPER_B64']}"
        ).encode("utf-8")
    ).hexdigest()
    cached = current_app.config.get("_DUMMY_PASSWORD_HASH")
    cached_fingerprint = current_app.config.get("_DUMMY_PASSWORD_HASH_CONFIG")
    if cached and hmac.compare_digest(str(cached_fingerprint), config_fingerprint):
        return str(cached)
    dummy = hash_password("not-a-real-sitbank-password")
    current_app.config["_DUMMY_PASSWORD_HASH"] = dummy
    current_app.config["_DUMMY_PASSWORD_HASH_CONFIG"] = config_fingerprint
    return dummy


def warm_dummy_password_hash() -> None:
    _dummy_password_hash()


def _find_user_by_identifier(identifier: str) -> User | None:
    normalized = _normalize(identifier)
    return db.session.execute(
        db.select(User).where(
            or_(
                func.lower(User.username) == normalized,
                func.lower(User.email) == normalized,
            )
        )
    ).scalar_one_or_none()


def _find_user_by_username_or_email(username: str, email: str) -> User | None:
    username_normalized = _normalize(username)
    email_normalized = _normalize(email)
    return db.session.execute(
        db.select(User).where(
            or_(
                func.lower(User.username) == username_normalized,
                func.lower(User.email) == email_normalized,
            )
        )
    ).scalar_one_or_none()


def _find_user_by_registration_fields(username: str, email: str, phone_number: str) -> User | None:
    return db.session.execute(
        db.select(User).where(
            or_(
                func.lower(User.username) == _normalize(username),
                func.lower(User.email) == _normalize(email),
                User.phone_number == phone_number.strip(),
            )
        )
    ).scalar_one_or_none()


def _generate_account_number() -> str:
    for _ in range(10):
        candidate = "012" + "".join(str(secrets.randbelow(10)) for _ in range(6))
        if not db.session.execute(db.select(User).where(User.account_number == candidate)).scalar_one_or_none():
            return candidate
    raise AuthError("Could not generate a unique account number", 500)


def register_user(data: dict[str, Any]) -> tuple[User, list[str]]:
    try:
        normalized_email = require_verified_registration_email(data["email"])
    except RegistrationOtpError as exc:
        raise AuthError(str(exc), exc.status_code) from exc

    if data.get("password") != data.get("confirm_password"):
        audit_event("registration", "failure", metadata={"reason": "password_mismatch"})
        raise AuthError("Passwords must match", 400)

    try:
        password_policy_warnings = validate_password_policy(data["password"])
    except PasswordPolicyError as exc:
        audit_event("registration", "failure", metadata={"reason": "password_policy"})
        raise AuthError(str(exc), 400) from exc

    if _find_user_by_registration_fields(data["username"], normalized_email, data["phone_number"]):
        audit_event("registration", "failure", metadata={"reason": "duplicate_identifier"})
        raise AuthError("Registration could not be completed with those details", 400)

    user = User(
        username=data["username"].strip(),
        email=normalized_email,
        password_hash=hash_password(data["password"]),
        full_name=data["full_name"].strip(),
        phone_number=data["phone_number"].strip(),
        account_number=_generate_account_number(),
    )
    db.session.add(user)
    try:
        db.session.flush()
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        audit_event("registration", "failure", metadata={"reason": "integrity_error"})
        raise AuthError("Registration could not be completed with those details", 400) from exc
    consume_verified_registration_email(normalized_email)
    audit_event(
        "registration",
        "success",
        user=user,
        metadata={
            "password_screening": (
                "local_only_fallback" if password_policy_warnings else "local_and_live"
            )
        },
    )
    return user, password_policy_warnings


def authenticate_primary(identifier: str, password: str) -> dict[str, Any]:
    principal = _auth_principal(identifier)
    user = _find_user_by_identifier(identifier)
    try:
        _enforce_auth_backoff("login", principal)
    except AuthError:
        raise

    password_ok = False
    if is_password_raw_length_safe(password):
        candidate_hash = user.password_hash if user else _dummy_password_hash()
        password_ok = verify_password(password, candidate_hash)

    if user is None or not password_ok:
        audit_event(
            "login",
            "failure",
            user=user,
            metadata={
                "known_user": user is not None,
                "principal_ref": principal_reference(identifier),
            },
        )
        record_failure("login", principal)
        raise AuthError(GENERIC_LOGIN_ERROR, 401)

    ensure_account_can_authenticate(user)

    user.failed_login_count = 0
    user.last_login_at = datetime.now(timezone.utc)
    if password_hash_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    db.session.commit()
    clear_failures("login", principal)
    _clear_user_security_failures(user, "password")

    if user.mfa_enabled:
        begin_password_authenticated_session(user.id)
        audit_event("login_password", "success", user=user, metadata={"mfa_required": True})
        return {
            "message": "MFA verification required",
            "mfa_required": True,
        }

    if enrolled_webauthn_credential_count(user) > 0:
        begin_password_authenticated_session(user.id)
        audit_event("login_password", "success", user=user, metadata={"passkey_required": True})
        return {
            "message": "Passkey verification required",
            "mfa_required": True,
            "webauthn_required": True,
        }

    session_id = establish_authenticated_session(
        user_id=user.id,
        mfa_verified=False,
        auth_context=PASSWORD_BOOTSTRAP_AUTH_CONTEXT,
    )
    audit_event("login", "success", user=user, session_id=session_id, metadata={"mfa_required": False})
    return {
        "message": "MFA setup required",
        "mfa_required": False,
        "mfa_setup_required": True,
        "session_ref": public_session_reference(session_id),
        "user": _public_user(user),
    }


def generate_mfa_setup(user: User) -> dict[str, str]:
    ensure_account_not_frozen(user, "MFA setup")
    if user.mfa_enabled:
        audit_event("mfa_setup_generate", "failure", user=user, metadata={"reason": "already_enabled"})
        raise AuthError("MFA is already enabled", 409)
    if has_enrolled_mfa_method(user) and not has_recent_fresh_mfa():
        audit_event("mfa_setup_generate", "failure", user=user, metadata={"reason": "fresh_mfa_required"})
        raise AuthError("Recent MFA verification is required before adding another MFA method", 403)

    secret = pyotp.random_base32(length=32)
    nonce, ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_secret_nonce = nonce
    user.mfa_secret_ciphertext = ciphertext
    user.mfa_enabled = False
    db.session.commit()
    audit_event("mfa_setup_generate", "success", user=user)

    return _mfa_setup_payload(user, secret)


def pending_mfa_setup(user: User) -> dict[str, str] | None:
    if user.mfa_enabled or not user.mfa_secret_nonce or not user.mfa_secret_ciphertext:
        return None

    secret = _mfa_secret_for_user(user)
    return _mfa_setup_payload(user, secret)


def verify_mfa_setup(user: User, code: str) -> dict[str, Any]:
    if not _verify_totp_for_user(user, code, "mfa_setup"):
        _handle_mfa_verification_failure(user, "mfa_setup_verify")

    user.mfa_enabled = True
    recovery_codes = generate_recovery_codes_for_user(user, commit=False, audit=False)
    session_id = rotate_authenticated_session_after_mfa(user.id)
    audit_event_required(
        "mfa_setup_verify",
        "success",
        user=user,
        session_id=session_id,
        metadata={"recovery_code_count": len(recovery_codes)},
    )
    db.session.commit()
    return {
        "message": "MFA enabled",
        "session_ref": public_session_reference(session_id),
        "recovery_codes": recovery_codes,
        "recovery_codes_remaining": len(recovery_codes),
        "recovery_codes_low": False,
    }


def generate_mfa_replacement(user: User, code: str | None, stepup_token: str | None = None) -> dict[str, str]:
    ensure_account_not_frozen(user, "MFA replacement")
    if not user.mfa_enabled:
        audit_event("mfa_replace_start", "failure", user=user, metadata={"reason": "mfa_not_enabled"})
        raise AuthError("MFA is not enabled", 403)

    verify_high_risk_authorization(
        user,
        code,
        stepup_token,
        "mfa_replace_start",
    )

    secret = pyotp.random_base32(length=32)
    nonce, ciphertext = encrypt_mfa_secret(secret, user.id)
    session[MFA_REPLACEMENT_NONCE_KEY] = _b64encode(nonce)
    session[MFA_REPLACEMENT_CIPHERTEXT_KEY] = _b64encode(ciphertext)
    session[MFA_REPLACEMENT_STARTED_AT_KEY] = int(time.time())
    session.modified = True
    audit_event("mfa_replace_start", "success", user=user)
    return _mfa_setup_payload(user, secret)


def pending_mfa_replacement(user: User) -> dict[str, str] | None:
    if not user.mfa_enabled:
        return None
    secret = _pending_mfa_replacement_secret(user)
    if secret is None:
        return None
    return _mfa_setup_payload(user, secret)


def verify_mfa_replacement(user: User, code: str) -> dict[str, Any]:
    ensure_account_not_frozen(user, "MFA replacement")
    if not user.mfa_enabled:
        audit_event("mfa_replace_verify", "failure", user=user, metadata={"reason": "mfa_not_enabled"})
        raise AuthError("MFA is not enabled", 403)

    secret = _pending_mfa_replacement_secret(user)
    if secret is None:
        audit_event("mfa_replace_verify", "failure", user=user, metadata={"reason": "missing_pending_secret"})
        raise AuthError("No pending MFA replacement", 401)

    if not _verify_totp_secret_for_user(user, secret, code, "mfa_replace_verify"):
        _handle_mfa_verification_failure(user, "mfa_replace_verify")

    user.mfa_secret_nonce = _b64decode(str(session[MFA_REPLACEMENT_NONCE_KEY]))
    user.mfa_secret_ciphertext = _b64decode(str(session[MFA_REPLACEMENT_CIPHERTEXT_KEY]))
    user.mfa_enabled = True
    recovery_codes = generate_recovery_codes_for_user(user, commit=False, audit=False)
    _clear_pending_mfa_replacement()
    session_id = rotate_authenticated_session_after_mfa(user.id)
    revoked = revoke_other_sessions(user.id)
    audit_event_required(
        "mfa_replace_verify",
        "success",
        user=user,
        session_id=session_id,
        metadata={"revoked_other_sessions": revoked, "recovery_code_count": len(recovery_codes)},
    )
    db.session.commit()
    return {
        "message": "Authenticator MFA replaced",
        "session_ref": public_session_reference(session_id),
        "revoked_other_sessions": revoked,
        "recovery_codes": recovery_codes,
        "recovery_codes_remaining": len(recovery_codes),
        "recovery_codes_low": False,
    }


def complete_pending_mfa(code: str) -> dict[str, Any]:
    user_id = session.get("pending_mfa_user_id")
    if not user_id:
        raise AuthError("No pending MFA challenge", 401)

    user = db.session.get(User, int(user_id))
    if user is None or not user.mfa_enabled:
        audit_event("mfa_login_verify", "failure", user_id=int(user_id))
        raise AuthError("No pending MFA challenge", 401)

    ensure_account_can_authenticate(user)

    factor = _verify_pending_login_authentication_code(user, code)

    user.last_login_at = datetime.now(timezone.utc)
    user.failed_login_count = 0
    db.session.commit()
    _clear_user_security_failures(user, "mfa")
    recovery_codes_remaining = unused_recovery_code_count(user)
    session_id = establish_authenticated_session(
        user_id=user.id,
        mfa_verified=True,
        auth_context="password+mfa_bootstrap",
    )
    audit_event("mfa_login_verify", "success", user=user, session_id=session_id, metadata={"factor": factor})
    return {
        "message": "Login successful",
        "session_ref": public_session_reference(session_id),
        "user": _public_user(user),
        "recovery_codes_remaining": recovery_codes_remaining,
        "recovery_codes_low": recovery_codes_remaining <= RECOVERY_CODE_LOW_THRESHOLD,
    }


def regenerate_totp_recovery_codes(user: User) -> dict[str, Any]:
    ensure_account_not_frozen(user, "recovery code regeneration")
    if not user.mfa_enabled:
        audit_event("recovery_codes_regenerate", "failure", user=user, metadata={"reason": "mfa_not_enabled"})
        raise AuthError("MFA is not enabled", 403)

    recovery_codes = generate_recovery_codes_for_user(user, commit=False, audit=False)
    audit_event_required(
        "recovery_codes_regenerate",
        "success",
        user=user,
        metadata={"recovery_code_count": len(recovery_codes)},
    )
    db.session.commit()
    return {
        "message": "Recovery codes regenerated",
        "recovery_codes": recovery_codes,
        "recovery_codes_remaining": len(recovery_codes),
        "recovery_codes_low": False,
    }


def freeze_own_account(user: User, code: str, stepup_token: str | None = None) -> dict[str, Any]:
    ensure_account_not_frozen(user, "account freeze")
    verify_high_risk_authorization(
        user,
        code,
        stepup_token,
        "account_freeze",
        rotate_session_on_success=False,
    )

    user.is_frozen = True
    db.session.commit()
    session_id = rotate_authenticated_session_after_mfa(user.id)
    revoked = revoke_other_sessions(user.id)
    audit_event(
        "account_freeze",
        "success",
        user=user,
        session_id=session_id,
        metadata={"revoked_other_sessions": revoked},
    )
    return {
        "message": "Account frozen. Unfreeze requires manual support review.",
        "session_ref": public_session_reference(session_id),
        "revoked_other_sessions": revoked,
    }


def logout_current_session() -> None:
    user_id = session.get("user_id") or session.get("pending_mfa_user_id")
    session_id = current_session_id()
    revoke_current_session(ended_reason="logout")
    audit_event(
        "logout",
        "success",
        user_id=int(user_id) if user_id else None,
        session_id=session_id,
    )


def active_sessions_for_user(user: User) -> list[dict[str, Any]]:
    return list_active_sessions(user.id)


def past_sessions_for_user(user: User) -> list[dict[str, Any]]:
    return list_past_sessions(user.id)


def update_profile_details(
    user: User,
    username: str,
    email: str,
    mfa_step_up_preference: str | None,
    code: str | None,
    stepup_token: str | None = None,
) -> bool:
    normalized_username = username.strip()
    username_lookup = _normalize(normalized_username)
    normalized_email = email.strip().lower()
    normalized_preference = _normalize_step_up_preference(mfa_step_up_preference)
    if (
        username_lookup == _normalize(user.username)
        and normalized_email == user.email
        and normalized_preference == user.mfa_step_up_preference
    ):
        return False

    ensure_account_not_frozen(user, "profile update")

    duplicate_user = db.session.execute(
        db.select(User).where(
            or_(
                func.lower(User.username) == username_lookup,
                func.lower(User.email) == normalized_email,
            ),
            User.id != user.id,
        )
    ).scalar_one_or_none()
    if duplicate_user is not None:
        audit_event("profile_update", "failure", user=user, metadata={"reason": "duplicate_identifier"})
        raise AuthError("Profile could not be updated with those details", 400)

    verify_high_risk_authorization(
        user,
        code,
        stepup_token,
        "profile_update",
    )

    user.username = normalized_username
    user.email = normalized_email
    user.mfa_step_up_preference = normalized_preference
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        audit_event("profile_update", "failure", user=user, metadata={"reason": "integrity_error"})
        raise AuthError("Profile could not be updated with those details", 400) from exc
    audit_event("profile_update", "success", user=user, metadata={"updated_fields": "profile_details"})
    return True


def change_password(
    user: User,
    current_password: str,
    new_password: str,
    confirm_new_password: str,
    code: str | None,
    stepup_token: str | None = None,
) -> dict[str, Any]:
    ensure_account_not_frozen(user, "password change")
    if new_password != confirm_new_password:
        audit_event("password_change", "failure", user=user, metadata={"reason": "password_mismatch"})
        raise AuthError("Passwords must match", 400)
    if not verify_password(current_password, user.password_hash):
        audit_event("password_change", "failure", user=user, metadata={"reason": "invalid_current_password"})
        _record_user_security_failure(user, "password_change", "password_change_failed_attempts")
        raise AuthError("Current password is invalid", 401)
    if verify_password(new_password, user.password_hash):
        audit_event("password_change", "failure", user=user, metadata={"reason": "password_reuse"})
        raise AuthError("New password must be different from the current password", 400)

    verify_high_risk_authorization(
        user,
        code,
        stepup_token,
        "password_change",
        rotate_session_on_success=False,
    )

    try:
        password_policy_warnings = validate_password_policy(new_password)
    except PasswordPolicyError as exc:
        audit_event("password_change", "failure", user=user, metadata={"reason": "password_policy"})
        raise AuthError(str(exc), 400) from exc

    user.password_hash = hash_password(new_password)
    user.failed_login_count = 0
    db.session.commit()
    session_id = rotate_authenticated_session_after_mfa(user.id)
    revoked = revoke_other_sessions(user.id)
    clear_failures("login", _auth_principal(user.username))
    clear_failures("login", _auth_principal(user.email))
    _clear_user_security_failures(user, "password_change")
    audit_event(
        "password_change",
        "success",
        user=user,
        session_id=session_id,
        metadata={
            "revoked_other_sessions": revoked,
            "password_screening": (
                "local_only_fallback" if password_policy_warnings else "local_and_live"
            ),
        },
    )
    return {
        "message": "Password changed",
        "session_ref": public_session_reference(session_id),
        "revoked_other_sessions": revoked,
        "warnings": password_policy_warnings,
    }


def terminate_session_for_user(user: User, session_reference: str) -> None:
    resolved_session_id = resolve_session_reference_for_user(user.id, session_reference)
    if resolved_session_id is None:
        audit_event(
            "session_terminate",
            "failure",
            user=user,
            metadata={"reason": "not_owned_or_not_found"},
        )
        raise AuthError("Session not found", 404)
    revoke_session(resolved_session_id, user.id, ended_reason="terminated")
    audit_event("session_terminate", "success", user=user, session_id=resolved_session_id)
    if session.get("user_id") == user.id and getattr(session, "sid", None) == resolved_session_id:
        session.clear()


def terminate_other_sessions_for_user(user: User) -> int:
    revoked = revoke_other_sessions(user.id, ended_reason="revoked")
    audit_event(
        "session_revoke_others",
        "success",
        user=user,
        metadata={"revoked_other_sessions": revoked},
    )
    return revoked


def verify_fresh_mfa_for_action(
    user: User,
    code: str | None,
    action: str,
    *,
    rotate_session_on_success: bool = True,
) -> None:
    if not user.mfa_enabled:
        audit_event(action, "failure", user=user, metadata={"reason": "mfa_not_enabled"})
        raise AuthError("MFA is required for this action", 403)

    if not code:
        audit_event(action, "failure", user=user, metadata={"reason": "missing_mfa_code"})
        raise AuthError(GENERIC_MFA_ERROR, 401)

    if not _verify_totp_for_user(user, code, action):
        _handle_mfa_verification_failure(user, action)
    if rotate_session_on_success and session.get("user_id") == user.id:
        rotate_authenticated_session_after_mfa(user.id)
    audit_event(action, "mfa_success", user=user)


def verify_high_risk_authorization(
    user: User,
    code: str | None,
    stepup_token: str | None,
    action: str,
    *,
    rotate_session_on_success: bool = True,
) -> None:
    from app.auth.webauthn_services import consume_step_up_token

    require_stable_session_for_sensitive_action(action)
    if not has_enrolled_mfa_method(user):
        audit_event(action, "failure", user=user, metadata={"reason": "mfa_not_enabled"})
        raise AuthError("MFA is required for this action", 403)
    if stepup_token:
        consume_step_up_token(user, action, stepup_token)
        audit_event(action, "passkey_success", user=user)
    elif code:
        if not user.mfa_enabled:
            audit_event(action, "failure", user=user, metadata={"reason": "totp_not_enabled"})
            raise AuthError("Use a passkey to verify this action", 403)
        if not _verify_totp_for_user(user, code, action):
            _handle_mfa_verification_failure(user, action)
        audit_event(action, "mfa_success", user=user)
    else:
        audit_event(action, "failure", user=user, metadata={"reason": "missing_mfa_step_up"})
        raise AuthError("MFA verification is required for this action", 403)
    if rotate_session_on_success and session.get("user_id") == user.id:
        rotate_authenticated_session_after_mfa(user.id)


def ensure_account_can_authenticate(user: User) -> None:
    if user.is_frozen or user.security_locked_at is not None:
        audit_event(
            "login",
            "blocked",
            user=user,
            metadata={"reason": user.security_lock_reason or "account_frozen"},
        )
        raise AuthError(ACCOUNT_AUTH_UNAVAILABLE_ERROR, 403)


def ensure_account_not_frozen(user: User, action: str) -> None:
    if user.is_frozen or user.security_locked_at is not None:
        raise FrozenAccountError(f"Account is frozen; {action} is blocked", 403)


def _handle_mfa_verification_failure(user: User, action: str) -> None:
    audit_event(action, "failure", user=user)
    _record_user_security_failure(user, "mfa", "mfa_failed_attempts")
    raise AuthError(GENERIC_MFA_ERROR, 401)


def _verify_pending_login_authentication_code(user: User, code: str) -> str:
    if _is_totp_code(code):
        if _verify_totp_for_user(user, code, "mfa_login"):
            return "totp"
        _handle_mfa_verification_failure(user, "mfa_login_verify")

    try:
        _enforce_auth_backoff("mfa_recovery_code", str(user.id))
    except AuthError:
        _record_user_security_failure(user, "mfa", "mfa_failed_attempts")
        raise

    if not consume_recovery_code(user, code, commit=False):
        record_failure("mfa_recovery_code", str(user.id))
        audit_event("mfa_recovery_code_verify", "failure", user=user)
        _record_user_security_failure(user, "mfa", "mfa_failed_attempts")
        raise AuthError(GENERIC_MFA_ERROR, 401)

    clear_failures("mfa_recovery_code", str(user.id))
    _clear_user_security_failures(user, "mfa")
    remaining = unused_recovery_code_count(user)
    audit_event_required("mfa_recovery_code_verify", "success", user=user, metadata={"remaining_codes": remaining})
    db.session.commit()
    _send_mfa_recovery_code_used_notification(user)
    return "recovery_code"


def _is_totp_code(code: str) -> bool:
    text = str(code or "")
    return len(text) == 6 and text.isdigit()


def _send_mfa_recovery_code_used_notification(user: User) -> None:
    try:
        send_recovery_code_used_notification(user)
    except Exception as exc:
        current_app.logger.warning("recovery_code_notification_failed error=%s", type(exc).__name__)
        audit_event("recovery_code_notification", "failure", user=user, metadata={"reason": "email_delivery_failed"})


def _record_user_security_failure(user: User, scope: str, lock_reason: str) -> None:
    key = f"ospbank:securityfail:{scope}:{user.id}"
    attempts = int(_redis().incr(key))
    _redis().expire(key, AUTH_LOCK_WINDOW_SECONDS)
    if attempts >= AUTH_LOCK_THRESHOLD:
        _lock_user_account(user, lock_reason, scope, attempts)


def _clear_user_security_failures(user: User, scope: str) -> None:
    _redis().delete(f"ospbank:securityfail:{scope}:{user.id}")


def _lock_user_account(user: User, reason: str, scope: str, attempts: int) -> None:
    user.is_frozen = True
    user.security_locked_at = datetime.now(timezone.utc)
    user.security_lock_reason = reason
    db.session.commit()
    revoked = revoke_all_sessions(user.id)
    audit_event(
        "account_lock",
        "locked",
        user=user,
        metadata={
            "reason": reason,
            "scope": scope,
            "attempts": attempts,
            "revoked_sessions": revoked,
        },
    )


def _totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(secret, digits=6, interval=30, digest=hashlib.sha1)


def _mfa_secret_for_user(user: User) -> str:
    if not user.mfa_secret_nonce or not user.mfa_secret_ciphertext:
        raise AuthError("MFA is not configured", 403)
    return decrypt_mfa_secret(user.mfa_secret_nonce, user.mfa_secret_ciphertext, user.id)


def _verify_totp_for_user(user: User, code: str, scope: str, *, valid_window: int | None = None) -> bool:
    return _verify_totp_secret_for_user(user, _mfa_secret_for_user(user), code, scope, valid_window=valid_window)


def _verify_totp_secret_for_user(
    user: User,
    secret: str,
    code: str,
    scope: str,
    *,
    valid_window: int | None = None,
) -> bool:
    if not re.fullmatch(r"[0-9]{6}", code or ""):
        record_failure(scope, str(user.id))
        return False

    try:
        _enforce_auth_backoff(scope, str(user.id))
    except AuthError:
        _record_user_security_failure(user, "mfa", "mfa_failed_attempts")
        raise
    now = int(time.time())
    accepted_step = _accepted_totp_step(secret, code, now, _totp_valid_window(scope, valid_window))
    if accepted_step is None:
        record_failure(scope, str(user.id))
        return False

    code_digest = hashlib.sha256(code.encode("utf-8")).hexdigest()[:32]
    replay_key = f"ospbank:totp_replay:{user.id}:{accepted_step}:{code_digest}"
    replay_ttl = max(30, (_totp_valid_window(scope, valid_window) * 2 + 2) * 30)

    acquired = _redis().set(replay_key, "pending", nx=True, ex=replay_ttl)
    if not acquired:
        record_failure(scope, str(user.id))
        return False

    _redis().set(replay_key, "used", ex=replay_ttl)
    clear_failures(scope, str(user.id))
    _clear_user_security_failures(user, "mfa")
    mark_fresh_mfa()
    return True


def _totp_valid_window(scope: str, valid_window: int | None) -> int:
    if valid_window is not None:
        return valid_window
    if scope == "mfa_login":
        return int(current_app.config.get("TOTP_LOGIN_VALID_WINDOW", 1))
    return int(current_app.config.get("TOTP_HIGH_RISK_VALID_WINDOW", 0))


def _accepted_totp_step(secret: str, code: str, now: int, valid_window: int) -> int | None:
    current_step = now // 30
    totp = _totp(secret)
    for offset in range(-valid_window, valid_window + 1):
        candidate_step = current_step + offset
        if candidate_step < 0:
            continue
        expected = totp.at(candidate_step * 30)
        if hmac.compare_digest(expected, code):
            return candidate_step
    return None


def _mfa_setup_payload(user: User, secret: str) -> dict[str, str]:
    provisioning_uri = _totp(secret).provisioning_uri(
        name=user.email,
        issuer_name=current_app.config["MFA_ISSUER_NAME"],
    )
    return {
        "issuer": current_app.config["MFA_ISSUER_NAME"],
        "manual_entry_secret": secret,
        "otpauth_uri": provisioning_uri,
        "qr_code_data_uri": _qr_data_uri(provisioning_uri),
    }


def _pending_mfa_replacement_secret(user: User) -> str | None:
    nonce = session.get(MFA_REPLACEMENT_NONCE_KEY)
    ciphertext = session.get(MFA_REPLACEMENT_CIPHERTEXT_KEY)
    started_at = session.get(MFA_REPLACEMENT_STARTED_AT_KEY)
    if not nonce or not ciphertext or not started_at:
        return None
    try:
        age = int(time.time()) - int(started_at)
    except (TypeError, ValueError):
        _clear_pending_mfa_replacement()
        return None
    if age > current_app.config["PENDING_MFA_MAX_AGE_SECONDS"]:
        _clear_pending_mfa_replacement()
        return None
    try:
        return decrypt_mfa_secret(_b64decode(str(nonce)), _b64decode(str(ciphertext)), user.id)
    except (binascii.Error, InvalidTag, ValueError):
        _clear_pending_mfa_replacement()
        return None


def _clear_pending_mfa_replacement() -> None:
    session.pop(MFA_REPLACEMENT_NONCE_KEY, None)
    session.pop(MFA_REPLACEMENT_CIPHERTEXT_KEY, None)
    session.pop(MFA_REPLACEMENT_STARTED_AT_KEY, None)
    session.modified = True


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _qr_data_uri(provisioning_uri: str) -> str:
    image = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _public_user(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "mfa_enabled": user.mfa_enabled,
        "mfa_step_up_preference": user.mfa_step_up_preference,
        "is_frozen": user.is_frozen,
    }
