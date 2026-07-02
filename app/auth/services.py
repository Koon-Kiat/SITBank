from __future__ import annotations

import base64
import hashlib
import hmac
import io
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidTag
import pyotp
import qrcode
from flask import current_app, request, session
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import AuthAttemptCounter, TotpReplayRecord, User
from app.auth.registration_otp import (
    RegistrationOtpError,
    consume_verified_registration_email,
    require_current_verified_registration_email,
    require_verified_registration_email,
)
from app.auth.mfa_policy import (
    PASSWORD_BOOTSTRAP_AUTH_CONTEXT,
    enrolled_webauthn_credential_count,
    has_enrolled_mfa_method,
)
from app.security.audit import audit_event, audit_event_required, audit_reference, principal_reference
from app.security.crypto import decrypt_mfa_secret, encrypt_mfa_secret
from app.security.email import send_security_email
from app.security.identity_policy import IdentityPolicyError, require_customer_email
from app.security.password_history import (
    PasswordReuseError,
    assert_password_not_reused,
    mark_password_changed,
    replace_user_password,
)
from app.security.passwords import (
    PasswordPolicyError,
    hash_password,
    is_password_raw_length_safe,
    password_hash_needs_rehash,
    validate_password_policy,
    verify_password,
)
from app.security.rate_limits import AuthBackoffRequired, apply_exponential_backoff, clear_failures, record_failure
from app.security.session_hmac import active_hmac_hex
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
PROFILE_UPDATE_ERROR = "Profile could not be updated with those details"
AUTH_LOCK_THRESHOLD = 10
AUTH_LOCK_WINDOW_SECONDS = 15 * 60
MFA_REPLACEMENT_NONCE_KEY = "mfa_replacement_secret_nonce"
MFA_REPLACEMENT_CIPHERTEXT_KEY = "mfa_replacement_secret_ciphertext"
MFA_REPLACEMENT_STARTED_AT_KEY = "mfa_replacement_started_at"
PROFILE_EMAIL_PENDING_EMAIL_KEY = "profile_email_pending_email"
PROFILE_EMAIL_PENDING_USERNAME_KEY = "profile_email_pending_username"
PROFILE_EMAIL_PENDING_CODE_HMAC_KEY = "profile_email_pending_code_hmac"
PROFILE_EMAIL_PENDING_EXPIRES_AT_KEY = "profile_email_pending_expires_at"


class AuthError(ValueError):
    def __init__(self, message: str, status_code: int = 400, *, retry_after: int | None = None, field: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.retry_after = retry_after
        self.field = field  # UI-only hint; never exposed in API responses


class FrozenAccountError(AuthError):
    pass


MFA_NOT_ENABLED_ERROR = "MFA is not enabled"


def _normalize(value: str) -> str:
    return value.strip().casefold()


def _normalize_step_up_preference(value: str | None) -> str:
    normalized = str(value or "totp").strip().casefold()
    if normalized == "passkey":
        raise AuthError("Passkey verification preference is no longer available", 400)
    if normalized != "totp":
        raise AuthError("Invalid verification preference", 400)
    return normalized


def _ensure_step_up_preference_enrolled(user: User, preference: str) -> None:
    if preference == "totp" and not user.mfa_enabled:
        audit_event("profile_update", "failure", user=user, metadata={"reason": "preferred_mfa_unavailable"})
        raise AuthError("Choose an enrolled verification method", 400)


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
    # This fingerprints high-entropy in-memory configuration for cache invalidation;
    # user passwords are processed only by hash_password below.
    # lgtm[py/weak-sensitive-data-hashing]
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


def _username_taken(username: str) -> bool:
    return db.session.execute(
        db.select(User).where(func.lower(User.username) == _normalize(username))
    ).scalar_one_or_none() is not None


def _phone_number_taken(phone_number: str) -> bool:
    return db.session.execute(
        db.select(User).where(User.phone_number == phone_number.strip())
    ).scalar_one_or_none() is not None


def _email_taken(email: str) -> bool:
    return db.session.execute(
        db.select(User).where(func.lower(User.email) == _normalize(email))
    ).scalar_one_or_none() is not None


def _generate_account_number() -> str:
    for _ in range(10):
        candidate = "012" + "".join(str(secrets.randbelow(10)) for _ in range(6))
        if not db.session.execute(db.select(User).where(User.account_number == candidate)).scalar_one_or_none():
            return candidate
    raise AuthError("Could not generate a unique account number", 500)


def register_user(data: dict[str, Any]) -> tuple[User, list[str]]:
    try:
        normalized_email = (
            require_verified_registration_email(data["email"])
            if data.get("email")
            else require_current_verified_registration_email()
        )
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

    if _username_taken(data["username"]):
        audit_event("registration", "failure", metadata={"reason": "duplicate_username"})
        raise AuthError("Registration could not be completed with those details", 400, field="username")
    if _phone_number_taken(data["phone_number"]):
        audit_event("registration", "failure", metadata={"reason": "duplicate_phone"})
        raise AuthError("Registration could not be completed with those details", 400, field="phone")
    if _email_taken(normalized_email):
        audit_event("registration", "failure", metadata={"reason": "duplicate_email"})
        raise AuthError("Registration could not be completed with those details", 400, field="email")

    user = User(
        username=data["username"].strip(),
        email=normalized_email,
        password_hash=hash_password(data["password"]),
        account_type="customer",
        account_status="active",
        full_name=data["full_name"].strip(),
        phone_number=data["phone_number"].strip(),
        account_number=_generate_account_number(),
    )
    mark_password_changed(user)
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
    _enforce_auth_backoff("login", principal)
    failure_reason = "invalid_credentials"

    password_ok = False
    if is_password_raw_length_safe(password):
        candidate_hash = user.password_hash if user else _dummy_password_hash()
        password_ok = verify_password(password, candidate_hash)

    if user is not None and getattr(user, "account_type", "customer") != "customer":
        password_ok = False
        failure_reason = "not_customer_identity"

    if user is None or not password_ok:
        audit_event(
            "login",
            "failure",
            user=user,
            metadata={
                "known_user": user is not None,
                "reason": failure_reason,
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

    session_id = establish_authenticated_session(
        user_id=user.id,
        mfa_verified=False,
        auth_context=PASSWORD_BOOTSTRAP_AUTH_CONTEXT,
    )
    legacy_passkey_count = enrolled_webauthn_credential_count(user)
    metadata = {"mfa_required": False}
    if legacy_passkey_count > 0:
        metadata["legacy_passkey_credentials"] = legacy_passkey_count
        audit_event(
            "legacy_passkey_mfa_migration_required",
            "required",
            user=user,
            session_id=session_id,
            metadata={"legacy_passkey_credentials": legacy_passkey_count},
        )
    audit_event("login", "success", user=user, session_id=session_id, metadata=metadata)
    return {
        "message": "MFA setup required",
        "mfa_required": False,
        "mfa_setup_required": True,
        "legacy_passkey_migration_required": legacy_passkey_count > 0,
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
        raise AuthError(MFA_NOT_ENABLED_ERROR, 403)

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
        raise AuthError(MFA_NOT_ENABLED_ERROR, 403)

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


def regenerate_totp_recovery_codes(
    user: User,
    code: str | None,
    stepup_token: str | None = None,
) -> dict[str, Any]:
    ensure_account_not_frozen(user, "recovery code regeneration")
    if not user.mfa_enabled:
        audit_event("recovery_codes_regenerate", "failure", user=user, metadata={"reason": "mfa_not_enabled"})
        raise AuthError(MFA_NOT_ENABLED_ERROR, 403)
    verify_high_risk_authorization(
        user,
        code,
        stepup_token,
        "recovery_codes_regenerate",
    )

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
    code: str | None,
    stepup_token: str | None = None,
    email_verification_code: str | None = None,
) -> dict[str, Any]:
    normalized_username, username_lookup, normalized_email, email_changed = _profile_update_values(
        user,
        username,
        email,
    )

    if username_lookup == _normalize(user.username) and not email_changed:
        return {"updated": False, "email_verification_pending": False}

    ensure_account_not_frozen(user, "profile update")
    _ensure_step_up_preference_enrolled(user, "totp")
    _reject_duplicate_profile_identifiers(user, username_lookup, normalized_email)

    if email_changed:
        pending_result = _handle_profile_email_change(
            user,
            username=normalized_username,
            normalized_email=normalized_email,
            code=code,
            stepup_token=stepup_token,
            email_verification_code=email_verification_code,
        )
        if pending_result is not None:
            return pending_result
    else:
        verify_high_risk_authorization(
            user,
            code,
            stepup_token,
            "profile_update",
        )

    return _commit_profile_update(user, normalized_username, normalized_email, email_changed)


def _profile_update_values(user: User, username: str, email: str) -> tuple[str, str, str, bool]:
    normalized_username = username.strip()
    username_lookup = _normalize(normalized_username)
    submitted_email = email.strip().lower()
    email_changed = submitted_email != _normalize(user.email)
    if not email_changed:
        return normalized_username, username_lookup, submitted_email, False
    try:
        normalized_email = require_customer_email(email)
    except IdentityPolicyError as exc:
        audit_event("profile_update", "blocked", user=user, metadata={"reason": exc.reason})
        raise AuthError(PROFILE_UPDATE_ERROR, 400) from exc
    return normalized_username, username_lookup, normalized_email, True


def _handle_profile_email_change(
    user: User,
    *,
    username: str,
    normalized_email: str,
    code: str | None,
    stepup_token: str | None,
    email_verification_code: str | None,
) -> dict[str, Any] | None:
    if not email_verification_code:
        verify_high_risk_authorization(
            user,
            code,
            stepup_token,
            "profile_email_change_request",
        )
        _create_profile_email_change_challenge(
            user,
            username=username,
            email=normalized_email,
        )
        return {
            "updated": False,
            "email_verification_pending": True,
            "pending_email": normalized_email,
        }

    _validate_profile_email_change_code(user, normalized_email, email_verification_code)
    verify_high_risk_authorization(
        user,
        code,
        stepup_token,
        "profile_email_change_commit",
    )
    return None


def _validate_profile_email_change_code(
    user: User,
    normalized_email: str,
    email_verification_code: str,
) -> None:
    pending_change = _pending_profile_email_change(user)
    if pending_change is None:
        _reject_profile_email_change(
            user,
            reason="missing_or_expired_challenge",
            message="Email verification expired. Request a new code.",
        )
    if pending_change["email"] != normalized_email:
        _reject_profile_email_change(
            user,
            reason="superseded_challenge",
            message="Email verification expired. Request a new code.",
        )
    expected_hmac = str(pending_change["code_hmac"])
    submitted_hmac = _profile_email_code_hmac(
        user,
        normalized_email,
        str(email_verification_code or "").strip(),
    )
    if not hmac.compare_digest(expected_hmac, submitted_hmac):
        _reject_profile_email_change(
            user,
            reason="invalid_verification_code",
            message="Email verification code is invalid or expired",
        )


def _reject_profile_email_change(user: User, *, reason: str, message: str) -> None:
    audit_event(
        "profile_email_change",
        "failure",
        user=user,
        metadata={"reason": reason},
    )
    raise AuthError(message, 400)


def _commit_profile_update(
    user: User,
    normalized_username: str,
    normalized_email: str,
    email_changed: bool,
) -> dict[str, Any]:
    user.username = normalized_username
    if email_changed:
        user.email = normalized_email
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        audit_event("profile_update", "failure", user=user, metadata={"reason": "integrity_error"})
        raise AuthError(PROFILE_UPDATE_ERROR, 400) from exc
    if email_changed:
        _clear_pending_profile_email_change()
    audit_event(
        "profile_update",
        "success",
        user=user,
        metadata={"updated_fields": "profile_email" if email_changed else "profile_details"},
    )
    return {"updated": True, "email_verification_pending": False}


def _reject_duplicate_profile_identifiers(user: User, username_lookup: str, normalized_email: str) -> None:
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
        raise AuthError(PROFILE_UPDATE_ERROR, 400)


def _create_profile_email_change_challenge(user: User, *, username: str, email: str) -> None:
    verification_code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = int(time.time()) + int(current_app.config["PROFILE_EMAIL_CHANGE_TTL_SECONDS"])
    _clear_pending_profile_email_change()
    session[PROFILE_EMAIL_PENDING_USERNAME_KEY] = username
    session[PROFILE_EMAIL_PENDING_EMAIL_KEY] = email
    session[PROFILE_EMAIL_PENDING_CODE_HMAC_KEY] = _profile_email_code_hmac(
        user,
        email,
        verification_code,
    )
    session[PROFILE_EMAIL_PENDING_EXPIRES_AT_KEY] = expires_at
    session.modified = True
    try:
        send_security_email(
            email,
            "SITBank profile email verification code",
            (
                "Use this SITBank profile email verification code:\n\n"
                f"{verification_code}\n\n"
                "This code expires in 5 minutes. If you did not request it, ignore this email."
            ),
        )
    except Exception as exc:
        _clear_pending_profile_email_change()
        audit_event(
            "profile_email_change",
            "failure",
            user=user,
            metadata={"reason": "email_delivery_failed"},
        )
        raise AuthError("Could not send verification code. Please try again later.", 503) from exc
    audit_event(
        "profile_email_change",
        "requested",
        user=user,
        metadata={"email_ref": audit_reference("profile_email", email)},
    )


def _pending_profile_email_change(user: User) -> dict[str, str] | None:
    email = str(session.get(PROFILE_EMAIL_PENDING_EMAIL_KEY) or "")
    username = str(session.get(PROFILE_EMAIL_PENDING_USERNAME_KEY) or "")
    code_hmac = str(session.get(PROFILE_EMAIL_PENDING_CODE_HMAC_KEY) or "")
    try:
        expires_at = int(session.get(PROFILE_EMAIL_PENDING_EXPIRES_AT_KEY) or 0)
    except (TypeError, ValueError):
        expires_at = 0
    if not email or not username or not code_hmac or expires_at <= int(time.time()):
        if email or username or code_hmac or expires_at:
            _clear_pending_profile_email_change()
            audit_event("profile_email_change", "expired", user=user)
        return None
    return {"email": email, "username": username, "code_hmac": code_hmac}


def pending_profile_email_change() -> dict[str, str] | None:
    user_id = session.get("user_id")
    user = db.session.get(User, int(user_id)) if user_id else None
    if user is None:
        return None
    return _pending_profile_email_change(user)


def _clear_pending_profile_email_change() -> None:
    session.pop(PROFILE_EMAIL_PENDING_EMAIL_KEY, None)
    session.pop(PROFILE_EMAIL_PENDING_USERNAME_KEY, None)
    session.pop(PROFILE_EMAIL_PENDING_CODE_HMAC_KEY, None)
    session.pop(PROFILE_EMAIL_PENDING_EXPIRES_AT_KEY, None)
    session.modified = True


def _profile_email_code_hmac(user: User, email: str, code: str) -> str:
    return active_hmac_hex(
        f"profile-email-change:{user.id}:{current_session_id()}:{_normalize(email)}:{code}",
        length=64,
    )


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
    try:
        assert_password_not_reused(user, new_password)
    except PasswordReuseError as exc:
        audit_event("password_change", "failure", user=user, metadata={"reason": exc.reason})
        raise AuthError("New password must not match your current or recent passwords", 400) from exc

    try:
        password_policy_warnings = validate_password_policy(new_password)
    except PasswordPolicyError as exc:
        audit_event("password_change", "failure", user=user, metadata={"reason": "password_policy"})
        raise AuthError(str(exc), 400) from exc

    verify_high_risk_authorization(
        user,
        code,
        stepup_token,
        "password_change",
        rotate_session_on_success=False,
    )

    replace_user_password(user, new_password)
    user.failed_login_count = 0
    revoked = revoke_all_sessions(user.id, ended_reason="password_change")
    session_id = current_session_id()
    session.clear()
    db.session.commit()
    clear_failures("login", _auth_principal(user.username))
    clear_failures("login", _auth_principal(user.email))
    _clear_user_security_failures(user, "password_change")
    audit_event(
        "password_change",
        "success",
        user=user,
        session_id=session_id,
        metadata={
            "revoked_sessions": revoked,
            "revoked_other_sessions": max(0, revoked - 1),
            "password_screening": (
                "local_only_fallback" if password_policy_warnings else "local_and_live"
            ),
            "forced_change_cleared": True,
        },
    )
    return {
        "message": "Password changed. Please log in again.",
        "revoked_sessions": revoked,
        "revoked_other_sessions": max(0, revoked - 1),
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
    require_stable_session_for_sensitive_action(action)
    if not has_enrolled_mfa_method(user):
        audit_event(action, "failure", user=user, metadata={"reason": "mfa_not_enabled"})
        raise AuthError("MFA is required for this action", 403)
    if stepup_token:
        audit_event(action, "failure", user=user, metadata={"reason": "passkey_step_up_disabled"})
        raise AuthError("Enter an authenticator code to verify this action", 403)
    if not code:
        audit_event(action, "failure", user=user, metadata={"reason": "missing_mfa_step_up"})
        raise AuthError("MFA verification is required for this action", 403)
    if not user.mfa_enabled:
        audit_event(action, "failure", user=user, metadata={"reason": "totp_not_enabled"})
        raise AuthError("Authenticator MFA is required for this action", 403)
    if not _verify_totp_for_user(user, code, action):
        _handle_mfa_verification_failure(user, action)
    audit_event(action, "mfa_success", user=user)
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
    now = datetime.now(timezone.utc)
    counter_scope = f"user_security:{scope}"
    principal_hash = active_hmac_hex(f"{counter_scope}:{user.id}", length=64)
    statement = db.select(AuthAttemptCounter).where(
        AuthAttemptCounter.scope == counter_scope,
        AuthAttemptCounter.principal_hash == principal_hash,
    )
    if db.engine.dialect.name == "postgresql":
        statement = statement.with_for_update()
    counter = db.session.execute(statement).scalar_one_or_none()
    if counter is None or _as_utc(counter.window_expires_at) <= now:
        if counter is not None:
            db.session.delete(counter)
            db.session.flush()
        counter = AuthAttemptCounter(
            scope=counter_scope,
            principal_hash=principal_hash,
            user_id=user.id,
            failure_count=0,
            window_started_at=now,
            window_expires_at=now + timedelta(seconds=AUTH_LOCK_WINDOW_SECONDS),
            created_at=now,
            updated_at=now,
        )
        db.session.add(counter)
    counter.failure_count = int(counter.failure_count or 0) + 1
    counter.last_failed_at = now
    counter.updated_at = now
    counter.window_expires_at = now + timedelta(seconds=AUTH_LOCK_WINDOW_SECONDS)
    attempts = int(counter.failure_count)
    db.session.commit()
    if attempts >= AUTH_LOCK_THRESHOLD:
        _lock_user_account(user, lock_reason, scope, attempts)


def _clear_user_security_failures(user: User, scope: str) -> None:
    counter_scope = f"user_security:{scope}"
    principal_hash = active_hmac_hex(f"{counter_scope}:{user.id}", length=64)
    counter = db.session.execute(
        db.select(AuthAttemptCounter).where(
            AuthAttemptCounter.scope == counter_scope,
            AuthAttemptCounter.principal_hash == principal_hash,
        )
    ).scalar_one_or_none()
    if counter is not None:
        db.session.delete(counter)
        db.session.commit()


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
    # RFC-compatible TOTP uses HMAC-SHA1; this is not password hashing.
    return pyotp.TOTP(secret, digits=6, interval=30, digest=hashlib.sha1)  # NOSONAR


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
    if not re.fullmatch(r"\d{6}", code or ""):
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

    code_digest = active_hmac_hex(
        f"totp-replay:{user.id}:{scope}:{accepted_step}:{code}",
        length=64,
    )
    replay_ttl = max(30, (_totp_valid_window(scope, valid_window) * 2 + 2) * 30)
    replay_record = TotpReplayRecord(
        user_id=user.id,
        scope=scope,
        time_step=accepted_step,
        code_digest=code_digest,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=replay_ttl),
    )
    db.session.add(replay_record)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        record_failure(scope, str(user.id))
        return False

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
    except (InvalidTag, ValueError):
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
        "account_type": user.account_type,
        "mfa_enabled": user.mfa_enabled,
        "mfa_step_up_preference": user.mfa_step_up_preference,
        "is_frozen": user.is_frozen,
    }


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
