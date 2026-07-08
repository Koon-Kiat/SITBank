from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from cryptography.exceptions import InvalidTag
import pyotp
from flask import current_app, request, session
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import AuthAttemptCounter, RegistrationCredit, TotpReplayRecord, User
from app.security.qr import qr_data_uri
from app.auth.mfa_policy import (
    PASSWORD_BOOTSTRAP_AUTH_CONTEXT,
    has_enrolled_mfa_method,
)
from app.auth.registration_otp import (
    RegistrationOtpError,
    consume_verified_registration_email,
    require_current_verified_registration_email,
    require_verified_registration_email,
)
from app.auth.schemas import PHONE_RE
from app.security.audit import audit_event, audit_event_required, audit_reference, principal_reference
from app.security.crypto import decrypt_mfa_secret, encrypt_mfa_secret
from app.security.email import send_security_email
from app.security.identity_policy import (
    IdentityPolicyError,
    canonicalize_customer_email,
    require_customer_email,
)
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
from app.security.rate_limits import (
    AuthBackoffRequired,
    DurableRateLimitExceeded,
    apply_exponential_backoff,
    clear_failures,
    enforce_durable_failure_limit,
    record_failure,
)
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
from app.security.transaction_integrity import sign_registration_credit_integrity

from .recovery_codes import (
    RECOVERY_CODE_LOW_THRESHOLD,
    consume_recovery_code,
    generate_recovery_codes_for_user,
    send_recovery_code_used_notification,
    unused_recovery_code_count,
)


GENERIC_LOGIN_ERROR = "Invalid username or password"
GENERIC_MFA_ERROR = "Incorrect code. Check your authenticator and try again."
AUTH_BACKOFF_ERROR = "Too many failed attempts. Please wait before trying again."
ACCOUNT_AUTH_UNAVAILABLE_ERROR = "Authentication unavailable for this account"
PROFILE_UPDATE_ERROR = "Profile could not be updated with those details"
AUTH_LOCK_THRESHOLD = 10
CUSTOMER_PASSWORD_LOCK_THRESHOLD = 3
PRIVILEGED_PASSWORD_LOCK_THRESHOLD = 2
AUTH_LOCK_WINDOW_SECONDS = 15 * 60
MFA_REPLACEMENT_NONCE_KEY = "mfa_replacement_secret_nonce"
MFA_REPLACEMENT_CIPHERTEXT_KEY = "mfa_replacement_secret_ciphertext"
MFA_REPLACEMENT_STARTED_AT_KEY = "mfa_replacement_started_at"
PROFILE_EMAIL_PENDING_EMAIL_KEY = "profile_email_pending_email"
PROFILE_EMAIL_PENDING_PHONE_HMAC_KEY = "profile_email_pending_phone_hmac"
PROFILE_EMAIL_PENDING_CODE_HMAC_KEY = "profile_email_pending_code_hmac"
PROFILE_EMAIL_PENDING_EXPIRES_AT_KEY = "profile_email_pending_expires_at"
PROFILE_EMAIL_CHANGE_EXPIRED_MESSAGE = "Email verification expired. Request a new code."
REGISTRATION_WELCOME_CREDIT_AMOUNT = Decimal("100.00")


class AuthError(ValueError):
    def __init__(self, message: str, status_code: int = 400, *, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.retry_after = retry_after


class FrozenAccountError(AuthError):
    pass


MFA_NOT_ENABLED_ERROR = "MFA is not enabled"


def _normalize(value: str) -> str:
    return value.strip().casefold()


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


def _registration_duplicate_reason(
    username: str,
    canonical_email: str,
    phone_number: str,
) -> str | None:
    checks = (
        (
            "duplicate_username",
            func.lower(User.username) == _normalize(username),
        ),
        (
            "duplicate_email",
            User.registration_email_canonical == canonical_email,
        ),
        (
            "duplicate_phone",
            User.phone_number == phone_number.strip(),
        ),
    )
    for reason, condition in checks:
        if db.session.execute(db.select(User.id).where(condition).limit(1)).scalar_one_or_none():
            return reason
    return None


def _generate_account_number() -> str:
    for _ in range(10):
        candidate = "".join(str(secrets.randbelow(10)) for _ in range(12))
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
    canonical_email = canonicalize_customer_email(normalized_email)

    if data.get("password") != data.get("confirm_password"):
        audit_event("registration", "failure", metadata={"reason": "password_mismatch"})
        raise AuthError("Passwords must match", 400)

    try:
        password_policy_warnings = validate_password_policy(data["password"])
    except PasswordPolicyError as exc:
        audit_event("registration", "failure", metadata={"reason": "password_policy"})
        raise AuthError(str(exc), 400) from exc

    duplicate_reason = _registration_duplicate_reason(
        data["username"],
        canonical_email,
        data["phone_number"],
    )
    if duplicate_reason:
        audit_event("registration", "failure", metadata={"reason": duplicate_reason})
        raise AuthError("Registration could not be completed with those details", 400)

    user = User(
        username=data["username"].strip(),
        email=normalized_email,
        registration_email_canonical=canonical_email,
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
        _apply_registration_welcome_credit(user)
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        audit_event("registration", "failure", metadata={"reason": "integrity_error"})
        raise AuthError("Registration could not be completed with those details", 400) from exc
    except RuntimeError as exc:
        db.session.rollback()
        current_app.logger.warning("registration_welcome_credit_failed error=%s", type(exc).__name__)
        audit_event("registration", "failure", metadata={"reason": "welcome_credit_unavailable"})
        raise AuthError("Registration could not be completed right now. Please try again later.", 503) from exc
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


def _apply_registration_welcome_credit(user: User) -> None:
    existing_credit = db.session.execute(
        db.select(RegistrationCredit.id).where(RegistrationCredit.user_id == user.id).limit(1)
    ).scalar_one_or_none()
    if existing_credit is not None:
        return

    credit_ref = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc)
    credit_hash, key_id, algorithm, version = sign_registration_credit_integrity(
        credit_ref=credit_ref,
        user_id=int(user.id),
        amount=REGISTRATION_WELCOME_CREDIT_AMOUNT,
        status="completed",
        created_at=created_at,
    )
    user.balance = Decimal(str(user.balance or "0.00")) + REGISTRATION_WELCOME_CREDIT_AMOUNT
    db.session.add(
        RegistrationCredit(
            credit_ref=credit_ref,
            credit_hash=credit_hash,
            credit_integrity_key_id=key_id,
            credit_integrity_algorithm=algorithm,
            credit_integrity_version=version,
            user_id=user.id,
            amount=REGISTRATION_WELCOME_CREDIT_AMOUNT,
            status="completed",
            created_at=created_at,
        )
    )
    audit_event_required(
        "registration_credit",
        "success",
        user=user,
        metadata={
            "credit_type": "welcome",
            "amount": "fixed_sgd_100",
            "credit_ref": audit_reference("registration_credit", credit_ref),
        },
    )


def _customer_password_matches(user: User | None, password: str) -> bool:
    if not is_password_raw_length_safe(password):
        return False
    candidate_hash = user.password_hash if user else _dummy_password_hash()
    return verify_password(password, candidate_hash)


def _validate_customer_primary_credentials(
    user: User | None,
    identifier: str,
    password: str,
    principal: str,
) -> User:
    failure_reason = "invalid_credentials"
    password_ok = _customer_password_matches(user, password)
    if user is not None and getattr(user, "account_type", "customer") != "customer":
        password_ok = False
        failure_reason = "not_customer_identity"
    if user is not None and password_ok:
        return user
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
    if user is not None and user.account_type == "customer":
        user.failed_login_count = int(user.failed_login_count or 0) + 1
        _record_user_security_failure(
            user,
            "password",
            "password_failed_attempts",
        )
    raise AuthError(GENERIC_LOGIN_ERROR, 401)


def authenticate_primary(identifier: str, password: str) -> dict[str, Any]:
    principal = _auth_principal(identifier)
    user = _find_user_by_identifier(identifier)
    _enforce_auth_backoff("login", principal)
    user = _validate_customer_primary_credentials(
        user,
        identifier,
        password,
        principal,
    )

    _enforce_customer_login_account_state(user)

    if password_hash_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    db.session.commit()

    if user.mfa_enabled:
        clear_failures(
            "customer_mfa_login",
            _customer_mfa_failure_principal(user.id),
        )
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
    user.failed_login_count = 0
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()
    clear_failures("login", principal)
    _clear_user_security_failures(user, "password")
    audit_event(
        "login",
        "success",
        user=user,
        session_id=session_id,
        metadata={"mfa_required": False},
    )
    return {
        "message": "MFA setup required",
        "mfa_required": False,
        "mfa_setup_required": True,
        "session_ref": public_session_reference(session_id),
        "user": _public_user(user),
    }


def _enforce_customer_login_account_state(user: User) -> None:
    automatic_lock_reasons = {"password_failed_attempts", "mfa_failed_attempts"}
    if (
        user.security_locked_at is not None
        and user.security_lock_reason in automatic_lock_reasons
    ):
        message = GENERIC_LOGIN_ERROR
        status_code = 401
        reason = user.security_lock_reason
    elif user.is_frozen:
        message = ACCOUNT_AUTH_UNAVAILABLE_ERROR
        status_code = 403
        reason = user.security_lock_reason or "account_frozen"
    elif user.security_locked_at is not None:
        message = GENERIC_LOGIN_ERROR
        status_code = 401
        reason = user.security_lock_reason or "account_unavailable"
    else:
        return
    audit_event("login", "blocked", user=user, metadata={"reason": reason})
    raise AuthError(message, status_code)


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
    user.mfa_pending_started_at = datetime.now(timezone.utc)
    user.mfa_pending_session_hash = _mfa_setup_session_hash()
    db.session.commit()
    audit_event("mfa_setup_generate", "success", user=user)

    return _mfa_setup_payload(user, secret)


def pending_mfa_setup(user: User) -> dict[str, str] | None:
    if user.mfa_enabled or not user.mfa_secret_nonce or not user.mfa_secret_ciphertext:
        return None
    _require_active_pending_mfa_setup(user, raise_error=False)
    # Setup material is returned only by generate_mfa_setup. A page refresh
    # intentionally requires a safe restart instead of redisplaying the secret.
    return None


def verify_mfa_setup(user: User, code: str) -> dict[str, Any]:
    _require_active_pending_mfa_setup(user)
    if not _verify_totp_for_user(user, code, "mfa_setup"):
        _handle_mfa_verification_failure(user, "mfa_setup_verify")

    user.mfa_enabled = True
    user.mfa_pending_started_at = None
    user.mfa_pending_session_hash = None
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


def generate_mfa_replacement(user: User, code: str | None) -> dict[str, str]:
    ensure_account_not_frozen(user, "MFA replacement")
    if not user.mfa_enabled:
        audit_event("mfa_replace_start", "failure", user=user, metadata={"reason": "mfa_not_enabled"})
        raise AuthError(MFA_NOT_ENABLED_ERROR, 403)

    verify_high_risk_authorization(
        user,
        code,
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
    _pending_mfa_replacement_secret(user)
    # Replacement material is shown only in the response that creates it.
    return None


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

    principal = _customer_mfa_failure_principal(user.id)
    failure_limit = int(current_app.config["CUSTOMER_MFA_FAILURE_LIMIT"])
    _enforce_customer_mfa_failure_limit(user, principal, failure_limit)
    factor = _verify_pending_login_authentication_code(user, code)

    user.last_login_at = datetime.now(timezone.utc)
    user.failed_login_count = 0
    db.session.commit()
    clear_failures("customer_mfa_login", principal)
    clear_failures("login", _auth_principal(user.username))
    clear_failures("login", _auth_principal(user.email))
    _clear_user_security_failures(user, "password")
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


def _customer_mfa_failure_principal(user_id: int) -> str:
    return f"{_client_ip()}:{user_id}"


def _enforce_customer_mfa_failure_limit(
    user: User,
    principal: str,
    failure_limit: int,
    *,
    audit_block: bool = True,
) -> None:
    try:
        enforce_durable_failure_limit(
            "customer_mfa_login",
            principal,
            limit=failure_limit,
        )
    except DurableRateLimitExceeded as exc:
        if audit_block:
            audit_event(
                "mfa_login_verify",
                "blocked",
                user=user,
                metadata={
                    "reason": "wrong_code_threshold_exceeded",
                    "retry_after": exc.retry_after,
                },
            )
        raise AuthError(
            GENERIC_MFA_ERROR,
            429,
            retry_after=exc.retry_after,
        ) from exc


def _record_customer_mfa_login_failure(
    user: User,
    *,
    reason: str,
    event_type: str,
) -> None:
    principal = _customer_mfa_failure_principal(user.id)
    failure_limit = int(current_app.config["CUSTOMER_MFA_FAILURE_LIMIT"])
    failure_window_seconds = int(
        current_app.config["CUSTOMER_MFA_FAILURE_WINDOW_SECONDS"]
    )
    attempts = record_failure(
        "customer_mfa_login",
        principal,
        window_seconds=failure_window_seconds,
    )
    outcome = "blocked" if attempts > failure_limit else "failure"
    audit_event(
        event_type,
        outcome,
        user=user,
        metadata={
            "reason": (
                "wrong_code_threshold_exceeded"
                if attempts > failure_limit
                else reason
            ),
            "failure_count": attempts,
        },
    )
    _record_user_security_failure(user, "mfa", "mfa_failed_attempts")
    if attempts > failure_limit:
        _enforce_customer_mfa_failure_limit(
            user,
            principal,
            failure_limit,
            audit_block=False,
        )


def regenerate_totp_recovery_codes(
    user: User,
    code: str | None,
) -> dict[str, Any]:
    ensure_account_not_frozen(user, "recovery code regeneration")
    if not user.mfa_enabled:
        audit_event("recovery_codes_regenerate", "failure", user=user, metadata={"reason": "mfa_not_enabled"})
        raise AuthError(MFA_NOT_ENABLED_ERROR, 403)
    verify_high_risk_authorization(
        user,
        code,
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


def freeze_own_account(user: User, code: str) -> dict[str, Any]:
    ensure_account_not_frozen(user, "account freeze")
    verify_high_risk_authorization(
        user,
        code,
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
    _send_account_freeze_notification(user)
    return {
        "message": "Account frozen. Unfreeze requires manual support review.",
        "session_ref": public_session_reference(session_id),
        "revoked_other_sessions": revoked,
    }


def _send_account_freeze_notification(user: User) -> None:
    body = (
        "Your SITBank account was frozen from an authenticated session. "
        "If you did not request this, contact SITBank support through the approved recovery path."
    )
    try:
        send_security_email(user.email, "SITBank account frozen", body)
    except Exception as exc:
        current_app.logger.warning("account_freeze_notification_failed error=%s", type(exc).__name__)
        audit_event("account_freeze_notification", "failure", user=user, metadata={"reason": "email_delivery_failed"})
        return
    audit_event("account_freeze_notification", "queued", user=user)


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
    email: str,
    phone_number: str,
    code: str | None,
    email_verification_code: str | None = None,
) -> dict[str, Any]:
    (
        normalized_email,
        normalized_phone,
        email_changed,
        phone_changed,
    ) = _profile_update_values(
        user,
        email,
        phone_number,
    )

    if not email_changed and not phone_changed:
        return {"updated": False, "email_verification_pending": False}

    ensure_account_not_frozen(user, "profile update")
    _ensure_step_up_preference_enrolled(user, "totp")
    _reject_duplicate_profile_identifiers(user, normalized_email, normalized_phone)

    if email_changed:
        pending_result = _handle_profile_email_change(
            user,
            normalized_email=normalized_email,
            normalized_phone=normalized_phone,
            code=code,
            email_verification_code=email_verification_code,
        )
        if pending_result is not None:
            return pending_result
    else:
        verify_high_risk_authorization(
            user,
            code,
            "profile_update",
        )

    return _commit_profile_update(
        user,
        normalized_email,
        normalized_phone,
        email_changed,
        phone_changed,
    )


def _profile_update_values(user: User, email: str, phone_number: str) -> tuple[str, str, bool, bool]:
    submitted_email = email.strip().lower()
    normalized_phone = str(phone_number or "").strip()
    if re.fullmatch(PHONE_RE, normalized_phone) is None:
        audit_event("profile_update", "blocked", user=user, metadata={"reason": "invalid_phone"})
        raise AuthError(PROFILE_UPDATE_ERROR, 400)

    email_changed = submitted_email != _normalize(user.email)
    phone_changed = normalized_phone != str(user.phone_number or "")
    if not email_changed:
        return submitted_email, normalized_phone, False, phone_changed
    try:
        normalized_email = require_customer_email(email)
    except IdentityPolicyError as exc:
        audit_event("profile_update", "blocked", user=user, metadata={"reason": exc.reason})
        raise AuthError(PROFILE_UPDATE_ERROR, 400) from exc
    return normalized_email, normalized_phone, True, phone_changed


def _handle_profile_email_change(
    user: User,
    *,
    normalized_email: str,
    normalized_phone: str,
    code: str | None,
    email_verification_code: str | None,
) -> dict[str, Any] | None:
    if not email_verification_code:
        verify_high_risk_authorization(
            user,
            code,
            "profile_email_change_request",
        )
        _create_profile_email_change_challenge(
            user,
            email=normalized_email,
            phone_number=normalized_phone,
        )
        return {
            "updated": False,
            "email_verification_pending": True,
            "pending_email": normalized_email,
        }

    _validate_profile_email_change_code(user, normalized_email, normalized_phone, email_verification_code)
    verify_high_risk_authorization(
        user,
        code,
        "profile_email_change_commit",
    )
    return None


def _validate_profile_email_change_code(
    user: User,
    normalized_email: str,
    normalized_phone: str,
    email_verification_code: str,
) -> None:
    pending_change = _pending_profile_email_change(user)
    if pending_change is None:
        _reject_profile_email_change(
            user,
            reason="missing_or_expired_challenge",
            message=PROFILE_EMAIL_CHANGE_EXPIRED_MESSAGE,
        )
    if pending_change["email"] != normalized_email:
        _reject_profile_email_change(
            user,
            reason="superseded_challenge",
            message=PROFILE_EMAIL_CHANGE_EXPIRED_MESSAGE,
        )
    if pending_change["phone_hmac"] != _profile_phone_hmac(user, normalized_phone):
        _reject_profile_email_change(
            user,
            reason="superseded_challenge",
            message=PROFILE_EMAIL_CHANGE_EXPIRED_MESSAGE,
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
    normalized_email: str,
    normalized_phone: str,
    email_changed: bool,
    phone_changed: bool,
) -> dict[str, Any]:
    if email_changed:
        user.email = normalized_email
        user.registration_email_canonical = canonicalize_customer_email(normalized_email)
    if phone_changed:
        user.phone_number = normalized_phone
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
        metadata={"updated_fields": _profile_updated_fields(email_changed, phone_changed)},
    )
    return {"updated": True, "email_verification_pending": False}


def _profile_updated_fields(email_changed: bool, phone_changed: bool) -> str:
    if email_changed and phone_changed:
        return "profile_email_phone"
    if email_changed:
        return "profile_email"
    if phone_changed:
        return "profile_phone"
    return "profile_details"


def _reject_duplicate_profile_identifiers(
    user: User,
    normalized_email: str,
    normalized_phone: str,
) -> None:
    canonical_email = canonicalize_customer_email(normalized_email)
    duplicate_user = db.session.execute(
        db.select(User).where(
            or_(
                User.registration_email_canonical == canonical_email,
                User.phone_number == normalized_phone,
            ),
            User.id != user.id,
        )
    ).scalar_one_or_none()
    if duplicate_user is not None:
        audit_event("profile_update", "failure", user=user, metadata={"reason": "duplicate_identifier"})
        raise AuthError(PROFILE_UPDATE_ERROR, 400)


def _create_profile_email_change_challenge(
    user: User,
    *,
    email: str,
    phone_number: str,
) -> None:
    verification_code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = int(time.time()) + int(current_app.config["PROFILE_EMAIL_CHANGE_TTL_SECONDS"])
    _clear_pending_profile_email_change()
    session[PROFILE_EMAIL_PENDING_EMAIL_KEY] = email
    session[PROFILE_EMAIL_PENDING_PHONE_HMAC_KEY] = _profile_phone_hmac(user, phone_number)
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
    phone_hmac = str(session.get(PROFILE_EMAIL_PENDING_PHONE_HMAC_KEY) or "")
    code_hmac = str(session.get(PROFILE_EMAIL_PENDING_CODE_HMAC_KEY) or "")
    try:
        expires_at = int(session.get(PROFILE_EMAIL_PENDING_EXPIRES_AT_KEY) or 0)
    except (TypeError, ValueError):
        expires_at = 0
    if not email or not phone_hmac or not code_hmac or expires_at <= int(time.time()):
        if email or phone_hmac or code_hmac or expires_at:
            _clear_pending_profile_email_change()
            audit_event("profile_email_change", "expired", user=user)
        return None
    return {"email": email, "phone_hmac": phone_hmac, "code_hmac": code_hmac}


def pending_profile_email_change() -> dict[str, str] | None:
    user_id = session.get("user_id")
    user = db.session.get(User, int(user_id)) if user_id else None
    if user is None:
        return None
    return _pending_profile_email_change(user)


def _clear_pending_profile_email_change() -> None:
    session.pop(PROFILE_EMAIL_PENDING_EMAIL_KEY, None)
    session.pop(PROFILE_EMAIL_PENDING_PHONE_HMAC_KEY, None)
    session.pop(PROFILE_EMAIL_PENDING_CODE_HMAC_KEY, None)
    session.pop(PROFILE_EMAIL_PENDING_EXPIRES_AT_KEY, None)
    session.modified = True


def _profile_email_code_hmac(user: User, email: str, code: str) -> str:
    return active_hmac_hex(
        f"profile-email-change:{user.id}:{current_session_id()}:{_normalize(email)}:{code}",
        length=64,
    )


def _profile_phone_hmac(user: User, phone_number: str) -> str:
    return active_hmac_hex(
        f"profile-phone-change:{user.id}:{current_session_id()}:{phone_number.strip()}",
        length=64,
    )


def change_password(
    user: User,
    current_password: str,
    new_password: str,
    confirm_new_password: str,
    code: str | None,
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
    action: str,
    *,
    rotate_session_on_success: bool = True,
) -> None:
    require_stable_session_for_sensitive_action(action)
    if not has_enrolled_mfa_method(user):
        audit_event(action, "failure", user=user, metadata={"reason": "mfa_not_enabled"})
        raise AuthError("MFA is required for this action", 403)
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


def verify_totp_code_for_user(user: User, code: str, scope: str) -> bool:
    """Verify a TOTP code for an explicit user, independent of any active
    session. Used by cross-device flows (e.g. the top-up QR approval page)
    where verification happens on a device with no SITBank login of its own.
    """

    return _verify_totp_for_user(user, code, scope)


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
        if _verify_totp_for_user(
            user,
            code,
            "mfa_login",
            track_failures=False,
        ):
            return "totp"
        _record_customer_mfa_login_failure(
            user,
            reason="invalid_totp",
            event_type="mfa_login_verify",
        )
        raise AuthError(GENERIC_MFA_ERROR, 401)

    if not consume_recovery_code(user, code, commit=False):
        _record_customer_mfa_login_failure(
            user,
            reason="invalid_recovery_code",
            event_type="mfa_recovery_code_verify",
        )
        raise AuthError(GENERIC_MFA_ERROR, 401)

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
    if attempts >= _user_security_lock_threshold(user, scope):
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


def _user_security_lock_threshold(user: User, scope: str) -> int:
    if scope == "password" and user.account_type in {"staff", "admin", "root_admin"}:
        return PRIVILEGED_PASSWORD_LOCK_THRESHOLD
    if scope == "password":
        return CUSTOMER_PASSWORD_LOCK_THRESHOLD
    return AUTH_LOCK_THRESHOLD


def _totp(secret: str) -> pyotp.TOTP:
    # RFC-compatible TOTP uses HMAC-SHA1; this is not password hashing.
    return pyotp.TOTP(secret, digits=6, interval=30, digest=hashlib.sha1)  # NOSONAR


def _mfa_secret_for_user(user: User) -> str:
    if not user.mfa_secret_nonce or not user.mfa_secret_ciphertext:
        raise AuthError("MFA is not configured", 403)
    return decrypt_mfa_secret(user.mfa_secret_nonce, user.mfa_secret_ciphertext, user.id)


def _verify_totp_for_user(
    user: User,
    code: str,
    scope: str,
    *,
    valid_window: int | None = None,
    track_failures: bool = True,
) -> bool:
    return _verify_totp_secret_for_user(
        user,
        _mfa_secret_for_user(user),
        code,
        scope,
        valid_window=valid_window,
        track_failures=track_failures,
    )


def _verify_totp_secret_for_user(
    user: User,
    secret: str,
    code: str,
    scope: str,
    *,
    valid_window: int | None = None,
    track_failures: bool = True,
) -> bool:
    if not re.fullmatch(r"\d{6}", code or ""):
        if track_failures:
            record_failure(scope, str(user.id))
        return False

    if track_failures:
        try:
            _enforce_auth_backoff(scope, str(user.id))
        except AuthError:
            _record_user_security_failure(user, "mfa", "mfa_failed_attempts")
            raise
    now = int(time.time())
    accepted_step = _accepted_totp_step(secret, code, now, _totp_valid_window(scope, valid_window))
    if accepted_step is None:
        if track_failures:
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
        if track_failures:
            record_failure(scope, str(user.id))
        return False

    if track_failures:
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
        "qr_code_data_uri": qr_data_uri(provisioning_uri),
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
    if age < 0 or age > current_app.config["PENDING_MFA_MAX_AGE_SECONDS"]:
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


def _require_active_pending_mfa_setup(
    user: User,
    *,
    raise_error: bool = True,
) -> bool:
    started_at = user.mfa_pending_started_at
    binding = str(user.mfa_pending_session_hash or "")
    active = bool(started_at and binding)
    if active:
        age = (datetime.now(timezone.utc) - _as_utc(started_at)).total_seconds()
        active = (
            0 <= age <= int(current_app.config["PENDING_MFA_MAX_AGE_SECONDS"])
            and hmac.compare_digest(binding, _mfa_setup_session_hash())
        )
    if active:
        return True
    if started_at or binding or user.mfa_secret_nonce or user.mfa_secret_ciphertext:
        user.mfa_secret_nonce = None
        user.mfa_secret_ciphertext = None
        user.mfa_pending_started_at = None
        user.mfa_pending_session_hash = None
        db.session.commit()
        audit_event("mfa_setup_pending", "expired", user=user)
    if raise_error:
        raise AuthError("MFA setup expired. Start again.", 401)
    return False


def _mfa_setup_session_hash() -> str:
    return active_hmac_hex(
        f"mfa-setup-session:{current_session_id()}",
        length=64,
    )


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _public_user(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "account_type": user.account_type,
        "mfa_enabled": user.mfa_enabled,
        "is_frozen": user.is_frozen,
    }


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
