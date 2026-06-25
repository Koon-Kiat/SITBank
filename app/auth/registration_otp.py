from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone

from flask import current_app, session
from sqlalchemy import func

from app.extensions import db
from app.models import RegistrationOtpChallenge, User
from app.security.audit import audit_event, audit_reference
from app.security.email import send_security_email
from app.security.session_hmac import active_hmac_hex


APPROVED_REGISTRATION_EMAIL_DOMAINS = frozenset(
    {
        "sit.singaporetech.edu.sg",
        "singaporetech.edu.sg",
    }
)
GENERIC_OTP_SENT_MESSAGE = "If the email is eligible, a verification code has been sent."
GENERIC_OTP_ERROR = "Verification code expired or invalid. Please request a new code."
REGISTRATION_OTP_TTL_SECONDS = 5 * 60
REGISTRATION_OTP_RESEND_COOLDOWN_SECONDS = 60
REGISTRATION_OTP_MAX_ATTEMPTS = 5
REGISTRATION_OTP_SESSION_BINDING_KEY = "registration_otp_session_ref"
REGISTRATION_OTP_PENDING_EMAIL_KEY = "registration_otp_pending_email"
REGISTRATION_OTP_VERIFIED_EMAIL_KEY = "registration_otp_verified_email"
REGISTRATION_OTP_VERIFIED_AT_KEY = "registration_otp_verified_at"


class RegistrationOtpError(ValueError):
    def __init__(self, message: str, status_code: int = 400, *, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.retry_after = retry_after


def normalize_registration_email(email: str) -> str:
    return str(email or "").strip().casefold()


def is_approved_registration_email(email: str) -> bool:
    normalized = normalize_registration_email(email)
    local, separator, domain = normalized.partition("@")
    return bool(local and separator and domain in APPROVED_REGISTRATION_EMAIL_DOMAINS)


def request_registration_otp(email: str) -> dict[str, str]:
    normalized_email = normalize_registration_email(email)
    email_ref = audit_reference("registration_email", normalized_email)
    if not is_approved_registration_email(normalized_email):
        audit_event(
            "registration_otp",
            "failed",
            metadata={"reason": "invalid_domain", "email_ref": email_ref},
        )
        raise RegistrationOtpError("Use your SIT email address to register.", 400)

    existing_user = _user_by_email(normalized_email)
    if existing_user is not None:
        audit_event(
            "registration_otp",
            "requested",
            user=existing_user,
            metadata={"email_ref": email_ref, "eligible": False},
        )
        return {"message": GENERIC_OTP_SENT_MESSAGE}

    now = _utcnow()
    challenge = _load_otp_challenge(normalized_email, create_session_binding=True)
    if challenge is not None:
        retry_after = int((_as_utc(challenge.resend_available_at) - now).total_seconds())
        if retry_after > 0:
            audit_event(
                "registration_otp",
                "failed",
                metadata={"reason": "cooldown", "email_ref": email_ref},
            )
            raise RegistrationOtpError(
                "Please wait before requesting another verification code.",
                429,
                retry_after=retry_after,
            )

    otp_code = f"{secrets.randbelow(1_000_000):06d}"
    _clear_registration_progress_state()
    if challenge is None:
        challenge = RegistrationOtpChallenge(
            session_binding_hash=_session_binding_hash(create_session_binding=True),
            email_hash=_email_hash(normalized_email),
        )
        db.session.add(challenge)
    challenge.otp_hmac = _otp_hmac(normalized_email, otp_code)
    challenge.attempt_count = 0
    challenge.resend_available_at = now + timedelta(seconds=REGISTRATION_OTP_RESEND_COOLDOWN_SECONDS)
    challenge.expires_at = now + timedelta(seconds=REGISTRATION_OTP_TTL_SECONDS)
    challenge.used_at = None
    challenge.updated_at = now
    db.session.commit()
    try:
        send_security_email(
            normalized_email,
            "SITBank registration verification code",
            (
                "Use this SITBank registration verification code:\n\n"
                f"{otp_code}\n\n"
                "This code expires in 5 minutes. If you did not request it, ignore this email."
            ),
        )
    except Exception as exc:
        db.session.delete(challenge)
        db.session.commit()
        _clear_registration_progress_state()
        audit_event(
            "registration_otp",
            "failed",
            metadata={"reason": "email_delivery_failed", "email_ref": email_ref, "error_type": type(exc).__name__},
        )
        raise RegistrationOtpError("Could not send verification code. Please try again later.", 503) from exc

    audit_event("registration_otp", "requested", metadata={"email_ref": email_ref, "eligible": True})
    session[REGISTRATION_OTP_PENDING_EMAIL_KEY] = normalized_email
    return {"message": GENERIC_OTP_SENT_MESSAGE}


def verify_registration_otp(email: str, otp_code: str) -> dict[str, str]:
    normalized_email = normalize_registration_email(email)
    email_ref = audit_reference("registration_email", normalized_email)
    if not is_approved_registration_email(normalized_email):
        audit_event(
            "registration_otp",
            "failed",
            metadata={"reason": "invalid_domain", "email_ref": email_ref},
        )
        raise RegistrationOtpError(GENERIC_OTP_ERROR, 400)

    challenge = _load_otp_challenge(normalized_email)
    if challenge is None:
        audit_event(
            "registration_otp",
            "expired",
            metadata={"email_ref": email_ref},
        )
        raise RegistrationOtpError(GENERIC_OTP_ERROR, 400)

    attempts = int(challenge.attempt_count or 0) + 1
    expected_hmac = str(challenge.otp_hmac or "")
    submitted_hmac = _otp_hmac(normalized_email, str(otp_code or "").strip())
    if not hmac.compare_digest(expected_hmac, submitted_hmac):
        if attempts >= REGISTRATION_OTP_MAX_ATTEMPTS:
            db.session.delete(challenge)
            outcome = "locked"
        else:
            challenge.attempt_count = attempts
            challenge.updated_at = _utcnow()
            outcome = "failed"
        db.session.commit()
        audit_event(
            "registration_otp",
            outcome,
            metadata={"reason": "invalid_code", "email_ref": email_ref, "attempts": attempts},
        )
        raise RegistrationOtpError(GENERIC_OTP_ERROR, 400)

    db.session.delete(challenge)
    db.session.commit()
    session[REGISTRATION_OTP_VERIFIED_EMAIL_KEY] = normalized_email
    session[REGISTRATION_OTP_VERIFIED_AT_KEY] = int(time.time())
    session.pop(REGISTRATION_OTP_PENDING_EMAIL_KEY, None)
    audit_event("registration_otp", "verified", metadata={"email_ref": email_ref})
    return {"message": "Email verified. Complete registration to create your account."}


def pending_registration_email() -> str | None:
    pending_email = normalize_registration_email(str(session.get(REGISTRATION_OTP_PENDING_EMAIL_KEY) or ""))
    return pending_email or None


def current_verified_registration_email() -> str | None:
    verified_email = normalize_registration_email(str(session.get(REGISTRATION_OTP_VERIFIED_EMAIL_KEY) or ""))
    verified_at = int(session.get(REGISTRATION_OTP_VERIFIED_AT_KEY) or 0)
    if not verified_email or int(time.time()) - verified_at > REGISTRATION_OTP_TTL_SECONDS:
        if verified_email:
            _clear_registration_session_state()
        return None
    return verified_email


def require_current_verified_registration_email() -> str:
    verified_email = current_verified_registration_email()
    if not verified_email:
        audit_event("registration", "failure", metadata={"reason": "email_otp_required"})
        raise RegistrationOtpError("Verify your SIT email before creating an account.", 400)
    return verified_email


def require_verified_registration_email(email: str) -> str:
    normalized_email = normalize_registration_email(email)
    verified_email = current_verified_registration_email()
    if not verified_email or verified_email != normalized_email:
        audit_event(
            "registration",
            "failure",
            metadata={
                "reason": "email_otp_required",
                "email_ref": audit_reference("registration_email", normalized_email),
            },
        )
        raise RegistrationOtpError("Verify your SIT email before creating an account.", 400)
    return normalized_email


def consume_verified_registration_email(email: str) -> None:
    normalized_email = normalize_registration_email(email)
    if normalize_registration_email(str(session.get(REGISTRATION_OTP_VERIFIED_EMAIL_KEY) or "")) == normalized_email:
        _clear_registration_session_state()


def _session_reference(*, create_session_binding: bool = False) -> str:
    session_ref = str(session.get(REGISTRATION_OTP_SESSION_BINDING_KEY) or "")
    if not session_ref and create_session_binding:
        session_ref = secrets.token_urlsafe(32)
        session[REGISTRATION_OTP_SESSION_BINDING_KEY] = session_ref
    return session_ref or str(getattr(session, "sid", "") or "anonymous")


def _session_binding_hash(*, create_session_binding: bool = False) -> str:
    return active_hmac_hex(
        f"registration-otp-session:{_session_reference(create_session_binding=create_session_binding)}",
        length=64,
    )


def _email_hash(email: str) -> str:
    return active_hmac_hex(f"registration-otp-email:{normalize_registration_email(email)}", length=64)


def _otp_hmac(email: str, otp_code: str) -> str:
    key = str(current_app.config["SECRET_KEY"]).encode("utf-8")
    payload = f"registration-otp:v1:{normalize_registration_email(email)}:{otp_code}".encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _load_otp_challenge(
    email: str,
    *,
    create_session_binding: bool = False,
) -> RegistrationOtpChallenge | None:
    challenge = db.session.execute(
        db.select(RegistrationOtpChallenge).where(
            RegistrationOtpChallenge.session_binding_hash
            == _session_binding_hash(create_session_binding=create_session_binding),
            RegistrationOtpChallenge.email_hash == _email_hash(email),
            RegistrationOtpChallenge.used_at.is_(None),
        )
    ).scalar_one_or_none()
    if challenge is None:
        return None
    if _as_utc(challenge.expires_at) <= _utcnow():
        db.session.delete(challenge)
        db.session.commit()
        return None
    return challenge


def _clear_registration_session_state() -> None:
    _clear_registration_progress_state()
    session.pop(REGISTRATION_OTP_SESSION_BINDING_KEY, None)


def _clear_registration_progress_state() -> None:
    session.pop(REGISTRATION_OTP_PENDING_EMAIL_KEY, None)
    session.pop(REGISTRATION_OTP_VERIFIED_EMAIL_KEY, None)
    session.pop(REGISTRATION_OTP_VERIFIED_AT_KEY, None)


def _user_by_email(email: str) -> User | None:
    return db.session.execute(
        db.select(User).where(func.lower(User.email) == normalize_registration_email(email))
    ).scalar_one_or_none()


def _utcnow() -> datetime:
    return datetime.fromtimestamp(time.time(), timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
