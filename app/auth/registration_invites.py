from __future__ import annotations

import csv
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from flask import current_app
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import RegistrationInvite, User
from app.security.audit import audit_event, audit_event_required, audit_system_event, principal_reference


INVITE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
GENERIC_INVITE_ERROR = "Registration requires a valid invitation."


class RegistrationInviteRejected(ValueError):
    def __init__(self, reason: str, *, status_code: int = 403) -> None:
        super().__init__(GENERIC_INVITE_ERROR)
        self.reason = reason
        self.status_code = status_code


def normalize_registration_email(email: str) -> str:
    return str(email or "").strip().casefold()


def registration_invite_url(token: str, *, base_url: str | None = None) -> str:
    root = (base_url or current_app.config.get("PASSWORD_RESET_BASE_URL") or "").strip().rstrip("/")
    if not root:
        root = current_app.config["WEBAUTHN_RP_ORIGIN"].strip().rstrip("/")
    return f"{root}/register?invite={quote(token, safe='')}"


def create_registration_invite(
    email: str,
    *,
    expires_at: datetime,
    created_by_user_id: int | None = None,
    audit: bool = True,
) -> tuple[RegistrationInvite, str]:
    normalized_email = normalize_registration_email(email)
    if not normalized_email:
        raise ValueError("email is required")
    if _ensure_aware_utc(expires_at) <= _utcnow():
        raise ValueError("expires_at must be in the future")

    for _attempt in range(3):
        token = secrets.token_urlsafe(32)
        invite = RegistrationInvite(
            token_hash=registration_invite_token_hash(token),
            intended_email_normalized=normalized_email,
            created_by_user_id=created_by_user_id,
            expires_at=_ensure_aware_utc(expires_at),
        )
        db.session.add(invite)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            continue
        if audit:
            audit_system_event(
                "registration_invite",
                "created",
                user_id=created_by_user_id,
                metadata=_invite_metadata(invite, created_by_user_id=created_by_user_id),
            )
        return invite, token

    raise RuntimeError("Could not generate a unique registration invite token")


def create_registration_invites_from_csv(
    csv_path: Path,
    *,
    expires_at: datetime,
    created_by_user_id: int | None = None,
) -> list[tuple[RegistrationInvite, str]]:
    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or "email" not in {field.strip() for field in reader.fieldnames}:
                raise ValueError("CSV must include an email column")
            emails = [str(row.get("email") or "").strip() for row in reader if str(row.get("email") or "").strip()]
    except OSError as exc:
        raise ValueError(f"CSV could not be read: {type(exc).__name__}") from exc

    created: list[tuple[RegistrationInvite, str]] = []
    for email in emails:
        created.append(
            create_registration_invite(
                email,
                expires_at=expires_at,
                created_by_user_id=created_by_user_id,
            )
        )

    audit_system_event(
        "registration_invite_bulk",
        "created",
        user_id=created_by_user_id,
        metadata={"created_count": len(created), "created_by_user_id": created_by_user_id},
    )
    return created


def revoke_registration_invite(
    invite_id: int,
    *,
    revoked_by_user_id: int | None = None,
) -> RegistrationInvite:
    invite = db.session.get(RegistrationInvite, invite_id)
    if invite is None:
        raise ValueError("registration invite not found")
    if invite.used_at is not None:
        raise ValueError("used registration invites cannot be revoked")
    if invite.revoked_at is None:
        invite.revoked_at = _utcnow()
        invite.revoked_by_user_id = revoked_by_user_id
        db.session.commit()
        audit_system_event(
            "registration_invite",
            "revoked",
            user_id=revoked_by_user_id,
            metadata=_invite_metadata(invite, revoked_by_user_id=revoked_by_user_id),
        )
    return invite


def registration_invite_token_hash(token: str) -> str:
    normalized = _clean_token(token)
    key = str(current_app.config["SECRET_KEY"]).encode("utf-8")
    payload = f"registration-invite:v1:{normalized}".encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def valid_registration_invite_for_form(token: str | None) -> RegistrationInvite | None:
    try:
        return _load_usable_invite(token, audit_failures=True, lock=False)
    except RegistrationInviteRejected:
        return None


def require_registration_invite_for_email(token: str | None, email: str) -> RegistrationInvite:
    invite = _load_usable_invite(token, audit_failures=True, lock=True)
    submitted_email = normalize_registration_email(email)
    if invite.intended_email_normalized != submitted_email:
        invite.last_attempt_at = _utcnow()
        _audit_invite_rejection(
            "email_mismatch",
            invite=invite,
            submitted_email=submitted_email,
        )
        raise RegistrationInviteRejected("email_mismatch")
    invite.last_attempt_at = _utcnow()
    return invite


def mark_registration_invite_used(invite: RegistrationInvite, user: User) -> None:
    if invite.used_at is not None:
        _audit_invite_rejection("used", invite=invite, submitted_email=user.email)
        raise RegistrationInviteRejected("used")
    if invite.revoked_at is not None:
        _audit_invite_rejection("revoked", invite=invite, submitted_email=user.email)
        raise RegistrationInviteRejected("revoked")
    if _ensure_aware_utc(invite.expires_at) <= _utcnow():
        _audit_invite_rejection("expired", invite=invite, submitted_email=user.email)
        raise RegistrationInviteRejected("expired")
    if invite.intended_email_normalized != normalize_registration_email(user.email):
        _audit_invite_rejection("email_mismatch", invite=invite, submitted_email=user.email)
        raise RegistrationInviteRejected("email_mismatch")

    now = _utcnow()
    invite.used_at = now
    invite.used_by_user_id = user.id
    invite.last_attempt_at = now
    audit_event_required(
        "registration_invite",
        "used",
        user=user,
        metadata=_invite_metadata(invite, used_by_user_id=user.id),
    )


def _load_usable_invite(token: str | None, *, audit_failures: bool, lock: bool) -> RegistrationInvite:
    try:
        token_hash = registration_invite_token_hash(token or "")
    except RegistrationInviteRejected as exc:
        if audit_failures:
            _audit_invite_rejection(exc.reason)
        raise

    statement = db.select(RegistrationInvite).where(RegistrationInvite.token_hash == token_hash)
    if lock:
        statement = statement.with_for_update()
    invite = db.session.execute(statement).scalar_one_or_none()
    if invite is None:
        if audit_failures:
            _audit_invite_rejection("invalid")
        raise RegistrationInviteRejected("invalid")

    reason = _invite_rejection_reason(invite)
    if reason is not None:
        invite.last_attempt_at = _utcnow()
        if audit_failures:
            _audit_invite_rejection(reason, invite=invite)
        raise RegistrationInviteRejected(reason)
    return invite


def _invite_rejection_reason(invite: RegistrationInvite) -> str | None:
    if invite.revoked_at is not None:
        return "revoked"
    if invite.used_at is not None:
        return "used"
    if _ensure_aware_utc(invite.expires_at) <= _utcnow():
        return "expired"
    return None


def _clean_token(token: str) -> str:
    cleaned = str(token or "").strip()
    if not cleaned:
        raise RegistrationInviteRejected("missing", status_code=400)
    if not INVITE_TOKEN_RE.fullmatch(cleaned):
        raise RegistrationInviteRejected("invalid")
    return cleaned


def _audit_invite_rejection(
    reason: str,
    *,
    invite: RegistrationInvite | None = None,
    submitted_email: str | None = None,
) -> None:
    metadata = {"reason": reason}
    if invite is not None:
        metadata.update(_invite_metadata(invite))
    if submitted_email:
        metadata["submitted_email_ref"] = principal_reference(submitted_email)
    audit_event("registration_invite", "rejected", metadata=metadata)


def _invite_metadata(
    invite: RegistrationInvite,
    *,
    created_by_user_id: int | None = None,
    used_by_user_id: int | None = None,
    revoked_by_user_id: int | None = None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "invite_id": invite.id,
        "intended_email_ref": principal_reference(invite.intended_email_normalized),
    }
    if created_by_user_id is not None:
        metadata["created_by_user_id"] = created_by_user_id
    if used_by_user_id is not None:
        metadata["used_by_user_id"] = used_by_user_id
    if revoked_by_user_id is not None:
        metadata["revoked_by_user_id"] = revoked_by_user_id
    return metadata


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
