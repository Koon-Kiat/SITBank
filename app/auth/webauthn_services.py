from __future__ import annotations

import base64
import binascii
from datetime import timezone
from typing import Any

from app.extensions import db
from app.models import User, WebAuthnCredential
from app.security.audit import audit_event

from .services import AuthError


PASSKEY_DISABLED_MESSAGE = (
    "Passkey authentication is no longer available. "
    "Use authenticator MFA or manual account recovery."
)
STEP_UP_TOKEN_PREFIX = "ospbank:webauthn_stepup:"


def webauthn_credential_count(user: User) -> int:
    return legacy_webauthn_credential_count(user)


def legacy_webauthn_credential_count(user: User) -> int:
    if user.id is None:
        return 0
    return int(
        db.session.execute(
            db.select(db.func.count(WebAuthnCredential.id)).where(
                WebAuthnCredential.user_id == user.id
            )
        ).scalar_one()
    )


def has_webauthn_credentials(user: User) -> bool:
    return legacy_webauthn_credential_count(user) > 0


def has_full_webauthn_access(_user: User) -> bool:
    return False


def webauthn_required_for_user(_user: User) -> bool:
    return False


def current_webauthn_credential_reference() -> None:
    return None


def list_credentials_for_user(user: User) -> list[dict[str, Any]]:
    if user.id is None:
        return []
    credentials = db.session.execute(
        db.select(WebAuthnCredential)
        .where(WebAuthnCredential.user_id == user.id)
        .order_by(WebAuthnCredential.created_at.asc(), WebAuthnCredential.id.asc())
    ).scalars()
    return [_public_legacy_credential(item) for item in credentials]


def begin_registration_options(user: User, _label: str) -> dict[str, Any]:
    _audit_disabled("register_options", user=user)


def verify_registration(user: User, _credential: dict[str, Any]) -> dict[str, Any]:
    _audit_disabled("register", user=user)


def begin_authentication_options() -> dict[str, Any]:
    _audit_disabled("authenticate_options")


def verify_authentication(_credential: dict[str, Any]) -> dict[str, Any]:
    _audit_disabled("authenticate")


def begin_step_up_options(user: User, action: str) -> dict[str, Any]:
    _audit_disabled("step_up_options", user=user, metadata={"action": str(action or "")[:64]})


def verify_step_up(user: User, action: str, _credential: dict[str, Any]) -> dict[str, Any]:
    _audit_disabled("step_up_verify", user=user, metadata={"action": str(action or "")[:64]})


def begin_password_reset_options(user: User, _transaction_id: str) -> dict[str, Any]:
    _audit_disabled("password_reset_options", user=user)


def verify_password_reset_assertion(
    user: User,
    _transaction_id: str,
    _credential: dict[str, Any],
) -> dict[str, Any]:
    _audit_disabled("password_reset_verify", user=user)


def consume_step_up_token(user: User, action: str, _token: str | None) -> None:
    _audit_disabled("step_up_token", user=user, metadata={"action": str(action or "")[:64]})


def revoke_credential(
    user: User,
    _credential_id: str,
    *,
    stepup_token: str | None = None,
    stepup_already_consumed: bool = False,
) -> dict[str, Any]:
    metadata = {"stepup_token_submitted": bool(stepup_token), "stepup_already_consumed": stepup_already_consumed}
    _audit_disabled("revoke", user=user, metadata=metadata)


def stage_transaction_security_key_context(user: User, _transaction_context: dict[str, Any]) -> str:
    _audit_disabled("transaction_stage", user=user)


def begin_transaction_security_key_challenge(user: User, _transaction_reference: str) -> dict[str, Any]:
    _audit_disabled("transaction_options", user=user)


def verify_transaction_security_key_challenge(user: User, _credential: dict[str, Any]) -> dict[str, Any]:
    _audit_disabled("transaction_verify", user=user)


def _step_up_token_cache_key(token: str) -> str:
    return f"{STEP_UP_TOKEN_PREFIX}{token}"


def bytes_to_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def base64url_to_bytes(value: str) -> bytes:
    text = str(value or "")
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode((text + padding).encode("ascii"))
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise AuthError("Invalid credential reference", 400) from exc


def _audit_disabled(
    action: str,
    *,
    user: User | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    payload = {"reason": "webauthn_decommissioned"}
    if metadata:
        payload.update(metadata)
    audit_event(f"webauthn_{action}", "blocked", user=user, metadata=payload)
    raise AuthError(PASSKEY_DISABLED_MESSAGE, 410)


def _public_legacy_credential(item: WebAuthnCredential) -> dict[str, Any]:
    created_at = item.created_at
    last_used_at = item.last_used_at
    return {
        "id": item.id,
        "credential_id": bytes_to_base64url(item.credential_id),
        "label": item.label,
        "aaguid": item.aaguid,
        "attestation_format": item.attestation_format,
        "credential_kind": item.credential_kind,
        "credential_kind_display": "Legacy passkey",
        "active": False,
        "decommissioned": True,
        "created_at": created_at.astimezone(timezone.utc).isoformat() if created_at else None,
        "last_used_at": last_used_at.astimezone(timezone.utc).isoformat() if last_used_at else None,
    }
