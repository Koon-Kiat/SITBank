from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from typing import Any

from flask import current_app, g, has_request_context, request, session

from app.extensions import db
from app.models import SecurityAuditEvent, User

try:
    from webauthn.helpers import bytes_to_base64url
except ImportError:  # pragma: no cover - dependency is required in production.
    bytes_to_base64url = None


SENSITIVE_KEY_PARTS = (
    "password",
    "totp",
    "code",
    "secret",
    "key",
    "token",
    "uri",
    "url",
    "session_id",
    "ciphertext",
    "nonce",
)


def register_correlation_id(app) -> None:
    @app.before_request
    def set_correlation_id() -> None:
        g.correlation_id = str(uuid.uuid4())


def session_fingerprint(session_id: str | None) -> str | None:
    if not session_id:
        return None
    digest = hmac.new(
        current_app.config["SECRET_KEY"].encode("utf-8"),
        session_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:16]


def audit_event(
    event_type: str,
    outcome: str,
    *,
    user: User | None = None,
    user_id: int | None = None,
    metadata: dict[str, Any] | None = None,
    session_id: str | None = None,
) -> None:
    if not has_request_context():
        return

    try:
        event = SecurityAuditEvent(
            event_type=event_type[:80],
            outcome=outcome[:24],
            user_id=user.id if user is not None else user_id,
            ip_address=(request.remote_addr or "unknown")[:64],
            user_agent=(request.user_agent.string or "unknown")[:256],
            correlation_id=getattr(g, "correlation_id", str(uuid.uuid4())),
            session_ref=session_fingerprint(session_id or getattr(session, "sid", None)),
            event_metadata=_sanitize_metadata(metadata or {}),
        )
        db.session.add(event)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.warning("security_audit_write_failed event=%s error=%s", event_type, type(exc).__name__)


def audit_webauthn_event(
    action: str,
    outcome: str,
    *,
    user: User | None = None,
    user_id: int | None = None,
    credential_id: bytes | str | None = None,
    label: str | None = None,
    aaguid: str | None = None,
    metadata: dict[str, Any] | None = None,
    session_id: str | None = None,
) -> None:
    credential_ref = credential_id
    if isinstance(credential_id, bytes):
        credential_ref = bytes_to_base64url(credential_id) if bytes_to_base64url else credential_id.hex()

    event_metadata = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "credential_id": credential_ref,
        "label": label,
        "aaguid": aaguid,
    }
    event_metadata.update(metadata or {})
    audit_event(
        f"webauthn_{action}",
        outcome,
        user=user,
        user_id=user_id,
        metadata=event_metadata,
        session_id=session_id,
    )


def _sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        key_text = _clean_audit_text(key, 64)
        key_lower = key_text.casefold()
        if any(part in key_lower for part in SENSITIVE_KEY_PARTS):
            clean[key_text] = "[redacted]"
            continue
        if isinstance(value, bool | int | float) or value is None:
            clean[key_text] = value
        else:
            clean[key_text] = _clean_audit_text(value, 256)
    return clean


def _clean_audit_text(value: Any, limit: int) -> str:
    text = str(value)
    cleaned = "".join(char if (char >= " " and char != "\x7f") else " " for char in text)
    return " ".join(cleaned.split())[:limit]
