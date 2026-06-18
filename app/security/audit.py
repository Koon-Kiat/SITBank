from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from flask import current_app, g, has_request_context, request, session

from app.extensions import db
from app.models import SecurityAuditEvent, User
from app.security.session_hmac import active_hmac_hex

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


def audit_reference(value: str) -> str:
    """Generate an HMAC-style reference for an identifier to safely log it."""
    if not value:
        return ""
    secret = current_app.config["SECRET_KEY"].encode("utf-8")
    return hashlib.blake2b(value.encode("utf-8"), key=secret[:64], digest_size=16).hexdigest()


def principal_reference(identifier: str) -> str:
    """Generate a principal reference to safely log sensitive user identifiers."""
    if not identifier:
        return ""
    normalized = identifier.strip().casefold()
    secret = current_app.config["SECRET_KEY"].encode("utf-8")
    return hashlib.blake2b(normalized.encode("utf-8"), key=secret[:64], digest_size=16).hexdigest()


def register_correlation_id(app) -> None:
    @app.before_request
    def set_correlation_id() -> None:
        g.correlation_id = str(uuid.uuid4())


def session_fingerprint(session_id: str | None) -> str | None:
    if not session_id:
        return None
    return active_hmac_hex(session_id, length=16)


def _compute_event_hash(event: SecurityAuditEvent, previous_hash: str | None) -> str:
    """Compute a tamper-evident SHA-256 hash for the audit event."""
    payload = {
        "event_type": event.event_type,
        "outcome": event.outcome,
        "user_id": event.user_id,
        "ip_address": event.ip_address,
        "user_agent": event.user_agent,
        "correlation_id": event.correlation_id,
        "session_ref": event.session_ref,
        "event_metadata": event.event_metadata,
        "previous_event_hash": previous_hash,
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


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
        
        # Support tamper-evident hash chaining
        last_event = db.session.query(SecurityAuditEvent).order_by(SecurityAuditEvent.id.desc()).first()
        previous_hash = last_event.event_hash if last_event else None
        event.previous_event_hash = previous_hash
        event.hash_algorithm = "sha256"
        event.event_hash = _compute_event_hash(event, previous_hash)
        
        db.session.add(event)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.warning(
            "security_audit_write_failed event=%s outcome=%s error=%s metadata=%s",
            event_type, outcome, type(exc).__name__, _sanitize_metadata(metadata or {})
        )


def audit_system_event(
    event_type: str,
    outcome: str,
    *,
    user_id: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    try:
        event = SecurityAuditEvent(
            event_type=event_type[:80],
            outcome=outcome[:24],
            user_id=user_id,
            ip_address="system",
            user_agent="system",
            correlation_id=str(uuid.uuid4()),
            session_ref=None,
            event_metadata=_sanitize_metadata(metadata or {}),
        )
        
        # Support tamper-evident hash chaining
        last_event = db.session.query(SecurityAuditEvent).order_by(SecurityAuditEvent.id.desc()).first()
        previous_hash = last_event.event_hash if last_event else None
        event.previous_event_hash = previous_hash
        event.hash_algorithm = "sha256"
        event.event_hash = _compute_event_hash(event, previous_hash)
        
        db.session.add(event)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.warning(
            "security_audit_write_failed event=%s outcome=%s error=%s metadata=%s",
            event_type, outcome, type(exc).__name__, _sanitize_metadata(metadata or {})
        )


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
            
        if isinstance(value, dict):
            clean[key_text] = _sanitize_metadata(value)
            continue
            
        if isinstance(value, (list, tuple, set)):
            clean[key_text] = [_sanitize_metadata(v) if isinstance(v, dict) else _clean_audit_text(v, 256) for v in value]
            continue
            
        if isinstance(value, bool | int | float) or value is None:
            clean[key_text] = value
        else:
            text_value = _clean_audit_text(value, 256)
            if re.search(r'\b(?:bearer|basic)\s+', text_value, re.IGNORECASE) or re.search(r'\b\d{8,12}\b', text_value):
                clean[key_text] = "[redacted]"
            else:
                clean[key_text] = text_value
    return clean


def _clean_audit_text(value: Any, limit: int) -> str:
    text = str(value)
    cleaned = "".join(char if (char >= " " and char != "\x7f") else " " for char in text)
    return " ".join(cleaned.split())[:limit]
