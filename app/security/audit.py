from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from flask import current_app, g, has_app_context, has_request_context, request, session
from sqlalchemy import text

from app.extensions import db
from app.models import SecurityAuditEvent, User
from app.security.session_hmac import active_hmac_hex

try:
    from webauthn.helpers import bytes_to_base64url
except ImportError:  # pragma: no cover - dependency is required in production.
    bytes_to_base64url = None


SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "challenge",
    "ciphertext",
    "cookie",
    "csrf",
    "full_account",
    "iban",
    "mfa_secret",
    "nonce",
    "passwd",
    "password",
    "private_key",
    "public_key",
    "raw_redis",
    "redis_payload",
    "session_id",
    "sessionid",
    "secret",
    "totp",
    "code",
    "token",
    "uri",
    "url",
)

SENSITIVE_EXACT_KEYS = (
    "credential",
    "sid",
)

ACCOUNT_KEY_PARTS = (
    "account_number",
    "account_no",
    "payee_account",
    "pan",
)

SENSITIVE_CREDENTIAL_URL_RE = re.compile(
    r"\b(?:postgres(?:ql)?|redis)://[^\s/@]*:[^\s/@]*@",
    re.IGNORECASE,
)
SENSITIVE_WEBHOOK_URL_RE = re.compile(
    r"https://(?:[^/\s]*hooks[^/\s]*|(?:discord(?:app)?\.com))/(?:api/)?(?:webhooks|services)/\S+",
    re.IGNORECASE,
)
SENSITIVE_PRIVATE_KEY_RE = re.compile(
    r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY",
    re.IGNORECASE,
)
SENSITIVE_LONG_TOKEN_RE = re.compile(r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_+/=-]{48,}")

AUDIT_HASH_ALGORITHM = "sha256-v1"
AUDIT_CHAIN_START_HASH = "0" * 64
AUDIT_CHAIN_ADVISORY_LOCK_ID = 6151467082736394621


def register_correlation_id(app) -> None:
    @app.before_request
    def set_correlation_id() -> None:
        g.correlation_id = str(uuid.uuid4())


def session_fingerprint(session_id: str | None) -> str | None:
    if not session_id:
        return None
    return active_hmac_hex(session_id, length=16)


def audit_reference(namespace: str, value: Any, *, length: int = 32) -> str | None:
    text = str(value or "").strip()
    if not text or not has_app_context():
        return None
    clean_namespace = _clean_audit_text(namespace, 48).casefold() or "audit"
    return active_hmac_hex(f"audit-ref:{clean_namespace}:{text.casefold()}", length=length)


def principal_reference(identifier: str | None) -> str | None:
    return audit_reference("principal", identifier, length=32)


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

    clean_event_type = _clean_audit_text(event_type, 80)
    clean_outcome = _clean_audit_text(outcome, 24)
    clean_metadata = _sanitize_metadata(metadata or {})
    user_identifier = user.id if user is not None else user_id
    request_ip = _clean_audit_text(request.remote_addr or "unknown", 64)
    request_user_agent = _clean_audit_text(request.user_agent.string or "unknown", 256)
    correlation_id = _clean_audit_text(getattr(g, "correlation_id", str(uuid.uuid4())), 36)
    session_ref = session_fingerprint(session_id or getattr(session, "sid", None))
    path = _clean_audit_text(request.path, 256)
    method = _clean_audit_text(request.method, 16)
    created_at = datetime.now(timezone.utc)

    try:
        _lock_audit_chain_for_insert()
        previous_event_hash = _latest_audit_event_hash()
        event = SecurityAuditEvent(
            event_type=clean_event_type,
            outcome=clean_outcome,
            user_id=user_identifier,
            ip_address=request_ip,
            user_agent=request_user_agent,
            correlation_id=correlation_id,
            session_ref=session_ref,
            event_metadata=clean_metadata,
            previous_event_hash=previous_event_hash,
            hash_algorithm=AUDIT_HASH_ALGORITHM,
            created_at=created_at,
        )
        event.event_hash = _compute_audit_event_hash(event)
        db.session.add(event)
        db.session.flush()
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        _log_audit_write_failed(
            event_type=clean_event_type,
            outcome=clean_outcome,
            user_id=user_identifier,
            ip_address=request_ip,
            user_agent=request_user_agent,
            correlation_id=correlation_id,
            session_ref=session_ref,
            path=path,
            method=method,
            metadata=clean_metadata,
            error_type=type(exc).__name__,
        )
        return

    _log_audit_record(event, path=path, method=method)


def audit_system_event(
    event_type: str,
    outcome: str,
    *,
    user_id: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    clean_event_type = _clean_audit_text(event_type, 80)
    clean_outcome = _clean_audit_text(outcome, 24)
    clean_metadata = {**_sanitize_metadata(metadata or {}), "actor": "system"}
    correlation_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc)
    try:
        _lock_audit_chain_for_insert()
        previous_event_hash = _latest_audit_event_hash()
        event = SecurityAuditEvent(
            event_type=clean_event_type,
            outcome=clean_outcome,
            user_id=user_id,
            ip_address="system",
            user_agent="system",
            correlation_id=correlation_id,
            session_ref=None,
            event_metadata=clean_metadata,
            previous_event_hash=previous_event_hash,
            hash_algorithm=AUDIT_HASH_ALGORITHM,
            created_at=created_at,
        )
        event.event_hash = _compute_audit_event_hash(event)
        db.session.add(event)
        db.session.flush()
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        _log_audit_write_failed(
            event_type=clean_event_type,
            outcome=clean_outcome,
            user_id=user_id,
            ip_address="system",
            user_agent="system",
            correlation_id=correlation_id,
            session_ref=None,
            path=None,
            method=None,
            metadata=clean_metadata,
            error_type=type(exc).__name__,
        )
        return

    _log_audit_record(event, path=None, method=None)


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


def verify_audit_hash_chain(*, anchor: Mapping[str, Any] | None = None) -> dict[str, Any]:
    events = list(
        db.session.execute(
            db.select(SecurityAuditEvent).order_by(SecurityAuditEvent.id.asc())
        ).scalars()
    )
    previous_hash = AUDIT_CHAIN_START_HASH
    chain_started = False
    verified_event_count = 0
    legacy_unhashed_event_count = 0
    latest_event_id: int | None = None
    latest_event_hash: str | None = None
    errors: list[dict[str, Any]] = []

    for event in events:
        if not event.event_hash:
            if chain_started:
                _append_chain_error(errors, event.id, "missing_event_hash")
            else:
                legacy_unhashed_event_count += 1
            continue

        chain_started = True
        if event.hash_algorithm != AUDIT_HASH_ALGORITHM:
            _append_chain_error(
                errors,
                event.id,
                "unsupported_hash_algorithm",
                algorithm=event.hash_algorithm,
            )
        if event.previous_event_hash != previous_hash:
            _append_chain_error(errors, event.id, "previous_hash_mismatch")

        try:
            expected_hash = _compute_audit_event_hash(event)
        except Exception as exc:  # pragma: no cover - defensive around legacy data.
            _append_chain_error(errors, event.id, "hash_compute_failed", error_type=type(exc).__name__)
        else:
            if not hmac.compare_digest(str(event.event_hash), expected_hash):
                _append_chain_error(errors, event.id, "event_hash_mismatch")

        previous_hash = str(event.event_hash)
        latest_event_id = int(event.id)
        latest_event_hash = str(event.event_hash)
        verified_event_count += 1

    result = {
        "valid": not errors,
        "hash_algorithm": AUDIT_HASH_ALGORITHM,
        "chain_start": AUDIT_CHAIN_START_HASH,
        "event_count": len(events),
        "verified_event_count": verified_event_count,
        "legacy_unhashed_event_count": legacy_unhashed_event_count,
        "latest_event_id": latest_event_id,
        "latest_event_hash": latest_event_hash,
        "errors": errors,
        "anchor_validated": None,
        "anchor_errors": [],
    }
    if anchor is not None:
        _compare_audit_anchor(result, anchor)
    return result


def audit_log_anchor() -> dict[str, Any]:
    verification = verify_audit_hash_chain()
    return {
        "message": "security_audit_anchor",
        "generated_at": _utc_iso(datetime.now(timezone.utc)),
        "hash_algorithm": verification["hash_algorithm"],
        "chain_start": verification["chain_start"],
        "event_count": verification["event_count"],
        "verified_event_count": verification["verified_event_count"],
        "legacy_unhashed_event_count": verification["legacy_unhashed_event_count"],
        "latest_event_id": verification["latest_event_id"],
        "latest_event_hash": verification["latest_event_hash"],
        "valid": verification["valid"],
    }


def _sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        key_text = _clean_audit_text(key, 64)
        key_lower = key_text.casefold()
        if _is_sensitive_key(key_lower):
            clean[key_text] = "[redacted]"
            continue
        clean[key_text] = _sanitize_metadata_value(value, key_lower, depth=0)
    return clean


def _sanitize_metadata_value(value: Any, key_lower: str, *, depth: int) -> Any:
    if isinstance(value, bool | int | float) or value is None:
        return value
    if depth < 4 and isinstance(value, Mapping):
        nested: dict[str, Any] = {}
        for nested_key, nested_value in list(value.items())[:20]:
            nested_key_text = _clean_audit_text(nested_key, 64)
            nested_key_lower = nested_key_text.casefold()
            nested[nested_key_text] = (
                "[redacted]"
                if _is_sensitive_key(nested_key_lower)
                else _sanitize_metadata_value(nested_value, nested_key_lower, depth=depth + 1)
            )
        return nested
    if depth < 4 and isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_sanitize_metadata_value(item, key_lower, depth=depth + 1) for item in list(value)[:20]]

    text = _clean_audit_text(value, 256)
    if _looks_like_sensitive_value(text) or _looks_like_account_value(key_lower, text):
        return "[redacted]"
    return text


def _clean_audit_text(value: Any, limit: int) -> str:
    text = str(value)
    cleaned = "".join(char if (char >= " " and char != "\x7f") else " " for char in text)
    return " ".join(cleaned.split())[:limit]


def _is_sensitive_key(key_lower: str) -> bool:
    if key_lower.endswith("_ref") or key_lower in {"principal_ref", "session_ref"}:
        return False
    normalized_key = key_lower.replace("-", "_")
    if normalized_key in SENSITIVE_EXACT_KEYS:
        return True
    return any(part in normalized_key for part in SENSITIVE_KEY_PARTS)


def _looks_like_sensitive_value(text: str) -> bool:
    lowered = text.casefold()
    if lowered.startswith(("bearer ", "basic ", "token ")):
        return True
    if SENSITIVE_CREDENTIAL_URL_RE.search(text):
        return True
    if SENSITIVE_WEBHOOK_URL_RE.search(text):
        return True
    if SENSITIVE_PRIVATE_KEY_RE.search(text):
        return True
    return bool(SENSITIVE_LONG_TOKEN_RE.fullmatch(text.strip()))


def _looks_like_account_value(key_lower: str, text: str) -> bool:
    if key_lower.endswith("_ref"):
        return False
    if not any(part in key_lower for part in ACCOUNT_KEY_PARTS):
        return False
    digits = re.sub(r"\D", "", text)
    return len(digits) >= 8


def _latest_audit_event_hash() -> str:
    statement = (
        db.select(SecurityAuditEvent.event_hash)
        .where(SecurityAuditEvent.event_hash.is_not(None))
        .order_by(SecurityAuditEvent.id.desc())
        .limit(1)
    )
    if db.engine.dialect.name == "postgresql":
        statement = statement.with_for_update()
    latest_hash = db.session.execute(statement).scalar_one_or_none()
    return str(latest_hash or AUDIT_CHAIN_START_HASH)


def _lock_audit_chain_for_insert() -> None:
    if db.engine.dialect.name != "postgresql":
        return
    db.session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"),
        {"lock_id": AUDIT_CHAIN_ADVISORY_LOCK_ID},
    )


def _compute_audit_event_hash(event: SecurityAuditEvent) -> str:
    canonical_payload = _canonical_audit_event_payload(event)
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


def _canonical_audit_event_payload(event: SecurityAuditEvent) -> str:
    payload = {
        "event_type": event.event_type,
        "outcome": event.outcome,
        "user_id": event.user_id,
        "ip_address": event.ip_address,
        "user_agent": event.user_agent,
        "correlation_id": event.correlation_id,
        "session_ref": event.session_ref,
        "event_metadata": _canonical_json_value(event.event_metadata or {}),
        "created_at": _utc_iso(event.created_at),
        "previous_event_hash": event.previous_event_hash,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def _canonical_json_value(value: Any) -> Any:
    if isinstance(value, bool | int | float | str) or value is None:
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_json_value(value[key])
            for key in sorted(value, key=lambda item: str(item))
        }
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray | str):
        return [_canonical_json_value(item) for item in value]
    return str(value)


def _append_chain_error(
    errors: list[dict[str, Any]],
    event_id: int,
    reason: str,
    **extra: Any,
) -> None:
    if len(errors) >= 20:
        return
    error = {"event_id": int(event_id), "reason": reason}
    for key, value in extra.items():
        error[_clean_audit_text(key, 48)] = _clean_audit_text(value, 80)
    errors.append(error)


def _compare_audit_anchor(result: dict[str, Any], anchor: Mapping[str, Any]) -> None:
    anchor_errors: list[dict[str, Any]] = []
    for field in (
        "hash_algorithm",
        "chain_start",
        "event_count",
        "verified_event_count",
        "legacy_unhashed_event_count",
        "latest_event_id",
        "latest_event_hash",
    ):
        if anchor.get(field) == result.get(field):
            continue
        _append_chain_error(
            anchor_errors,
            int(result.get("latest_event_id") or 0),
            "anchor_mismatch",
            field=field,
        )
    if anchor_errors:
        result["errors"].extend(anchor_errors)
        result["valid"] = False
        result["anchor_validated"] = False
        result["anchor_errors"] = anchor_errors
    else:
        result["anchor_validated"] = True
        result["anchor_errors"] = []


def _log_audit_record(event: SecurityAuditEvent, *, path: str | None, method: str | None) -> None:
    payload = {
        "message": "security_audit_event",
        "event_id": event.id,
        "event_type": event.event_type,
        "outcome": event.outcome,
        "user_id": event.user_id,
        "ip_address": event.ip_address,
        "user_agent": event.user_agent,
        "path": path,
        "method": method,
        "correlation_id": event.correlation_id,
        "session_ref": event.session_ref,
        "previous_event_hash": event.previous_event_hash,
        "event_hash": event.event_hash,
        "hash_algorithm": event.hash_algorithm,
        "created_at": _utc_iso(event.created_at),
        "logged_at": _utc_iso(datetime.now(timezone.utc)),
        "metadata": _sanitize_metadata(event.event_metadata or {}),
    }
    current_app.logger.info(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def _log_audit_write_failed(
    *,
    event_type: str,
    outcome: str,
    user_id: int | None,
    ip_address: str,
    user_agent: str,
    correlation_id: str,
    session_ref: str | None,
    path: str | None,
    method: str | None,
    metadata: dict[str, Any],
    error_type: str,
) -> None:
    payload = {
        "message": "security_audit_write_failed",
        "event_type": event_type,
        "outcome": outcome,
        "user_id": user_id,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "path": path,
        "method": method,
        "correlation_id": correlation_id,
        "session_ref": session_ref,
        "error_type": _clean_audit_text(error_type, 80),
        "logged_at": _utc_iso(datetime.now(timezone.utc)),
        "metadata": _sanitize_metadata(metadata),
    }
    current_app.logger.warning(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def _utc_iso(value: datetime) -> str:
    timestamp = value
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
