from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import current_app, g, has_app_context, has_request_context, request, session
from sqlalchemy import text

from app.extensions import db
from app.models import SecurityAuditEvent, User
from app.security.sensitive_values import contains_sensitive_url
from app.security.session_hmac import active_hmac_hex


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

SENSITIVE_PRIVATE_KEY_RE = re.compile(
    r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY",
    re.IGNORECASE,
)
SENSITIVE_LONG_TOKEN_RE = re.compile(r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_+/=-]{48,}")

AUDIT_HASH_ALGORITHM = "hmac-sha256-v1"
LEGACY_AUDIT_HASH_ALGORITHM = "sha256-v1"
SUPPORTED_AUDIT_HASH_ALGORITHMS = frozenset(
    {AUDIT_HASH_ALGORITHM, LEGACY_AUDIT_HASH_ALGORITHM}
)
AUDIT_HMAC_KEY_MIN_LENGTH = 32
AUDIT_CHAIN_START_HASH = "0" * 64
AUDIT_CHAIN_ADVISORY_LOCK_ID = 6151467082736394621


class AuditWriteError(RuntimeError):
    """Raised when a protected action cannot write its required audit event."""


REDACTED_VALUE = "[redacted]"


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
    _audit_event(
        event_type,
        outcome,
        user=user,
        user_id=user_id,
        metadata=metadata,
        session_id=session_id,
        required=False,
    )


def audit_event_required(
    event_type: str,
    outcome: str,
    *,
    user: User | None = None,
    user_id: int | None = None,
    metadata: dict[str, Any] | None = None,
    session_id: str | None = None,
) -> None:
    """Flush a required audit row without owning the caller's transaction.

    Callers that mutate business state must commit after this returns, or roll
    back if it raises. Keeping that boundary explicit prevents audit logging
    from accidentally committing or rolling back unrelated pending state.
    """
    _audit_event(
        event_type,
        outcome,
        user=user,
        user_id=user_id,
        metadata=metadata,
        session_id=session_id,
        required=True,
    )


def validate_audit_integrity_config() -> int:
    return len(_audit_hmac_key_bytes())


def _audit_event(
    event_type: str,
    outcome: str,
    *,
    user: User | None,
    user_id: int | None,
    metadata: dict[str, Any] | None,
    session_id: str | None,
    required: bool,
) -> None:
    if not has_request_context():
        if required:
            raise AuditWriteError("Required audit events need a request context")
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
        with db.session.no_autoflush:
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
        if required:
            db.session.flush([event])
        else:
            db.session.flush()
            db.session.commit()
    except Exception as exc:
        if not required:
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
        if required:
            raise AuditWriteError("Required audit event could not be recorded") from exc
        return

    _log_audit_record(event, path=path, method=method)


def audit_system_event(
    event_type: str,
    outcome: str,
    *,
    user_id: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    _write_system_audit_event(
        event_type,
        outcome,
        user_id=user_id,
        metadata=metadata,
        required=False,
    )


def audit_system_event_required(
    event_type: str,
    outcome: str,
    *,
    user_id: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Commit a standalone system audit event or fail the operation closed."""
    _write_system_audit_event(
        event_type,
        outcome,
        user_id=user_id,
        metadata=metadata,
        required=True,
    )


def _write_system_audit_event(
    event_type: str,
    outcome: str,
    *,
    user_id: int | None,
    metadata: dict[str, Any] | None,
    required: bool,
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
        if required:
            raise AuditWriteError(
                "Required system audit event could not be recorded"
            ) from exc
        return

    _log_audit_record(event, path=None, method=None)


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
            legacy_unhashed_event_count += _record_missing_event_hash(
                event,
                chain_started=chain_started,
                errors=errors,
            )
            continue
        chain_started = True
        _verify_hashed_audit_event(event, previous_hash=previous_hash, errors=errors)
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
        "anchor_status": "not_configured",
        "anchor_stale": False,
        "anchor_event_id": None,
        "events_since_anchor": None,
        "anchor_refresh_required": False,
    }
    if anchor is not None:
        _compare_audit_anchor(result, anchor)
    return result


def _record_missing_event_hash(
    event: SecurityAuditEvent,
    *,
    chain_started: bool,
    errors: list[dict[str, Any]],
) -> int:
    if chain_started:
        _append_chain_error(errors, event.id, "missing_event_hash")
        return 0
    return 1


def _verify_hashed_audit_event(
    event: SecurityAuditEvent,
    *,
    previous_hash: str,
    errors: list[dict[str, Any]],
) -> None:
    event_algorithm = event.hash_algorithm or LEGACY_AUDIT_HASH_ALGORITHM
    if event_algorithm not in SUPPORTED_AUDIT_HASH_ALGORITHMS:
        _append_chain_error(
            errors,
            event.id,
            "unsupported_hash_algorithm",
            algorithm=event_algorithm,
        )
    if event.previous_event_hash != previous_hash:
        _append_chain_error(errors, event.id, "previous_hash_mismatch")
    try:
        expected_hash = _compute_audit_event_hash(event)
    except Exception as exc:  # pragma: no cover - defensive around legacy data.
        _append_chain_error(
            errors,
            event.id,
            "hash_compute_failed",
            error_type=type(exc).__name__,
        )
        return
    if not hmac.compare_digest(str(event.event_hash), expected_hash):
        _append_chain_error(errors, event.id, "event_hash_mismatch")


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


def write_audit_log_anchor(path: Path) -> dict[str, Any]:
    if path.exists() and not path.is_file():
        raise RuntimeError("Audit anchor output must identify a regular file")
    anchor = audit_log_anchor()
    payload = json.dumps(anchor, separators=(",", ":"), sort_keys=True) + "\n"
    temporary_path = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary_path.write_text(payload, encoding="utf-8")
        temporary_path.chmod(0o600)
        temporary_path.replace(path)
        path.chmod(0o600)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    return anchor


def refresh_audit_log_anchor(path: Path) -> dict[str, Any]:
    """Refresh only a validated or append-only stale configured anchor."""
    validate_existing_audit_anchor_path(path)
    try:
        existing_anchor = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Configured audit anchor is unreadable or malformed") from exc
    if not isinstance(existing_anchor, dict):
        raise RuntimeError("Configured audit anchor must contain a JSON object")

    try:
        _lock_audit_chain_for_insert()
        verification = verify_audit_hash_chain(anchor=existing_anchor)
        if (
            verification.get("valid") is not True
            or verification.get("anchor_status") not in {"validated", "stale"}
        ):
            raise RuntimeError(
                "Audit anchor refresh refused because chain or anchor validation failed"
            )
        previous_status = str(verification["anchor_status"])
        refreshed_anchor = write_audit_log_anchor(path)
        if refreshed_anchor.get("valid") is not True:
            raise RuntimeError("Audit anchor refresh refused because the chain is invalid")
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    return {
        "message": "security_audit_anchor_refreshed",
        "previous_anchor_status": previous_status,
        "anchor_status": "validated",
        "anchor_refresh_required": False,
        "event_count": int(refreshed_anchor.get("event_count") or 0),
        "latest_event_id": refreshed_anchor.get("latest_event_id"),
    }


def validate_existing_audit_anchor_path(path: Path) -> None:
    if not path.is_absolute():
        raise RuntimeError("Configured audit anchor path must be absolute")
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("Configured audit anchor must be a regular non-symlink file")
    parent = path.parent
    if not parent.is_dir() or any(item.is_symlink() for item in path.parents):
        raise RuntimeError("Configured audit anchor parent directory is unsafe")
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise RuntimeError("Configured audit anchor permissions must be owner-only")


def _sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        key_text = _clean_audit_text(key, 64)
        key_lower = key_text.casefold()
        if _is_sensitive_key(key_lower):
            clean[key_text] = REDACTED_VALUE
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
                REDACTED_VALUE
                if _is_sensitive_key(nested_key_lower)
                else _sanitize_metadata_value(nested_value, nested_key_lower, depth=depth + 1)
            )
        return nested
    if depth < 4 and isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_sanitize_metadata_value(item, key_lower, depth=depth + 1) for item in list(value)[:20]]

    raw_text = str(value)
    if contains_sensitive_url(raw_text):
        return REDACTED_VALUE
    text = _clean_audit_text(raw_text, 256)
    if _looks_like_sensitive_value(text) or _looks_like_account_value(key_lower, text):
        return REDACTED_VALUE
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
    # PostgreSQL inserts are already serialized by the advisory transaction lock.
    # Avoid row locks so the runtime role only needs append-only SELECT/INSERT access.
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
    algorithm = event.hash_algorithm or LEGACY_AUDIT_HASH_ALGORITHM
    payload = canonical_payload.encode("utf-8")
    if algorithm == AUDIT_HASH_ALGORITHM:
        return hmac.new(_audit_hmac_key_bytes(), payload, hashlib.sha256).hexdigest()
    if algorithm == LEGACY_AUDIT_HASH_ALGORITHM:
        return hashlib.sha256(payload).hexdigest()
    raise ValueError(f"Unsupported audit hash algorithm: {algorithm}")


def _audit_hmac_key_bytes() -> bytes:
    if not has_app_context():
        raise RuntimeError("SECURITY_AUDIT_HMAC_KEY requires an application context")
    value = str(current_app.config.get("SECURITY_AUDIT_HMAC_KEY") or "")
    if len(value) < AUDIT_HMAC_KEY_MIN_LENGTH:
        raise RuntimeError(
            f"SECURITY_AUDIT_HMAC_KEY must be at least {AUDIT_HMAC_KEY_MIN_LENGTH} characters"
        )
    return value.encode("utf-8")


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
    result["anchor_status"] = "checking"
    result["anchor_validated"] = False
    result["anchor_stale"] = False
    result["anchor_refresh_required"] = False

    anchor_values = _validated_anchor_values(result, anchor, anchor_errors)
    anchor_event_id = anchor_values.get("latest_event_id")
    result["anchor_event_id"] = anchor_event_id
    if anchor_errors:
        _set_critical_anchor_errors(result, anchor_errors)
        return

    chain_valid = result.get("valid") is True
    if not chain_valid:
        result["anchor_status"] = "not_checked_due_chain_failure"
        result["anchor_errors"] = []
        return

    if _anchor_matches_current_head(result, anchor):
        result["anchor_validated"] = True
        result["anchor_status"] = "validated"
        result["anchor_errors"] = []
        result["events_since_anchor"] = 0
        return

    if _anchor_is_append_only_stale(result, anchor_values):
        result["anchor_status"] = "stale"
        result["anchor_stale"] = True
        result["anchor_refresh_required"] = True
        result["anchor_errors"] = []
        result["events_since_anchor"] = int(result["event_count"]) - int(anchor_values["event_count"])
        return

    for field in _ANCHOR_CURRENT_HEAD_FIELDS:
        if anchor.get(field) != result.get(field):
            _append_chain_error(
                anchor_errors,
                int(result.get("latest_event_id") or 0),
                "anchor_mismatch",
                field=field,
            )
    if anchor_errors:
        _set_critical_anchor_errors(result, anchor_errors)


_ANCHOR_CURRENT_HEAD_FIELDS = (
    "hash_algorithm",
    "chain_start",
    "event_count",
    "verified_event_count",
    "legacy_unhashed_event_count",
    "latest_event_id",
    "latest_event_hash",
)


def _validated_anchor_values(
    result: Mapping[str, Any],
    anchor: Mapping[str, Any],
    anchor_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    event_id_for_error = int(result.get("latest_event_id") or 0)
    values: dict[str, Any] = {}
    for field in ("hash_algorithm", "chain_start"):
        values[field] = anchor.get(field)
        if anchor.get(field) != result.get(field):
            _append_chain_error(
                anchor_errors,
                event_id_for_error,
                "anchor_mismatch",
                field=field,
            )
    if anchor.get("valid") is not True:
        _append_chain_error(
            anchor_errors,
            event_id_for_error,
            "anchor_malformed",
            field="valid",
        )
    for field in (
        "event_count",
        "verified_event_count",
        "legacy_unhashed_event_count",
    ):
        values[field] = _anchor_non_negative_int(
            anchor,
            field,
            event_id_for_error=event_id_for_error,
            anchor_errors=anchor_errors,
        )
    values["latest_event_id"] = _anchor_latest_event_id(
        result,
        anchor,
        event_id_for_error=event_id_for_error,
        anchor_errors=anchor_errors,
    )
    values["latest_event_hash"] = _anchor_latest_event_hash(
        result,
        anchor,
        event_id_for_error=event_id_for_error,
        anchor_errors=anchor_errors,
    )
    if anchor_errors:
        return values

    _validate_anchor_position(result, values, anchor_errors)
    if anchor_errors:
        return values
    _validate_anchor_event_hash(values, anchor_errors)
    return values


def _anchor_non_negative_int(
    anchor: Mapping[str, Any],
    field: str,
    *,
    event_id_for_error: int,
    anchor_errors: list[dict[str, Any]],
) -> int | None:
    value = anchor.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _append_chain_error(
            anchor_errors,
            event_id_for_error,
            "anchor_malformed",
            field=field,
        )
        return None
    return int(value)


def _anchor_latest_event_id(
    result: Mapping[str, Any],
    anchor: Mapping[str, Any],
    *,
    event_id_for_error: int,
    anchor_errors: list[dict[str, Any]],
) -> int | None:
    value = anchor.get("latest_event_id")
    if value is None and result.get("latest_event_id") is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _append_chain_error(
            anchor_errors,
            event_id_for_error,
            "anchor_malformed",
            field="latest_event_id",
        )
        return None
    return int(value)


def _anchor_latest_event_hash(
    result: Mapping[str, Any],
    anchor: Mapping[str, Any],
    *,
    event_id_for_error: int,
    anchor_errors: list[dict[str, Any]],
) -> str | None:
    value = anchor.get("latest_event_hash")
    if value is None and result.get("latest_event_hash") is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        _append_chain_error(
            anchor_errors,
            event_id_for_error,
            "anchor_malformed",
            field="latest_event_hash",
        )
        return None
    return value


def _validate_anchor_position(
    result: Mapping[str, Any],
    anchor_values: Mapping[str, Any],
    anchor_errors: list[dict[str, Any]],
) -> None:
    latest_event_id = result.get("latest_event_id")
    anchor_event_id = anchor_values.get("latest_event_id")
    event_id_for_error = int(latest_event_id or 0)
    if anchor_event_id is not None and latest_event_id is not None and anchor_event_id > int(latest_event_id):
        _append_chain_error(
            anchor_errors,
            event_id_for_error,
            "anchor_current_behind",
            field="latest_event_id",
        )
    for field in (
        "event_count",
        "verified_event_count",
        "legacy_unhashed_event_count",
    ):
        anchor_count = anchor_values.get(field)
        if anchor_count is not None and int(anchor_count) > int(result.get(field) or 0):
            _append_chain_error(
                anchor_errors,
                event_id_for_error,
                "anchor_current_behind",
                field=field,
            )


def _validate_anchor_event_hash(
    anchor_values: Mapping[str, Any],
    anchor_errors: list[dict[str, Any]],
) -> None:
    anchor_event_id = anchor_values.get("latest_event_id")
    anchor_event_hash = anchor_values.get("latest_event_hash")
    if anchor_event_id is None and anchor_event_hash is None:
        return
    event_id_for_error = int(anchor_event_id or 0)
    anchored_event = db.session.get(SecurityAuditEvent, anchor_event_id)
    if anchored_event is None or not anchored_event.event_hash:
        _append_chain_error(
            anchor_errors,
            event_id_for_error,
            "anchor_event_missing",
        )
        return
    if not hmac.compare_digest(str(anchored_event.event_hash), str(anchor_event_hash)):
        _append_chain_error(
            anchor_errors,
            event_id_for_error,
            "anchor_event_hash_mismatch",
        )


def _anchor_matches_current_head(result: Mapping[str, Any], anchor: Mapping[str, Any]) -> bool:
    return all(anchor.get(field) == result.get(field) for field in _ANCHOR_CURRENT_HEAD_FIELDS)


def _anchor_is_append_only_stale(
    result: Mapping[str, Any],
    anchor_values: Mapping[str, Any],
) -> bool:
    anchor_event_id = anchor_values.get("latest_event_id")
    latest_event_id = result.get("latest_event_id")
    if anchor_event_id is None or latest_event_id is None:
        return False
    if int(anchor_event_id) >= int(latest_event_id):
        return False
    anchor_event_count = anchor_values.get("event_count")
    if anchor_event_count is None or int(anchor_event_count) >= int(result.get("event_count") or 0):
        return False
    return all(
        int(anchor_values[field]) <= int(result.get(field) or 0)
        for field in (
            "event_count",
            "verified_event_count",
            "legacy_unhashed_event_count",
        )
        if anchor_values.get(field) is not None
    )


def _set_critical_anchor_errors(
    result: dict[str, Any],
    anchor_errors: list[dict[str, Any]],
) -> None:
    result["errors"].extend(anchor_errors)
    result["valid"] = False
    result["anchor_validated"] = False
    result["anchor_stale"] = False
    result["anchor_refresh_required"] = False
    result["anchor_status"] = "critical"
    result["anchor_errors"] = anchor_errors


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
