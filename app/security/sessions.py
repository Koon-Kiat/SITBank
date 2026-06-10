from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import time
import uuid
from datetime import datetime, timezone
from collections.abc import Iterator
from typing import Any

from flask import Flask, current_app, flash, jsonify, redirect, request, session, url_for
from redis import Redis

from app.security.session_hmac import active_hmac_hex, matches_hmac

try:
    from flask_session.redis import RedisSessionInterface
except ImportError:  # Flask-Session keeps compatibility import paths across releases.
    from flask_session.redis.redis import RedisSessionInterface


SESSION_META_PREFIX = "ospbank:session_meta:"
USER_SESSIONS_PREFIX = "ospbank:user_sessions:"
PAST_SESSIONS_PREFIX = "ospbank:past_sessions:"
REVOKED_SESSION_PREFIX = "ospbank:revoked_session:"
SESSION_RISK_REAUTH_REQUIRED_KEY = "risk_reauth_required"
SESSION_RISK_FINGERPRINT_KEY = "risk_fingerprint"
SESSION_HISTORY_LIMIT_DEFAULT = 20
SESSION_END_REASON_LABELS = {
    "logout": "Logged out",
    "terminated": "Terminated",
    "revoked": "Revoked",
    "expired": "Expired",
    "rotated": "Session refreshed",
    "ended": "Ended",
}


class UuidRedisSessionInterface(RedisSessionInterface):
    def _generate_sid(self, session_id_length: int | None = None) -> str:
        return str(uuid.uuid4())


def install_uuid_redis_sessions(app: Flask, redis_client: Redis) -> None:
    app.config["SESSION_REDIS"] = redis_client
    app.session_interface = UuidRedisSessionInterface(
        app,
        client=redis_client,
        key_prefix=app.config["SESSION_KEY_PREFIX"],
        use_signer=False,
        permanent=True,
        sid_length=32,
        serialization_format="msgpack",
    )


def _redis() -> Redis:
    return current_app.extensions["redis"]


def _redis_session() -> Redis:
    return current_app.extensions["redis_session"]


def _now() -> int:
    return int(time.time())


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def current_session_id() -> str | None:
    return getattr(session, "sid", None)


def public_session_reference(session_id: str | None) -> str:
    if not session_id:
        return ""
    return active_hmac_hex(f"session-reference:{session_id}", length=32)


def _session_storage_key(session_id: str) -> str:
    return f"{current_app.config['SESSION_KEY_PREFIX']}{session_id}"


def _session_meta_key(session_id: str) -> str:
    return f"{SESSION_META_PREFIX}{session_id}"


def _user_sessions_key(user_id: int) -> str:
    return f"{USER_SESSIONS_PREFIX}{user_id}"


def _past_sessions_key(user_id: int) -> str:
    return f"{PAST_SESSIONS_PREFIX}{user_id}"


def _revoked_key(session_id: str) -> str:
    return f"{REVOKED_SESSION_PREFIX}{session_id}"


def rotate_session_id() -> None:
    if session:
        current_app.session_interface.regenerate(session)


def begin_password_authenticated_session(user_id: int) -> None:
    session.clear()
    session.permanent = True
    session["pending_mfa_user_id"] = user_id
    session["password_authenticated_at"] = _now()
    session["last_activity_at"] = _now()
    rotate_session_id()


def establish_authenticated_session(
    *,
    user_id: int,
    mfa_verified: bool,
    auth_context: str,
) -> str:
    login_time = utc_now_iso()
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["auth_context"] = auth_context
    session["login_at"] = login_time
    session["last_activity_at"] = _now()
    if mfa_verified:
        now = _now()
        session["mfa_verified_at"] = now
        session["fresh_mfa_verified_at"] = now
    rotate_session_id()
    refresh_session_risk_fingerprint()
    register_session_metadata(user_id=user_id, login_time=login_time)
    return current_session_id() or ""


def mark_fresh_mfa() -> None:
    now = _now()
    session["mfa_verified_at"] = now
    session["fresh_mfa_verified_at"] = now
    session["last_activity_at"] = now
    session.modified = True


def has_recent_fresh_mfa() -> bool:
    verified_at = int(session.get("fresh_mfa_verified_at") or 0)
    if not verified_at:
        return False
    return _now() - verified_at <= current_app.config["FRESH_MFA_SECONDS"]


def rotate_authenticated_session_after_mfa(user_id: int) -> str:
    old_session_id = current_session_id()
    login_time = session.get("login_at") or utc_now_iso()
    mark_fresh_mfa()
    rotate_session_id()
    new_session_id = current_session_id()
    if old_session_id and old_session_id != new_session_id:
        redis_client = _redis()
        metadata = redis_client.hgetall(_session_meta_key(old_session_id))
        if metadata:
            _record_past_session(
                redis_client,
                session_id=old_session_id,
                user_id=user_id,
                metadata=metadata,
                ended_reason="rotated",
            )
        redis_client.delete(_session_meta_key(old_session_id))
        redis_client.srem(_user_sessions_key(user_id), old_session_id)
        redis_client.setex(
            _revoked_key(old_session_id),
            current_app.config["SESSION_INACTIVITY_SECONDS"],
            "1",
        )
    refresh_session_risk_fingerprint()
    register_session_metadata(user_id=user_id, login_time=login_time)
    return new_session_id or ""


def refresh_session_risk_fingerprint() -> None:
    if not current_session_id():
        return
    fingerprint = current_session_risk_fingerprint()
    session[SESSION_RISK_FINGERPRINT_KEY] = fingerprint
    session.pop(SESSION_RISK_REAUTH_REQUIRED_KEY, None)
    session.modified = True
    session_id = current_session_id()
    if session_id:
        _redis().hset(_session_meta_key(session_id), SESSION_RISK_FINGERPRINT_KEY, fingerprint)


def current_session_risk_fingerprint() -> str:
    return active_hmac_hex(_current_session_risk_message(), length=32)


def _current_session_risk_message() -> str:
    parts = [
        _normalized_ip_context(request.remote_addr or ""),
        _user_agent_fingerprint(request.user_agent.string or "unknown"),
        str(session.get("auth_context") or ""),
        str(session.get("webauthn_credential_id") or ""),
    ]
    return "|".join(parts)


def require_stable_session_for_sensitive_action(action: str) -> None:
    if not current_session_id():
        return
    current = current_session_risk_fingerprint()
    stored = session.get(SESSION_RISK_FINGERPRINT_KEY)
    if not stored:
        refresh_session_risk_fingerprint()
        return
    if hmac.compare_digest(str(stored), current):
        return
    if matches_hmac(str(stored), _current_session_risk_message(), length=32):
        refresh_session_risk_fingerprint()
        return

    session[SESSION_RISK_REAUTH_REQUIRED_KEY] = True
    session.modified = True
    from app.auth.services import AuthError
    from app.security.audit import audit_event

    audit_event("session_risk", "step_up_required", metadata={"action": action})
    raise AuthError("Session verification required. Please sign in again.", 401)


def _normalized_ip_context(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if address.version == 4:
        return str(ipaddress.ip_network(f"{address}/24", strict=False).network_address) + "/24"
    return str(ipaddress.ip_network(f"{address}/64", strict=False).network_address) + "/64"


def _user_agent_fingerprint(value: str) -> str:
    normalized = " ".join((value or "unknown").split())[:256]
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def register_session_metadata(user_id: int, login_time: str) -> None:
    session_id = current_session_id()
    if not session_id:
        return
    ttl = current_app.config["SESSION_INACTIVITY_SECONDS"]
    metadata = {
        "session_id": session_id,
        "user_id": str(user_id),
        "ip_address": request.remote_addr or "",
        "user_agent": (request.user_agent.string or "unknown")[:256],
        "login_time": login_time,
        "last_activity": utc_now_iso(),
        SESSION_RISK_FINGERPRINT_KEY: session.get(SESSION_RISK_FINGERPRINT_KEY, ""),
    }
    redis_client = _redis()
    redis_client.hset(_session_meta_key(session_id), mapping=metadata)
    redis_client.expire(_session_meta_key(session_id), ttl)
    redis_client.sadd(_user_sessions_key(user_id), session_id)
    redis_client.expire(_user_sessions_key(user_id), 24 * 60 * 60)


def update_session_activity() -> None:
    session_id = current_session_id()
    user_id = session.get("user_id")
    if not session_id or not user_id:
        return
    ttl = current_app.config["SESSION_INACTIVITY_SECONDS"]
    redis_client = _redis()
    redis_client.hset(_session_meta_key(session_id), "last_activity", utc_now_iso())
    redis_client.expire(_session_meta_key(session_id), ttl)
    _redis_session().expire(_session_storage_key(session_id), ttl)


def _active_session_records(user_id: int) -> Iterator[tuple[str, dict[str, str]]]:
    redis_client = _redis()
    session_ids = list(redis_client.smembers(_user_sessions_key(user_id)))
    if not session_ids:
        return

    storage_pipeline = _redis_session().pipeline()
    metadata_pipeline = redis_client.pipeline()
    for session_id in session_ids:
        storage_pipeline.exists(_session_storage_key(session_id))
        metadata_pipeline.hgetall(_session_meta_key(session_id))

    storage_exists = storage_pipeline.execute()
    metadata_records = metadata_pipeline.execute()
    cleanup_pipeline = redis_client.pipeline()
    cleanup_required = False
    active_records: list[tuple[str, dict[str, str]]] = []

    for session_id, session_exists, metadata in zip(
        session_ids,
        storage_exists,
        metadata_records,
        strict=True,
    ):
        if not session_exists:
            if metadata:
                key, payload = _past_session_record(
                    session_id=session_id,
                    user_id=user_id,
                    metadata=metadata,
                    ended_reason="expired",
                )
                if key and payload:
                    cleanup_pipeline.lpush(key, payload)
                    cleanup_pipeline.ltrim(key, 0, _session_history_limit() - 1)
            cleanup_pipeline.srem(_user_sessions_key(user_id), session_id)
            cleanup_pipeline.delete(_session_meta_key(session_id))
            cleanup_required = True
            continue
        if not metadata:
            cleanup_pipeline.srem(_user_sessions_key(user_id), session_id)
            cleanup_required = True
            continue
        active_records.append((session_id, metadata))

    if cleanup_required:
        cleanup_pipeline.execute()
    yield from active_records


def list_active_sessions(user_id: int) -> list[dict[str, Any]]:
    sessions: list[dict[str, Any]] = []
    current_sid = current_session_id()
    for session_id, metadata in _active_session_records(user_id):
        public_metadata = {
            "session_ref": public_session_reference(session_id),
            "current": session_id == current_sid,
            "ip_address": _display_ip_address(metadata.get("ip_address", "")),
            "user_agent": _summarize_user_agent(metadata.get("user_agent", "")),
            "login_time": metadata.get("login_time", ""),
            "last_activity": metadata.get("last_activity", ""),
            "login_time_display": _format_session_time(metadata.get("login_time", "")),
            "last_activity_display": _format_session_time(metadata.get("last_activity", "")),
        }
        sessions.append(public_metadata)
    return sorted(sessions, key=lambda item: item.get("login_time", ""), reverse=True)


def list_past_sessions(user_id: int, limit: int | None = None) -> list[dict[str, Any]]:
    count = _session_history_limit(limit)
    if count <= 0:
        return []

    sessions: list[dict[str, Any]] = []
    for payload in _redis().lrange(_past_sessions_key(user_id), 0, count - 1):
        try:
            record = json.loads(payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue

        ended_reason = _normalize_session_end_reason(str(record.get("ended_reason", "")))
        public_metadata = {
            "session_ref": str(record.get("session_ref", "")),
            "ip_address": _display_ip_address(str(record.get("ip_address", ""))),
            "user_agent": _summarize_user_agent(str(record.get("user_agent", ""))),
            "login_time": str(record.get("login_time", "")),
            "last_activity": str(record.get("last_activity", "")),
            "ended_at": str(record.get("ended_at", "")),
            "ended_reason": ended_reason,
            "login_time_display": _format_session_time(str(record.get("login_time", ""))),
            "last_activity_display": _format_session_time(str(record.get("last_activity", ""))),
            "ended_at_display": _format_session_time(str(record.get("ended_at", ""))),
            "ended_reason_display": SESSION_END_REASON_LABELS[ended_reason],
        }
        sessions.append(public_metadata)
    return sessions


def resolve_session_reference_for_user(user_id: int, session_reference: str) -> str | None:
    for session_id, _metadata in _active_session_records(user_id):
        if matches_hmac(
            session_reference,
            f"session-reference:{session_id}",
            length=32,
        ):
            return session_id
    return None


def _session_history_limit(limit: int | None = None) -> int:
    configured_limit = limit if limit is not None else current_app.config.get(
        "SESSION_HISTORY_LIMIT",
        SESSION_HISTORY_LIMIT_DEFAULT,
    )
    try:
        value = int(configured_limit)
    except (TypeError, ValueError):
        return SESSION_HISTORY_LIMIT_DEFAULT
    return max(0, min(value, 100))


def _normalize_session_end_reason(value: str) -> str:
    return value if value in SESSION_END_REASON_LABELS else "ended"


def _record_past_session(
    redis_client: Redis,
    *,
    session_id: str,
    user_id: int,
    metadata: dict[str, str],
    ended_reason: str,
) -> None:
    key, payload = _past_session_record(
        session_id=session_id,
        user_id=user_id,
        metadata=metadata,
        ended_reason=ended_reason,
    )
    if not key or not payload:
        return

    limit = _session_history_limit()
    pipeline = redis_client.pipeline()
    pipeline.lpush(key, payload)
    pipeline.ltrim(key, 0, limit - 1)
    pipeline.execute()


def _past_session_record(
    *,
    session_id: str,
    user_id: int,
    metadata: dict[str, str],
    ended_reason: str,
) -> tuple[str, str]:
    limit = _session_history_limit()
    if limit <= 0:
        return "", ""

    reason = _normalize_session_end_reason(ended_reason)
    record = {
        "session_ref": public_session_reference(session_id),
        "ip_address": metadata.get("ip_address", ""),
        "user_agent": metadata.get("user_agent", ""),
        "login_time": metadata.get("login_time", ""),
        "last_activity": metadata.get("last_activity", ""),
        "ended_at": utc_now_iso(),
        "ended_reason": reason,
    }
    key = _past_sessions_key(user_id)
    payload = json.dumps(record, separators=(",", ":"), sort_keys=True)
    return key, payload


def _display_ip_address(value: str) -> str:
    if not value:
        return "unknown"
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    return address.compressed


def _summarize_user_agent(value: str) -> str:
    normalized = " ".join((value or "unknown").split())
    if len(normalized) <= 120:
        return normalized
    return f"{normalized[:117]}..."


def _format_session_time(value: str) -> str:
    if not value:
        return "Unknown"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return "Unknown"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    local_time = parsed.astimezone()
    return local_time.strftime("%d %b %Y %H:%M")


def revoke_session(session_id: str, user_id: int | None = None, *, ended_reason: str = "revoked") -> None:
    redis_client = _redis()
    metadata = redis_client.hgetall(_session_meta_key(session_id))
    owner = user_id
    if owner is None:
        try:
            owner = int(metadata.get("user_id") or 0) or None
        except ValueError:
            owner = None

    if owner is not None and metadata:
        _record_past_session(
            redis_client,
            session_id=session_id,
            user_id=owner,
            metadata=metadata,
            ended_reason=ended_reason,
        )

    _redis_session().delete(_session_storage_key(session_id))
    redis_client.delete(_session_meta_key(session_id))
    redis_client.setex(_revoked_key(session_id), current_app.config["SESSION_INACTIVITY_SECONDS"], "1")
    if owner is not None:
        redis_client.srem(_user_sessions_key(owner), session_id)


def revoke_current_session(*, ended_reason: str = "revoked") -> None:
    session_id = current_session_id()
    user_id = session.get("user_id") or session.get("pending_mfa_user_id")
    if session_id:
        revoke_session(session_id, int(user_id) if user_id else None, ended_reason=ended_reason)
    session.clear()


def revoke_other_sessions(user_id: int, *, ended_reason: str = "revoked") -> int:
    current_sid = current_session_id()
    revoked = 0
    for session_id, _metadata in _active_session_records(user_id):
        if session_id == current_sid:
            continue
        revoke_session(session_id, user_id, ended_reason=ended_reason)
        revoked += 1
    return revoked


def revoke_all_sessions(user_id: int, *, ended_reason: str = "revoked") -> int:
    revoked = 0
    for session_id, _metadata in list(_active_session_records(user_id)):
        revoke_session(session_id, user_id, ended_reason=ended_reason)
        revoked += 1
    return revoked


def register_session_hooks(app: Flask) -> None:
    @app.before_request
    def enforce_session_activity():
        session_id = current_session_id()
        if session_id and _redis().exists(_revoked_key(session_id)):
            session.clear()
            if not request.path.startswith("/auth/"):
                if request.endpoint in {
                    "main.index",
                    "web.login",
                    "web.login_submit",
                    "web.register_form",
                    "web.register_submit",
                }:
                    return None
                return redirect(url_for("web.login"))
            return jsonify({"error": "Session revoked"}), 401

        principal_id = session.get("user_id") or session.get("pending_mfa_user_id")
        if not principal_id:
            return None

        now = _now()
        pending_mfa_user_id = session.get("pending_mfa_user_id")
        if pending_mfa_user_id:
            authenticated_at = int(session.get("password_authenticated_at") or 0)
            max_age = current_app.config["PENDING_MFA_MAX_AGE_SECONDS"]
            if not authenticated_at or now - authenticated_at > max_age:
                session_id = current_session_id()
                revoke_current_session(ended_reason="expired")
                from app.security.audit import audit_event

                audit_event(
                    "mfa_login_expired",
                    "expired",
                    user_id=int(pending_mfa_user_id),
                    session_id=session_id,
                )
                if request.path.startswith("/auth/"):
                    return jsonify(
                        {
                            "error": "MFA challenge expired. Please log in again.",
                            "code": "mfa_challenge_expired",
                        }
                    ), 401
                flash("MFA challenge expired. Please log in again.", "warning")
                rotate_session_id()
                return redirect(url_for("web.login"))

        last_activity = int(session.get("last_activity_at") or now)
        if now - last_activity > current_app.config["SESSION_INACTIVITY_SECONDS"]:
            revoke_current_session(ended_reason="expired")
            return jsonify({"error": "Session expired"}), 401

        session["last_activity_at"] = now
        session.modified = True
        update_session_activity()
        return None
