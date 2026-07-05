from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any

from flask import Flask, current_app, flash, has_request_context, jsonify, redirect, request, session, url_for
from flask.sessions import SessionInterface, SessionMixin, session_json_serializer
from sqlalchemy.exc import IntegrityError
from werkzeug.datastructures import CallbackDict

from app.extensions import db
from app.models import ServerSideSession
from app.security.session_hmac import (
    SessionPayloadIntegrityError,
    active_hmac_hex,
    candidate_hmac_hex,
    matches_hmac,
    sign_session_payload,
    verify_session_payload,
)


SESSION_RISK_REAUTH_REQUIRED_KEY = "risk_reauth_required"
JSON_MIME_TYPE = "application/json"
WEB_LOGIN_ENDPOINT = "web.login"
ADMIN_LOGIN_ENDPOINT = "admin.login_form"
SESSION_RISK_FINGERPRINT_KEY = "risk_fingerprint"
SESSION_RISK_CONTEXT_KEY = "risk_context"
SESSION_RISK_CONTEXT_VERSION = 1
AUTH_CREATED_AT_KEY = "auth_created_at"
SESSION_HISTORY_LIMIT_DEFAULT = 20
SESSION_PAYLOAD_FORMAT = "session-hmac-v2"
SESSION_END_REASON_LABELS = {
    "logout": "Logged out",
    "terminated": "Terminated",
    "revoked": "Revoked",
    "expired": "Expired",
    "absolute_lifetime": "Session lifetime expired",
    "risk_change": "Session context changed",
    "rotated": "Session refreshed",
    "integrity_failure": "Session integrity failure",
    "session_cap": "Replaced by a new sign-in",
    "password_change": "Password changed",
    "password_reset": "Password reset",
    "manual_recovery": "Manual recovery completed",
    "security_unlock": "Security lock cleared",
    "ended": "Ended",
}
_SESSION_STORE_LOCK = threading.RLock()


def _session_store_locked(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        with _SESSION_STORE_LOCK:
            return func(*args, **kwargs)

    return wrapper


class DatabaseSession(CallbackDict, SessionMixin):
    def __init__(
        self,
        initial: dict[str, Any] | None = None,
        *,
        sid: str | None = None,
        new: bool = False,
    ) -> None:
        def on_update(_session: DatabaseSession) -> None:
            self.modified = True
            self.accessed = True

        super().__init__(initial, on_update)
        self.sid = sid or _new_session_id()
        self.new = new
        self.modified = False
        self.accessed = False


class DatabaseSessionSerializer:
    def encode(self, session_data: dict[str, Any]) -> bytes:
        return session_json_serializer.dumps(dict(session_data)).encode("utf-8")

    def decode(self, payload: bytes) -> dict[str, Any]:
        decoded = session_json_serializer.loads(payload.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("Session payload must decode to an object")
        return decoded


class DatabaseSessionInterface(SessionInterface):
    serializer = DatabaseSessionSerializer()
    session_class = DatabaseSession

    @_session_store_locked
    def open_session(self, app: Flask, request) -> DatabaseSession:
        cookie_name = self.get_cookie_name(app)
        session_id = request.cookies.get(cookie_name)
        if not session_id:
            return self.session_class(sid=_new_session_id(), new=True)

        record = _session_record_for_sid(session_id)
        if record is None:
            return self.session_class(sid=_new_session_id(), new=True)

        now = _utcnow()
        if record.revoked_at is not None:
            return self.session_class(sid=_new_session_id(), new=True)
        if record.expires_at is None:
            self._handle_integrity_failure(record, reason="missing_expires_at")
            return self.session_class(sid=_new_session_id(), new=True)
        if _as_utc_datetime(record.expires_at) <= now:
            _end_session_record(record, ended_reason="expired", now=now)
            _commit_quietly()
            return self.session_class(sid=_new_session_id(), new=True)
        if not record.payload:
            _end_session_record(record, ended_reason="ended", now=now)
            _commit_quietly()
            return self.session_class(sid=_new_session_id(), new=True)

        try:
            payload = verify_session_payload(
                bytes(record.payload),
                binding_context=_payload_binding_context(record.session_lookup_hash),
            )
            session_data = self.serializer.decode(payload)
        except SessionPayloadIntegrityError as exc:
            self._handle_integrity_failure(record, reason=exc.reason)
            return self.session_class(sid=_new_session_id(), new=True)
        except Exception:
            self._handle_integrity_failure(record, reason="malformed_payload")
            return self.session_class(sid=_new_session_id(), new=True)

        record.last_activity_at = now
        return self.session_class(session_data, sid=session_id)

    @_session_store_locked
    def save_session(self, app: Flask, session_obj: DatabaseSession, response) -> None:
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        secure = self.get_cookie_secure(app)
        httponly = self.get_cookie_httponly(app)
        samesite = self.get_cookie_samesite(app)
        cookie_name = self.get_cookie_name(app)

        if not session_obj:
            if session_obj.modified:
                _end_session_id(session_obj.sid, ended_reason="ended")
                _commit_quietly()
                response.delete_cookie(
                    cookie_name,
                    domain=domain,
                    path=path,
                    secure=secure,
                    httponly=httponly,
                    samesite=samesite,
                )
            return

        session_obj.permanent = True
        now = _utcnow()
        expires_at = _session_expires_at(now)
        lookup_hash = session_lookup_hash(session_obj.sid)
        payload = self.serializer.encode(dict(session_obj))
        signed_payload = sign_session_payload(
            payload,
            binding_context=_payload_binding_context(lookup_hash),
        )
        user_id = _session_user_id(session_obj)
        record = _session_record_for_lookup_hash(lookup_hash)
        if record is None:
            record = ServerSideSession(
                component=_session_component(),
                session_lookup_hash=lookup_hash,
                created_at=now,
                last_activity_at=now,
                expires_at=expires_at,
            )
            db.session.add(record)

        record.payload = signed_payload
        record.payload_format = SESSION_PAYLOAD_FORMAT
        record.session_ref = _public_reference_from_lookup_hash(lookup_hash)
        record.user_id = user_id
        record.last_activity_at = now
        record.expires_at = expires_at
        record.revoked_at = None
        record.ended_at = None
        record.ended_reason = None
        record.ip_address = request.remote_addr or record.ip_address or ""
        record.user_agent = ((request.user_agent.string or "")[:256] or record.user_agent or "unknown")
        record.risk_fingerprint = str(session_obj.get(SESSION_RISK_FINGERPRINT_KEY) or "")
        _commit_quietly()

        response.set_cookie(
            cookie_name,
            session_obj.sid,
            expires=self.get_expiration_time(app, session_obj),
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            samesite=samesite,
        )
        response.vary.add("Cookie")

    def regenerate(self, session_obj: DatabaseSession) -> None:
        old_session_id = getattr(session_obj, "sid", "")
        if old_session_id:
            _end_session_id(old_session_id, ended_reason="rotated")
        session_obj.sid = _new_session_id()
        session_obj.modified = True

    def _handle_integrity_failure(self, record: ServerSideSession, *, reason: str) -> None:
        now = _utcnow()
        store_ref = active_hmac_hex(f"session-store:{record.session_lookup_hash}", length=16)
        _end_session_record(record, ended_reason="integrity_failure", now=now)
        current_app.logger.warning(
            "session_integrity_failure reason=%s store_ref=%s",
            reason,
            store_ref,
        )
        try:
            from app.security.audit import audit_event

            audit_event(
                "session_integrity",
                "failure",
                metadata={"reason": reason, "store_ref": store_ref},
                session_id=store_ref,
            )
        except Exception as exc:
            current_app.logger.warning(
                "session_integrity_audit_failed reason=%s error=%s",
                reason,
                type(exc).__name__,
            )
            _commit_quietly()


def install_database_sessions(app: Flask) -> None:
    app.session_interface = DatabaseSessionInterface()


def _new_session_id() -> str:
    return str(uuid.uuid4())


def _now() -> int:
    return int(time.time())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return _utcnow().isoformat()


def _as_utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def current_session_id() -> str | None:
    if not has_request_context():
        return None
    return getattr(session, "sid", None)


def session_lookup_hash(session_id: str) -> str:
    # This is a keyed lookup verifier, not password hashing.
    # lgtm[py/weak-sensitive-data-hashing]
    return hmac.new(
        _lookup_hmac_key(),
        str(session_id).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def public_session_reference(session_id: str | None) -> str:
    if not session_id:
        return ""
    return _public_reference_from_lookup_hash(session_lookup_hash(session_id))


def _public_reference_from_lookup_hash(lookup_hash: str) -> str:
    return active_hmac_hex(f"session-reference:{lookup_hash}", length=32)


def _candidate_public_references(lookup_hash: str) -> Iterator[str]:
    yield from candidate_hmac_hex(f"session-reference:{lookup_hash}", length=32)


def _lookup_hmac_key() -> bytes:
    key = current_app.config.get("SESSION_LOOKUP_HMAC_KEY")
    if isinstance(key, bytes):
        return key
    raise RuntimeError("SESSION_LOOKUP_HMAC_KEY must be configured as 32 bytes")


def _session_component() -> str:
    return str(current_app.config.get("APP_MODE") or "customer")


def _payload_binding_context(lookup_hash: str) -> str:
    return f"db-session:{_session_component()}:{lookup_hash}"


def _session_record_for_sid(session_id: str) -> ServerSideSession | None:
    return _session_record_for_lookup_hash(session_lookup_hash(session_id))


def _session_record_for_lookup_hash(lookup_hash: str) -> ServerSideSession | None:
    with db.session.no_autoflush:
        records = list(
            db.session.execute(
                db.select(ServerSideSession)
                .where(
                    ServerSideSession.component == _session_component(),
                    ServerSideSession.session_lookup_hash == lookup_hash,
                )
                .order_by(
                    ServerSideSession.revoked_at.is_not(None).desc(),
                    ServerSideSession.ended_at.is_not(None).desc(),
                    ServerSideSession.id.desc(),
                )
                .limit(2)
            ).scalars()
        )
    if len(records) > 1:
        store_ref = active_hmac_hex(f"session-store:{lookup_hash}", length=16)
        current_app.logger.warning(
            "duplicate_session_records_detected store_ref=%s",
            store_ref,
        )
    return records[0] if records else None


def _session_expires_at(now: datetime) -> datetime:
    return now + timedelta(seconds=int(current_app.config["SESSION_INACTIVITY_SECONDS"]))


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
    now = _now()
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["auth_context"] = auth_context
    session["login_at"] = login_time
    session[AUTH_CREATED_AT_KEY] = now
    session["last_activity_at"] = now
    if mfa_verified:
        session["mfa_verified_at"] = now
        session["fresh_mfa_verified_at"] = now
    rotate_session_id()
    refresh_session_risk_fingerprint()
    register_session_metadata(user_id=user_id, login_time=login_time)
    if mfa_verified:
        enforce_active_session_cap(user_id)
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


def authenticated_session_age_seconds() -> int | None:
    """Return a bounded authenticated-session age, or None for invalid state."""
    if not session.get("user_id") or not current_session_id():
        return None
    created_at = session.get(AUTH_CREATED_AT_KEY)
    if isinstance(created_at, bool):
        return None
    try:
        age = _now() - int(created_at)
    except (TypeError, ValueError):
        return None
    if age < 0 or age > int(current_app.config["SESSION_ABSOLUTE_LIFETIME_SECONDS"]):
        return None
    return age


def authenticated_session_risk_is_stable() -> bool:
    """Fail closed unless the current authenticated session risk is stable."""
    if not session.get("user_id") or not current_session_id():
        return False
    if session.get(SESSION_RISK_REAUTH_REQUIRED_KEY):
        return False
    return _session_risk_severity(_session_risk_context_changes()) == "stable"


def rotate_authenticated_session_after_mfa(user_id: int) -> str:
    login_time = session.get("login_at") or utc_now_iso()
    mark_fresh_mfa()
    rotate_session_id()
    refresh_session_risk_fingerprint()
    register_session_metadata(user_id=user_id, login_time=str(login_time))
    return current_session_id() or ""


def refresh_session_risk_fingerprint() -> None:
    if not current_session_id():
        return
    fingerprint = current_session_risk_fingerprint()
    session[SESSION_RISK_FINGERPRINT_KEY] = fingerprint
    session[SESSION_RISK_CONTEXT_KEY] = _current_session_risk_context()
    session.pop(SESSION_RISK_REAUTH_REQUIRED_KEY, None)
    session.modified = True
    record = _current_session_record()
    if record is not None:
        record.risk_fingerprint = fingerprint


def current_session_risk_fingerprint() -> str:
    return active_hmac_hex(_current_session_risk_message(), length=32)


def _current_session_risk_message() -> str:
    parts = [
        _normalized_ip_context(request.remote_addr or ""),
        _user_agent_fingerprint(request.user_agent.string or "unknown"),
        str(session.get("auth_context") or ""),
    ]
    return "|".join(parts)


def require_stable_session_for_sensitive_action(action: str) -> None:
    if not current_session_id():
        return
    if session.get(SESSION_RISK_REAUTH_REQUIRED_KEY):
        _raise_session_risk_reauthentication(action, audit=False)

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

    _mark_session_risk_reauthentication_required()
    _raise_session_risk_reauthentication(action, audit=True)


def _raise_session_risk_reauthentication(action: str, *, audit: bool) -> None:
    from app.auth.services import AuthError

    if audit:
        from app.security.audit import audit_event

        audit_event(
            "session_risk",
            "step_up_required",
            user_id=_session_user_id(session),
            metadata={"action": action},
        )
    raise AuthError("Session verification required. Please sign in again.", 401)


def _mark_session_risk_reauthentication_required() -> None:
    session[SESSION_RISK_REAUTH_REQUIRED_KEY] = True
    session.modified = True


def _current_session_risk_context() -> dict[str, Any]:
    ip_network = _normalized_ip_context(request.remote_addr or "")
    user_agent = _normalized_user_agent(request.user_agent.string or "unknown")
    user_agent_family = _user_agent_family(user_agent)
    return {
        "version": SESSION_RISK_CONTEXT_VERSION,
        "ip_network_hash": _risk_context_hash("ip_network", ip_network),
        "user_agent_family_hash": _risk_context_hash(
            "user_agent_family",
            user_agent_family,
        ),
        "user_agent_hash": _risk_context_hash("user_agent", user_agent),
        "last_checked_at": _now(),
    }


def _risk_context_hash(label: str, value: str) -> str:
    return active_hmac_hex(
        f"session-risk-context:{label}:{value}",
        length=32,
    )


def _risk_context_hash_matches(stored: Any, label: str, value: str) -> bool:
    if not stored:
        return False
    return matches_hmac(
        str(stored),
        f"session-risk-context:{label}:{value}",
        length=32,
    )


def _normalized_user_agent(value: str) -> str:
    return " ".join((value or "unknown").split()).casefold()[:256]


def _user_agent_family(value: str) -> str:
    normalized = _normalized_user_agent(value)
    known_families = (
        ("edge", r"\bedg(?:e|a|ios)?/"),
        ("opera", r"\b(?:opr|opera)/"),
        ("chrome", r"\b(?:chrome|crios)/"),
        ("firefox", r"\b(?:firefox|fxios)/"),
        ("safari", r"\bsafari/"),
    )
    for family, pattern in known_families:
        if re.search(pattern, normalized):
            return family
    product = re.search(r"\b([a-z][a-z0-9._-]{1,31})/", normalized)
    if product:
        return product.group(1)
    token = re.search(r"\b([a-z][a-z0-9._-]{1,31})\b", normalized)
    return token.group(1) if token else "unknown"


def _session_risk_context_changes() -> set[str]:
    stored = session.get(SESSION_RISK_CONTEXT_KEY)
    if not isinstance(stored, dict):
        return {"session_context"}
    if stored.get("version") != SESSION_RISK_CONTEXT_VERSION:
        return {"session_context"}

    ip_network = _normalized_ip_context(request.remote_addr or "")
    user_agent = _normalized_user_agent(request.user_agent.string or "unknown")
    user_agent_family = _user_agent_family(user_agent)
    changes: set[str] = set()
    if not _risk_context_hash_matches(
        stored.get("ip_network_hash"),
        "ip_network",
        ip_network,
    ):
        changes.add("ip_network")
    if not _risk_context_hash_matches(
        stored.get("user_agent_family_hash"),
        "user_agent_family",
        user_agent_family,
    ):
        changes.add("user_agent_family")
    if not _risk_context_hash_matches(
        stored.get("user_agent_hash"),
        "user_agent",
        user_agent,
    ):
        changes.add("user_agent")
    return changes


def _session_risk_severity(changes: set[str]) -> str:
    if not changes:
        return "stable"
    if current_app.config.get("APP_MODE") == "admin":
        return "high"
    if changes == {"user_agent"}:
        return "low"
    if {"ip_network", "user_agent_family"} <= changes:
        return "high"
    return "medium"


def _store_current_session_risk_context(*, clear_reauth: bool) -> None:
    session[SESSION_RISK_FINGERPRINT_KEY] = current_session_risk_fingerprint()
    session[SESSION_RISK_CONTEXT_KEY] = _current_session_risk_context()
    if clear_reauth:
        session.pop(SESSION_RISK_REAUTH_REQUIRED_KEY, None)
    session.modified = True


def _touch_session_risk_context() -> None:
    stored = session.get(SESSION_RISK_CONTEXT_KEY)
    if (
        not isinstance(stored, dict)
        or stored.get("version") != SESSION_RISK_CONTEXT_VERSION
    ):
        _store_current_session_risk_context(clear_reauth=False)
        return
    updated = dict(stored)
    updated["last_checked_at"] = _now()
    session[SESSION_RISK_CONTEXT_KEY] = updated
    session.modified = True


def enforce_authenticated_session_context() -> Any:
    if not session.get("user_id") or not current_session_id():
        return None

    changes = _session_risk_context_changes()
    severity = _session_risk_severity(changes)
    if severity == "stable":
        if not isinstance(session.get(SESSION_RISK_CONTEXT_KEY), dict):
            _store_current_session_risk_context(clear_reauth=False)
        else:
            _touch_session_risk_context()
        return None

    app_mode = str(current_app.config.get("APP_MODE") or "customer")
    metadata = {
        "app_mode": app_mode,
        "severity": severity,
        "signals": sorted(changes),
    }
    from app.security.audit import audit_event

    if severity == "low":
        audit_event(
            "session_risk",
            "changed",
            user_id=_session_user_id(session),
            metadata=metadata,
        )
        _store_current_session_risk_context(clear_reauth=True)
        return None

    if severity == "medium":
        if not session.get(SESSION_RISK_REAUTH_REQUIRED_KEY):
            audit_event(
                "session_risk",
                "reauth_required",
                user_id=_session_user_id(session),
                metadata=metadata,
            )
        _mark_session_risk_reauthentication_required()
        _touch_session_risk_context()
        return None

    audit_event(
        "session_risk",
        "revoked",
        user_id=_session_user_id(session),
        metadata=metadata,
    )
    revoke_current_session(ended_reason="risk_change")
    return _session_expired_response("Session verification required")


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
    record = _current_session_record()
    now = _utcnow()
    if record is None:
        record = ServerSideSession(
            component=_session_component(),
            session_lookup_hash=session_lookup_hash(session_id),
            expires_at=_session_expires_at(now),
        )
        db.session.add(record)
    record.user_id = user_id
    record.session_ref = public_session_reference(session_id)
    record.ip_address = request.remote_addr or record.ip_address or ""
    record.user_agent = ((request.user_agent.string or "")[:256] or record.user_agent or "unknown")
    try:
        record.created_at = _as_utc_datetime(datetime.fromisoformat(str(login_time)))
    except ValueError:
        record.created_at = now
    record.last_activity_at = now
    record.expires_at = _session_expires_at(now)
    record.risk_fingerprint = str(session.get(SESSION_RISK_FINGERPRINT_KEY) or "")


def update_session_activity() -> None:
    session_id = current_session_id()
    user_id = session.get("user_id")
    if not session_id or not user_id:
        return
    record = _current_session_record()
    if record is None:
        return
    now = _utcnow()
    record.last_activity_at = now
    record.expires_at = _session_expires_at(now)
    record.user_id = int(user_id)
    record.session_ref = public_session_reference(session_id)
    record.risk_fingerprint = str(session.get(SESSION_RISK_FINGERPRINT_KEY) or "")


def _current_session_record() -> ServerSideSession | None:
    session_id = current_session_id()
    if not session_id:
        return None
    return _session_record_for_sid(session_id)


def _active_session_records(
    user_id: int,
    *,
    component: str | None = None,
) -> list[ServerSideSession]:
    now = _utcnow()
    session_component = str(component or _session_component())
    records = list(
        db.session.execute(
            db.select(ServerSideSession)
            .where(
                ServerSideSession.component == session_component,
                ServerSideSession.user_id == user_id,
                ServerSideSession.revoked_at.is_(None),
                ServerSideSession.ended_at.is_(None),
                ServerSideSession.expires_at > now,
                ServerSideSession.payload.is_not(None),
            )
            .order_by(ServerSideSession.created_at.desc(), ServerSideSession.id.desc())
        ).scalars()
    )
    _expire_stale_sessions(user_id=user_id, now=now)
    return records


def list_active_sessions(user_id: int) -> list[dict[str, Any]]:
    current_lookup_hash = session_lookup_hash(current_session_id()) if current_session_id() else ""
    sessions: list[dict[str, Any]] = []
    for record in _active_session_records(user_id):
        session_ref = _public_reference_from_lookup_hash(record.session_lookup_hash)
        public_metadata = {
            "session_ref": session_ref,
            "current": record.session_lookup_hash == current_lookup_hash,
            "ip_address": _display_ip_address(record.ip_address),
            "user_agent": _summarize_user_agent(record.user_agent),
            "login_time": _utc_iso(record.created_at),
            "last_activity": _utc_iso(record.last_activity_at),
            "login_time_display": _format_session_time(_utc_iso(record.created_at)),
            "last_activity_display": _format_session_time(_utc_iso(record.last_activity_at)),
        }
        sessions.append(public_metadata)
    return sessions


def list_past_sessions(user_id: int, limit: int | None = None) -> list[dict[str, Any]]:
    count = _session_history_limit(limit)
    if count <= 0:
        return []
    rows = list(
        db.session.execute(
            db.select(ServerSideSession)
            .where(
                ServerSideSession.component == _session_component(),
                ServerSideSession.user_id == user_id,
                ServerSideSession.ended_at.is_not(None),
            )
            .order_by(ServerSideSession.ended_at.desc(), ServerSideSession.id.desc())
            .limit(count)
        ).scalars()
    )
    sessions: list[dict[str, Any]] = []
    for record in rows:
        ended_reason = _normalize_session_end_reason(str(record.ended_reason or ""))
        login_time = _utc_iso(record.created_at)
        last_activity = _utc_iso(record.last_activity_at)
        ended_at = _utc_iso(record.ended_at)
        public_metadata = {
            "session_ref": record.session_ref or _public_reference_from_lookup_hash(record.session_lookup_hash),
            "ip_address": _display_ip_address(record.ip_address),
            "user_agent": _summarize_user_agent(record.user_agent),
            "login_time": login_time,
            "last_activity": last_activity,
            "ended_at": ended_at,
            "ended_reason": ended_reason,
            "login_time_display": _format_session_time(login_time),
            "last_activity_display": _format_session_time(last_activity),
            "ended_at_display": _format_session_time(ended_at),
            "ended_reason_display": SESSION_END_REASON_LABELS[ended_reason],
        }
        sessions.append(public_metadata)
    return sessions


def resolve_session_reference_for_user(user_id: int, session_reference: str) -> str | None:
    current_sid = current_session_id()
    current_lookup_hash = session_lookup_hash(current_sid) if current_sid else ""
    for record in _active_session_records(user_id):
        if any(hmac.compare_digest(str(session_reference), candidate) for candidate in _candidate_public_references(record.session_lookup_hash)):
            if record.session_lookup_hash == current_lookup_hash and current_sid:
                return current_sid
            return f"lookup:{record.session_lookup_hash}"
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
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return "Unknown"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    local_time = parsed.astimezone()
    return local_time.strftime("%d %b %Y %H:%M")


def _utc_iso(value: datetime | None) -> str:
    if value is None:
        return ""
    return _as_utc_datetime(value).isoformat()


def _session_user_id(session_obj: DatabaseSession) -> int | None:
    user_id = session_obj.get("user_id") or session_obj.get("pending_mfa_user_id")
    if not user_id:
        return None
    try:
        return int(user_id)
    except (TypeError, ValueError):
        return None


def _session_row_from_identifier(session_identifier: str) -> ServerSideSession | None:
    if str(session_identifier).startswith("lookup:"):
        lookup_hash = str(session_identifier).removeprefix("lookup:")
    else:
        lookup_hash = session_lookup_hash(session_identifier)
    return _session_record_for_lookup_hash(lookup_hash)


def revoke_session(session_id: str, user_id: int | None = None, *, ended_reason: str = "revoked") -> None:
    record = _session_row_from_identifier(session_id)
    if record is None:
        return
    if user_id is not None and record.user_id not in {None, int(user_id)}:
        return
    _end_session_record(record, ended_reason=ended_reason, now=_utcnow())


def revoke_current_session(*, ended_reason: str = "revoked") -> None:
    session_id = current_session_id()
    user_id = session.get("user_id") or session.get("pending_mfa_user_id")
    if session_id:
        revoke_session(session_id, int(user_id) if user_id else None, ended_reason=ended_reason)
    session.clear()


def revoke_other_sessions(user_id: int, *, ended_reason: str = "revoked") -> int:
    current_lookup_hash = session_lookup_hash(current_session_id()) if current_session_id() else ""
    revoked = 0
    for record in _active_session_records(user_id):
        if record.session_lookup_hash == current_lookup_hash:
            continue
        _end_session_record(record, ended_reason=ended_reason, now=_utcnow())
        revoked += 1
    return revoked


def revoke_all_sessions(
    user_id: int,
    *,
    ended_reason: str = "revoked",
    component: str | None = None,
) -> int:
    revoked = 0
    for record in _active_session_records(user_id, component=component):
        _end_session_record(record, ended_reason=ended_reason, now=_utcnow())
        revoked += 1
    return revoked


def enforce_active_session_cap(user_id: int) -> int:
    max_active_sessions = _configured_active_session_cap()
    current_lookup_hash = session_lookup_hash(current_session_id()) if current_session_id() else ""
    kept = 0
    revoked = 0
    now = _utcnow()
    records = _active_session_records(user_id)
    current_record = _current_session_record()
    if (
        current_record is not None
        and current_record.user_id == int(user_id)
        and current_record.revoked_at is None
        and current_record.ended_at is None
        and current_record not in records
    ):
        records.append(current_record)
    records.sort(
        key=lambda record: (
            record.session_lookup_hash != current_lookup_hash,
            _as_utc_datetime(record.created_at),
            int(record.id or 0),
        ),
        reverse=False,
    )
    for record in records:
        if kept < max_active_sessions:
            kept += 1
            continue
        _end_session_record(record, ended_reason="session_cap", now=now)
        revoked += 1
    if revoked:
        db.session.commit()
    return revoked


def _configured_active_session_cap() -> int:
    try:
        configured = int(current_app.config.get("MAX_ACTIVE_SESSIONS", 1))
    except (TypeError, ValueError):
        return 1
    return 1 if configured != 1 else configured


def _end_session_id(session_id: str, *, ended_reason: str) -> None:
    record = _session_record_for_sid(session_id)
    if record is not None:
        _end_session_record(record, ended_reason=ended_reason, now=_utcnow())


def _end_session_record(record: ServerSideSession, *, ended_reason: str, now: datetime) -> None:
    if record.ended_at is not None:
        return
    reason = _normalize_session_end_reason(ended_reason)
    record.session_ref = record.session_ref or _public_reference_from_lookup_hash(record.session_lookup_hash)
    record.payload = None
    record.revoked_at = now
    record.ended_at = now
    record.ended_reason = reason


def _expire_stale_sessions(*, user_id: int, now: datetime) -> None:
    stale_records = list(
        db.session.execute(
            db.select(ServerSideSession).where(
                ServerSideSession.component == _session_component(),
                ServerSideSession.user_id == user_id,
                ServerSideSession.revoked_at.is_(None),
                ServerSideSession.ended_at.is_(None),
                ServerSideSession.expires_at <= now,
            )
        ).scalars()
    )
    for record in stale_records:
        _end_session_record(record, ended_reason="expired", now=now)


def _commit_quietly() -> None:
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
    except Exception:
        db.session.rollback()
        raise


def _wants_session_json_response() -> bool:
    if current_app.config.get("APP_MODE") == "admin":
        return True
    if request.path.startswith(("/auth/", "/admin/")):
        return True
    best = request.accept_mimetypes.best_match([JSON_MIME_TYPE, "text/html"])
    return best == JSON_MIME_TYPE and (
        request.accept_mimetypes[JSON_MIME_TYPE] >= request.accept_mimetypes["text/html"]
    )


def _session_expired_response(message: str = "Session expired"):
    if _wants_session_json_response():
        return jsonify({"error": message}), 401
    return redirect(url_for(_login_endpoint(), session_expired=1))


def _session_revoked_response():
    if _wants_session_json_response():
        return jsonify({"error": "Session revoked"}), 401
    return redirect(url_for(_login_endpoint(), session_expired=1))


def _login_endpoint() -> str:
    """Return the login endpoint registered by the isolated runtime."""
    if current_app.config.get("APP_MODE") == "admin":
        return ADMIN_LOGIN_ENDPOINT
    return WEB_LOGIN_ENDPOINT


def register_session_hooks(app: Flask) -> None:
    app.before_request(_enforce_session_activity)


def _enforce_session_activity():
    revoked_response = _revoked_session_response_if_required()
    if revoked_response is not None:
        return revoked_response

    principal_id = session.get("user_id") or session.get("pending_mfa_user_id")
    if not principal_id:
        return None

    now = _now()
    pending_response = _pending_mfa_expiry_response(now)
    if pending_response is not None:
        return pending_response

    lifetime_response = _absolute_lifetime_expiry_response(now)
    if lifetime_response is not None:
        return lifetime_response

    last_activity = int(session.get("last_activity_at") or now)
    if now - last_activity > current_app.config["SESSION_INACTIVITY_SECONDS"]:
        revoke_current_session(ended_reason="expired")
        return _session_expired_response()

    context_response = enforce_authenticated_session_context()
    if context_response is not None:
        return context_response

    session["last_activity_at"] = now
    session.modified = True
    update_session_activity()
    return None


def _revoked_session_response_if_required():
    session_id = current_session_id()
    if not session_id or not session:
        return None
    record = _session_record_for_sid(session_id)
    if record is None or record.revoked_at is None:
        return None
    session.clear()
    public_endpoints = {
        _login_endpoint(),
        "admin.login",
        "main.index",
        WEB_LOGIN_ENDPOINT,
        "web.login_submit",
        "web.register_form",
        "web.register_submit",
    }
    if request.endpoint in public_endpoints:
        return None
    return _session_revoked_response()


def _pending_mfa_expiry_response(now: int):
    pending_mfa_user_id = session.get("pending_mfa_user_id")
    if not pending_mfa_user_id:
        return None
    authenticated_at = int(session.get("password_authenticated_at") or 0)
    max_age = current_app.config["PENDING_MFA_MAX_AGE_SECONDS"]
    if authenticated_at and now - authenticated_at <= max_age:
        return None

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
    return redirect(url_for(_login_endpoint()))


def _absolute_lifetime_expiry_response(now: int):
    authenticated_user_id = session.get("user_id")
    if not authenticated_user_id:
        return None
    try:
        absolute_lifetime = int(
            current_app.config["SESSION_ABSOLUTE_LIFETIME_SECONDS"]
        )
    except (KeyError, TypeError, ValueError):
        current_app.logger.error("SESSION_ABSOLUTE_LIFETIME_SECONDS is invalid")
        revoke_current_session(ended_reason="absolute_lifetime")
        return _session_expired_response()

    raw_auth_created_at = session.get(AUTH_CREATED_AT_KEY)
    if raw_auth_created_at is None:
        session[AUTH_CREATED_AT_KEY] = now
        session.modified = True
        return None
    try:
        auth_created_at = int(raw_auth_created_at)
    except (TypeError, ValueError):
        revoke_current_session(ended_reason="absolute_lifetime")
        return _session_expired_response()
    if auth_created_at > 0 and now - auth_created_at <= absolute_lifetime:
        return None

    session_id = current_session_id()
    from app.security.audit import audit_event

    audit_event(
        "session_absolute_lifetime",
        "expired",
        user_id=int(authenticated_user_id),
        session_id=session_id,
        metadata={
            "app_mode": current_app.config.get("APP_MODE", "customer"),
            "age_seconds": max(0, now - auth_created_at),
            "lifetime_seconds": absolute_lifetime,
        },
    )
    revoke_current_session(ended_reason="absolute_lifetime")
    return _session_expired_response()
