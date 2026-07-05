from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flask import current_app, g, request, session
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import AuthAttemptCounter
from app.security.session_hmac import active_hmac_hex


class AuthBackoffRequired(RuntimeError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("Authentication backoff is active")
        self.retry_after = retry_after


class DurableRateLimitExceeded(RuntimeError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("Durable request limit is active")
        self.retry_after = retry_after


LOGIN_BACKOFF_START_ATTEMPTS = 3


def _safe_identifier(value: str) -> str:
    return active_hmac_hex(
        f"rate-limit-identifier:{value.casefold()}",
        length=32,
    )


def request_principal() -> str:
    payload = request.get_json(silent=True) or request.form or {}
    remote_addr = get_remote_address() or "unknown"
    value = (
        payload.get("username")
        or payload.get("email")
        or payload.get("workplace_email")
        or payload.get("personal_email")
        or payload.get("identifier")
        or session.get("pending_mfa_user_id")
        or getattr(getattr(g, "current_user", None), "id", None)
        or remote_addr
    )
    principal = "principal:" + _safe_identifier(f"{remote_addr}:{str(value).strip().casefold()}")
    # Flask-Limiter consumes this key server-side; it is not an HTTP response.
    return principal  # nosemgrep


def mfa_principal() -> str:
    value = (
        session.get("pending_mfa_user_id")
        or session.get("user_id")
        or getattr(getattr(g, "current_user", None), "id", None)
        or get_remote_address()
    )
    principal = "mfa:" + _safe_identifier(str(value))
    return principal


def _backoff_start_attempts(scope: str) -> int:
    if scope in {"login", "admin_login"}:
        return LOGIN_BACKOFF_START_ATTEMPTS
    return 1


def apply_exponential_backoff(scope: str, principal: str) -> None:
    counter = _load_counter(scope, principal)
    attempts = int(counter.failure_count if counter is not None else 0)
    start_attempts = _backoff_start_attempts(scope)
    if attempts < start_attempts:
        return
    retry_after = min(2 ** (attempts - start_attempts), 16)
    raise AuthBackoffRequired(retry_after)


def record_failure(
    scope: str,
    principal: str,
    *,
    window_seconds: int | None = None,
) -> int:
    now = _utcnow()
    counter = _load_or_create_counter(
        scope,
        principal,
        now=now,
        window_seconds=window_seconds if window_seconds is not None else 5 * 60,
    )

    counter.failure_count = int(counter.failure_count or 0) + 1
    counter.last_failed_at = now
    counter.updated_at = now
    counter.window_expires_at = now + timedelta(
        seconds=(
            window_seconds
            if window_seconds is not None
            else (15 * 60 if counter.failure_count > 10 else 5 * 60)
        )
    )
    attempts = int(counter.failure_count)
    db.session.commit()
    if attempts in {2, 3, 5, 10} or attempts > 10:
        from app.security.audit import audit_event

        audit_event(
            "auth_backoff",
            "applied",
            metadata={"scope": scope, "attempts": int(attempts)},
        )
    return int(attempts)


def enforce_durable_failure_limit(
    scope: str,
    principal: str,
    *,
    limit: int,
) -> None:
    """Block only after the recorded failure count exceeds the threshold."""
    if limit < 1:
        raise ValueError("Durable failure limit must be positive")
    counter = _load_counter(scope, principal)
    if counter is None or int(counter.failure_count or 0) <= limit:
        return
    retry_after = max(
        1,
        int((_as_utc(counter.window_expires_at) - _utcnow()).total_seconds()),
    )
    raise DurableRateLimitExceeded(retry_after)


def clear_failures(scope: str, principal: str) -> None:
    counter = _load_counter(scope, principal, lock=True)
    if counter is not None:
        db.session.delete(counter)
        db.session.commit()


def consume_durable_rate_limit(
    scope: str,
    principal: str,
    *,
    limit: int,
    window_seconds: int,
) -> int:
    if limit < 1 or window_seconds < 1:
        raise ValueError("Durable rate-limit bounds must be positive")
    now = _utcnow()
    counter = _load_or_create_counter(
        scope,
        principal,
        now=now,
        window_seconds=window_seconds,
    )
    if int(counter.failure_count or 0) >= limit:
        retry_after = max(1, int((_as_utc(counter.window_expires_at) - now).total_seconds()))
        db.session.rollback()
        raise DurableRateLimitExceeded(retry_after)
    counter.failure_count = int(counter.failure_count or 0) + 1
    counter.updated_at = now
    db.session.commit()
    return int(counter.failure_count)


def _load_or_create_counter(
    scope: str,
    principal: str,
    *,
    now: datetime,
    window_seconds: int,
) -> AuthAttemptCounter:
    counter = _load_counter(scope, principal, lock=True)
    if counter is not None:
        return counter

    counter = AuthAttemptCounter(
        scope=scope,
        principal_hash=_counter_hash(scope, principal),
        ip_hash=_ip_hash_from_principal(principal),
        failure_count=0,
        window_started_at=now,
        window_expires_at=now + timedelta(seconds=window_seconds),
        created_at=now,
        updated_at=now,
    )
    if not _uses_postgresql_row_locks():
        db.session.add(counter)
    else:
        try:
            with db.session.begin_nested():
                db.session.add(counter)
                db.session.flush()
        except IntegrityError:
            # Another worker created the same durable counter after our initial
            # lookup. Reload it under the normal row lock so the attempt is still
            # counted instead of failing open or returning an untracked 500.
            counter = _load_counter(scope, principal, lock=True)
            if counter is None:
                raise
    return counter


def _uses_postgresql_row_locks() -> bool:
    return db.engine.dialect.name == "postgresql"


def _load_counter(scope: str, principal: str, *, lock: bool = False) -> AuthAttemptCounter | None:
    now = _utcnow()
    statement = db.select(AuthAttemptCounter).where(
        AuthAttemptCounter.scope == scope,
        AuthAttemptCounter.principal_hash == _counter_hash(scope, principal),
    )
    if lock and _uses_postgresql_row_locks():
        statement = statement.with_for_update()
    counter = db.session.execute(statement).scalar_one_or_none()
    if counter is None:
        return None
    if _as_utc(counter.window_expires_at) <= now:
        db.session.delete(counter)
        db.session.flush()
        return None
    return counter


def _counter_hash(scope: str, principal: str) -> str:
    return active_hmac_hex(f"auth-counter:{scope}:{principal}", length=64)


def _ip_hash_from_principal(principal: str) -> str | None:
    ip_text = str(principal).split(":", 1)[0].strip()
    if not ip_text:
        return None
    return active_hmac_hex(f"auth-counter-ip:{ip_text}", length=64)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
