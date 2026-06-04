from __future__ import annotations

import hashlib

from flask import current_app, g, request, session
from flask_limiter.util import get_remote_address


class AuthBackoffRequired(RuntimeError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("Authentication backoff is active")
        self.retry_after = retry_after


LOGIN_BACKOFF_START_ATTEMPTS = 3


def _redis():
    return current_app.extensions["redis"]


def _safe_identifier(value: str) -> str:
    digest = hashlib.sha256(value.casefold().encode("utf-8")).hexdigest()
    return digest[:32]


def request_principal() -> str:
    payload = request.get_json(silent=True) or request.form or {}
    value = (
        payload.get("username")
        or payload.get("email")
        or payload.get("identifier")
        or session.get("pending_mfa_user_id")
        or getattr(getattr(g, "current_user", None), "id", None)
        or get_remote_address()
    )
    principal = "principal:" + _safe_identifier(str(value))
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


def _failure_key(scope: str, principal: str) -> str:
    return f"ospbank:authfail:{scope}:{_safe_identifier(principal)}"


def _backoff_start_attempts(scope: str) -> int:
    if scope == "login":
        return LOGIN_BACKOFF_START_ATTEMPTS
    return 1


def apply_exponential_backoff(scope: str, principal: str) -> None:
    attempts = int(_redis().get(_failure_key(scope, principal)) or 0)
    start_attempts = _backoff_start_attempts(scope)
    if attempts < start_attempts:
        return
    retry_after = min(2 ** (attempts - start_attempts), 16)
    raise AuthBackoffRequired(retry_after)


def record_failure(scope: str, principal: str) -> None:
    key = _failure_key(scope, principal)
    attempts = _redis().incr(key)
    _redis().expire(key, 5 * 60)
    if attempts > 10:
        _redis().expire(key, 15 * 60)
    if attempts in {2, 3, 5, 10} or attempts > 10:
        from app.security.audit import audit_event

        audit_event(
            "auth_backoff",
            "applied",
            metadata={"scope": scope, "attempts": int(attempts)},
        )


def clear_failures(scope: str, principal: str) -> None:
    _redis().delete(_failure_key(scope, principal))
