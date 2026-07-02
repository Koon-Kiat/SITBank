from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flask import current_app

from app.extensions import db
from app.models import PasswordHistory, User
from app.security.passwords import hash_password, verify_password


DEFAULT_PASSWORD_HISTORY_RETENTION_COUNT = 3
PASSWORD_HISTORY_DISABLED_MESSAGE = "PASSWORD_HISTORY_ENABLED must be true"
PASSWORD_HISTORY_RETENTION_MESSAGE = "PASSWORD_HISTORY_RETENTION_COUNT must be at least 3"


class PasswordReuseError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def validate_password_history_config(config: dict[str, Any]) -> None:
    enabled = bool(config.get("PASSWORD_HISTORY_ENABLED", True))
    if not enabled:
        raise RuntimeError(PASSWORD_HISTORY_DISABLED_MESSAGE)
    try:
        retention_count = int(
            config.get(
                "PASSWORD_HISTORY_RETENTION_COUNT",
                DEFAULT_PASSWORD_HISTORY_RETENTION_COUNT,
            )
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeError("PASSWORD_HISTORY_RETENTION_COUNT must be an integer") from exc
    if retention_count < DEFAULT_PASSWORD_HISTORY_RETENTION_COUNT:
        raise RuntimeError(PASSWORD_HISTORY_RETENTION_MESSAGE)


def assert_password_not_reused(user: User, candidate_password: str) -> None:
    if verify_password(candidate_password, user.password_hash):
        raise PasswordReuseError("current_password")

    for entry in _history_entries(user, limit=_retention_count()):
        if verify_password(candidate_password, entry.password_hash):
            raise PasswordReuseError("password_history")


def replace_user_password(
    user: User,
    new_password: str,
    *,
    changed_at: datetime | None = None,
    clear_forced_change: bool = True,
) -> None:
    now = changed_at or datetime.now(timezone.utc)
    if user.id is not None and user.password_hash:
        db.session.add(
            PasswordHistory(
                user_id=int(user.id),
                password_hash=user.password_hash,
                created_at=now,
            )
        )
    user.password_hash = hash_password(new_password)
    user.password_changed_at = now
    if clear_forced_change:
        user.force_password_change = False
        user.force_password_change_reason = None
        user.force_password_change_at = None
    _prune_password_history(user, retention_count=_retention_count())


def mark_password_changed(user: User, *, changed_at: datetime | None = None) -> None:
    user.password_changed_at = changed_at or datetime.now(timezone.utc)
    user.force_password_change = False
    user.force_password_change_reason = None
    user.force_password_change_at = None


def require_forced_password_change(user: User, reason: str) -> None:
    normalized_reason = str(reason or "security_event").strip().casefold()[:80]
    user.force_password_change = True
    user.force_password_change_reason = normalized_reason or "security_event"
    user.force_password_change_at = datetime.now(timezone.utc)


def _history_entries(user: User, *, limit: int) -> list[PasswordHistory]:
    if user.id is None:
        return []
    return list(
        db.session.execute(
            db.select(PasswordHistory)
            .where(PasswordHistory.user_id == int(user.id))
            .order_by(PasswordHistory.created_at.desc(), PasswordHistory.id.desc())
            .limit(limit)
        ).scalars()
    )


def _prune_password_history(user: User, *, retention_count: int) -> None:
    if user.id is None:
        return
    rows = list(
        db.session.execute(
            db.select(PasswordHistory)
            .where(PasswordHistory.user_id == int(user.id))
            .order_by(PasswordHistory.created_at.desc(), PasswordHistory.id.desc())
        ).scalars()
    )
    for stale_entry in rows[retention_count:]:
        db.session.delete(stale_entry)


def _retention_count() -> int:
    try:
        configured = int(
            current_app.config.get(
                "PASSWORD_HISTORY_RETENTION_COUNT",
                DEFAULT_PASSWORD_HISTORY_RETENTION_COUNT,
            )
        )
    except (TypeError, ValueError):
        return DEFAULT_PASSWORD_HISTORY_RETENTION_COUNT
    return max(DEFAULT_PASSWORD_HISTORY_RETENTION_COUNT, configured)
