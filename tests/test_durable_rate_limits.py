from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import AuthAttemptCounter
from app.security import rate_limits
from app.security.rate_limits import (
    DurableRateLimitExceeded,
    _as_utc,
    _ip_hash_from_principal,
    consume_durable_rate_limit,
)


def test_durable_rate_limit_validates_bounds_and_blocks_at_limit(app):
    with app.test_request_context("/auth/register", environ_overrides={"REMOTE_ADDR": "198.51.100.5"}):
        with pytest.raises(ValueError, match="bounds must be positive"):
            consume_durable_rate_limit("test", "198.51.100.5:user", limit=0, window_seconds=60)

        assert (
            consume_durable_rate_limit(
                "test",
                "198.51.100.5:user",
                limit=1,
                window_seconds=60,
            )
            == 1
        )
        with pytest.raises(DurableRateLimitExceeded) as exc_info:
            consume_durable_rate_limit(
                "test",
                "198.51.100.5:user",
                limit=1,
                window_seconds=60,
            )
        assert exc_info.value.retry_after >= 1


def test_durable_rate_limit_replaces_expired_counter(app):
    with app.app_context():
        assert consume_durable_rate_limit("expired", "principal", limit=2, window_seconds=60) == 1
        counter = db.session.execute(
            db.select(AuthAttemptCounter).where(AuthAttemptCounter.scope == "expired")
        ).scalar_one()
        counter.window_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()

        assert consume_durable_rate_limit("expired", "principal", limit=2, window_seconds=60) == 1
        assert db.session.query(AuthAttemptCounter).filter_by(scope="expired").count() == 1


def test_rate_limit_helpers_handle_empty_principal_and_timezone_values():
    naive = datetime(2026, 1, 1)
    aware = datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=8)))

    assert _ip_hash_from_principal("") is None
    assert _as_utc(naive).tzinfo == timezone.utc
    assert _as_utc(aware).utcoffset() == timedelta(0)


def test_durable_counter_creation_race_reloads_winning_row(app, monkeypatch):
    existing = AuthAttemptCounter(
        scope="race",
        principal_hash="a" * 64,
        failure_count=1,
        window_started_at=datetime.now(timezone.utc),
        window_expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
    )
    loaded = iter([None, existing])

    class NestedTransaction:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(
        rate_limits,
        "_load_counter",
        lambda *_args, **_kwargs: next(loaded),
    )
    monkeypatch.setattr(rate_limits, "_uses_postgresql_row_locks", lambda: True)
    monkeypatch.setattr(
        rate_limits.db.session,
        "begin_nested",
        lambda: NestedTransaction(),
    )
    monkeypatch.setattr(rate_limits.db.session, "add", lambda _counter: None)
    monkeypatch.setattr(
        rate_limits.db.session,
        "flush",
        lambda: (_ for _ in ()).throw(
            IntegrityError("insert", {}, RuntimeError("duplicate"))
        ),
    )

    with app.app_context():
        counter = rate_limits._load_or_create_counter(
            "race",
            "principal",
            now=datetime.now(timezone.utc),
            window_seconds=60,
        )

    assert counter is existing
