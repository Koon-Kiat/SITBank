from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.security import state_cleanup


def test_batch_limit_uses_config_fallback_and_safe_bounds(app):
    with app.app_context():
        app.config["SECURITY_STATE_CLEANUP_BATCH_SIZE"] = 250
        assert state_cleanup._batch_limit(None) == 250
        assert state_cleanup._batch_limit("invalid") == 250
        assert state_cleanup._batch_limit(0) == 1
        assert state_cleanup._batch_limit(9000) == 5000
        assert state_cleanup._batch_limit("42") == 42


def test_as_utc_normalizes_naive_and_offset_datetimes():
    naive = datetime(2026, 1, 2, 3, 4, 5)
    offset = datetime(2026, 1, 2, 11, 4, 5, tzinfo=timezone(timedelta(hours=8)))

    assert state_cleanup._as_utc(naive) == naive.replace(tzinfo=timezone.utc)
    assert state_cleanup._as_utc(offset) == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def test_mark_expired_sessions_redacts_payload_and_records_expiry(app, monkeypatch):
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    records = [
        SimpleNamespace(
            payload={"secret": "fake"},
            revoked_at=None,
            ended_at=None,
            ended_reason=None,
        ),
        SimpleNamespace(
            payload={"secret": "fake-two"},
            revoked_at=None,
            ended_at=None,
            ended_reason=None,
        ),
    ]
    result = SimpleNamespace(scalars=lambda: records)
    monkeypatch.setattr(state_cleanup.db.session, "execute", lambda _statement: result)

    with app.app_context():
        assert state_cleanup._mark_expired_sessions(now, 20) == 2

    for record in records:
        assert record.payload is None
        assert record.revoked_at == now
        assert record.ended_at == now
        assert record.ended_reason == "expired"


def test_mark_expired_sessions_dry_run_counts_without_mutating(app, monkeypatch):
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    records = [
        SimpleNamespace(
            payload={"secret": "fake"},
            revoked_at=None,
            ended_at=None,
            ended_reason=None,
        )
    ]
    result = SimpleNamespace(scalars=lambda: records)
    monkeypatch.setattr(state_cleanup.db.session, "execute", lambda _statement: result)

    with app.app_context():
        assert state_cleanup._mark_expired_sessions(now, 20, dry_run=True) == 1

    assert records[0].payload == {"secret": "fake"}
    assert records[0].revoked_at is None
    assert records[0].ended_at is None
    assert records[0].ended_reason is None


def test_delete_rows_returns_zero_or_deletes_only_selected_ids(app, monkeypatch):
    executions = []
    scalar_results = iter([[], [2, 4]])

    def execute(statement):
        executions.append(statement)
        return SimpleNamespace(scalars=lambda: next(scalar_results))

    monkeypatch.setattr(state_cleanup.db.session, "execute", execute)

    with app.app_context():
        assert state_cleanup._delete_rows(
            state_cleanup.AuthAttemptCounter,
            state_cleanup.AuthAttemptCounter.window_expires_at
            <= datetime.now(timezone.utc),
            limit=10,
        ) == 0
        assert state_cleanup._delete_rows(
            state_cleanup.AuthAttemptCounter,
            state_cleanup.AuthAttemptCounter.window_expires_at
            <= datetime.now(timezone.utc),
            limit=10,
        ) == 2

    assert len(executions) == 3
    assert executions[-1].is_delete


def test_delete_rows_dry_run_counts_without_delete_statement(app, monkeypatch):
    executions = []

    def execute(statement):
        executions.append(statement)
        return SimpleNamespace(scalars=lambda: [2, 4])

    monkeypatch.setattr(state_cleanup.db.session, "execute", execute)

    with app.app_context():
        assert state_cleanup._delete_rows(
            state_cleanup.AuthAttemptCounter,
            state_cleanup.AuthAttemptCounter.window_expires_at
            <= datetime.now(timezone.utc),
            limit=10,
            dry_run=True,
        ) == 2

    assert len(executions) == 1
    assert not getattr(executions[0], "is_delete", False)


def test_cleanup_expired_security_state_uses_one_bounded_batch_and_commits(app, monkeypatch):
    now = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    delete_calls = []
    commit_calls = []
    monkeypatch.setattr(
        state_cleanup,
        "_mark_expired_sessions",
        lambda value, limit, *, dry_run: 3,
    )

    def fake_delete(model, *criteria, limit, dry_run):
        delete_calls.append((model, criteria, limit, dry_run))
        return len(delete_calls)

    monkeypatch.setattr(state_cleanup, "_delete_rows", fake_delete)
    monkeypatch.setattr(
        state_cleanup.db.session,
        "commit",
        lambda: commit_calls.append(True),
    )

    with app.app_context():
        app.config["SECURITY_STATE_RETENTION_DAYS"] = 30
        result = state_cleanup.cleanup_expired_security_state(now=now, limit=12)

    assert result == {
        "expired_sessions_marked": 3,
        "old_sessions_deleted": 1,
        "auth_attempt_counters_deleted": 2,
        "totp_replay_records_deleted": 3,
        "registration_otp_challenges_deleted": 4,
        "password_reset_transactions_deleted": 5,
        "password_reset_tokens_deleted": 6,
        "security_alert_dedupe_deleted": 7,
        "security_circuit_breakers_deleted": 8,
    }
    assert len(delete_calls) == 8
    assert all(limit == 12 for _, _, limit, _ in delete_calls)
    assert all(dry_run is False for _, _, _, dry_run in delete_calls)
    assert commit_calls == [True]


def test_cleanup_expired_security_state_dry_run_rolls_back(app, monkeypatch):
    now = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    delete_calls = []
    commit_calls = []
    rollback_calls = []
    monkeypatch.setattr(
        state_cleanup,
        "_mark_expired_sessions",
        lambda value, limit, *, dry_run: 3 if dry_run else 0,
    )

    def fake_delete(model, *criteria, limit, dry_run):
        delete_calls.append((model, criteria, limit, dry_run))
        return len(delete_calls)

    monkeypatch.setattr(state_cleanup, "_delete_rows", fake_delete)
    monkeypatch.setattr(
        state_cleanup.db.session,
        "commit",
        lambda: commit_calls.append(True),
    )
    monkeypatch.setattr(
        state_cleanup.db.session,
        "rollback",
        lambda: rollback_calls.append(True),
    )

    with app.app_context():
        app.config["SECURITY_STATE_RETENTION_DAYS"] = 30
        result = state_cleanup.cleanup_expired_security_state(
            now=now,
            limit=12,
            dry_run=True,
        )

    assert result["expired_sessions_marked"] == 3
    assert result["security_circuit_breakers_deleted"] == 8
    assert all(dry_run is True for _, _, _, dry_run in delete_calls)
    assert commit_calls == []
    assert rollback_calls == [True]
