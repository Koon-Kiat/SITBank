from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace

from app.extensions import db
from app.models import KnownDevice, TopUpApprovalRequest, User
from app.security import state_cleanup
from app.security.passwords import hash_password


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
        "public_transaction_idempotency_deleted": 9,
        "expired_known_devices_deleted": 10,
        "terminal_topup_approval_requests_deleted": 11,
    }
    assert len(delete_calls) == 11
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
    assert result["public_transaction_idempotency_deleted"] == 9
    assert result["expired_known_devices_deleted"] == 10
    assert result["terminal_topup_approval_requests_deleted"] == 11
    assert all(dry_run is True for _, _, _, dry_run in delete_calls)
    assert commit_calls == []
    assert rollback_calls == [True]


def test_cleanup_deletes_expired_known_devices_and_terminal_topup_requests(app):
    now = datetime(2026, 1, 31, 12, 0, tzinfo=timezone.utc)
    retention_cutoff = now - timedelta(days=30)

    with app.app_context():
        app.config["SECURITY_STATE_RETENTION_DAYS"] = 30
        user = User(
            username="cleanup-customer",
            email="cleanup-customer@example.com",
            password_hash=hash_password("correct horse battery staple"),
            account_type="customer",
            account_status="active",
            full_name="Cleanup Customer",
            phone_number="81234567",
            account_number="123456789012",
        )
        db.session.add(user)
        db.session.flush()
        db.session.add_all(
            [
                KnownDevice(
                    user_id=user.id,
                    device_token_hash="expired-device",
                    expires_at=now - timedelta(seconds=1),
                ),
                KnownDevice(
                    user_id=user.id,
                    device_token_hash="active-device",
                    expires_at=now + timedelta(days=1),
                ),
                TopUpApprovalRequest(
                    selector="completed-old",
                    verifier_hmac="hmac-completed-old",
                    user_id=user.id,
                    amount=Decimal("10.00"),
                    status="completed",
                    expires_at=retention_cutoff - timedelta(seconds=1),
                ),
                TopUpApprovalRequest(
                    selector="failed-recent",
                    verifier_hmac="hmac-failed-recent",
                    user_id=user.id,
                    amount=Decimal("10.00"),
                    status="failed",
                    expires_at=retention_cutoff + timedelta(seconds=1),
                ),
                TopUpApprovalRequest(
                    selector="pending-old",
                    verifier_hmac="hmac-pending-old",
                    user_id=user.id,
                    amount=Decimal("10.00"),
                    status="pending",
                    expires_at=retention_cutoff - timedelta(seconds=1),
                ),
            ]
        )
        db.session.commit()

        result = state_cleanup.cleanup_expired_security_state(now=now, limit=20)

        assert result["expired_known_devices_deleted"] == 1
        assert result["terminal_topup_approval_requests_deleted"] == 1
        remaining_device_hashes = {
            row.device_token_hash for row in db.session.execute(db.select(KnownDevice)).scalars()
        }
        remaining_topup_selectors = {
            row.selector for row in db.session.execute(db.select(TopUpApprovalRequest)).scalars()
        }
        assert remaining_device_hashes == {"active-device"}
        assert remaining_topup_selectors == {"failed-recent", "pending-old"}
