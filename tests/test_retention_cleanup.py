from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.security import retention


def test_retention_cleanup_defaults_to_dry_run_and_preserves_categories(app, monkeypatch):
    calls = []

    def fake_cleanup(**kwargs):
        calls.append(kwargs)
        return {"expired_sessions_marked": 2, "old_sessions_deleted": 1}

    monkeypatch.setattr(retention, "cleanup_expired_security_state", fake_cleanup)

    with app.app_context():
        app.config["SECURITY_STATE_RETENTION_DAYS"] = 30
        app.config["SECURITY_STATE_CLEANUP_BATCH_SIZE"] = 250
        result = retention.run_retention_cleanup(limit=7)

    assert calls == [{"now": None, "limit": 7, "dry_run": True, "commit": True}]
    assert result["mode"] == "dry_run"
    assert result["dry_run"] is True
    assert result["retention_days"] == 30
    assert result["batch_limit"] == 7
    assert result["category_counts"]["expired_sessions_marked"] == 2
    assert "expired_password_reset_transactions" in result["approved_categories"]
    assert (
        "expired_password_reset_tokens_without_transactions"
        in result["approved_categories"]
    )
    assert "security_audit_events" in result["preserved_categories"]
    assert "transactions" in result["preserved_categories"]
    assert result["scheduling"] == "weekly_operator_reviewed_dry_run"


def test_retention_cleanup_requires_confirmation_for_mutation(app, monkeypatch):
    monkeypatch.setattr(
        retention,
        "cleanup_expired_security_state",
        lambda **_kwargs: {"expired_sessions_marked": 0},
    )

    with app.app_context(), pytest.raises(
        retention.RetentionCleanupError,
        match="requires --confirm",
    ):
        retention.run_retention_cleanup(dry_run=False, confirm=False)


def test_retention_cleanup_confirmed_mode_calls_bounded_cleanup(app, monkeypatch):
    calls = []
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)

    def fake_cleanup(**kwargs):
        calls.append(kwargs)
        return {"security_alert_dedupe_deleted": 4}

    monkeypatch.setattr(retention, "cleanup_expired_security_state", fake_cleanup)

    with app.app_context():
        result = retention.run_retention_cleanup(
            now=now,
            limit=9,
            dry_run=False,
            confirm=True,
        )

    assert calls == [{"now": now, "limit": 9, "dry_run": False, "commit": True}]
    assert result["mode"] == "confirmed"
    assert result["dry_run"] is False
    assert result["category_counts"] == {"security_alert_dedupe_deleted": 4}


def test_retention_cleanup_rejects_unsafe_config_and_limit(app, monkeypatch):
    monkeypatch.setattr(
        retention,
        "cleanup_expired_security_state",
        lambda **_kwargs: {"expired_sessions_marked": 0},
    )

    with app.app_context():
        app.config["SECURITY_STATE_RETENTION_DAYS"] = 0
        with pytest.raises(retention.RetentionCleanupError, match="RETENTION_DAYS"):
            retention.run_retention_cleanup()

        app.config["SECURITY_STATE_RETENTION_DAYS"] = 30
        with pytest.raises(retention.RetentionCleanupError, match="--limit"):
            retention.run_retention_cleanup(limit=0)
