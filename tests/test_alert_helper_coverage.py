from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.security import alerts


def test_alert_environment_config_rejects_ambiguous_and_invalid_values(app, tmp_path):
    with pytest.raises(alerts.AlertConfigurationError, match="not both"):
        alerts.configured_alert_webhook_url(
            {
                "SECURITY_ALERT_WEBHOOK_URL": "https://example.test/hook",
                "SECURITY_ALERT_WEBHOOK_URL_FILE": str(tmp_path / "hook"),
            }
        )
    assert alerts._configured_alert_enabled({"APP_ENV": "production"}) is True
    assert alerts._configured_alert_enabled({"SECURITY_ALERT_ENABLED": "yes"}) is True
    assert alerts._configured_alert_enabled({"SECURITY_ALERT_ENABLED": "off"}) is False
    with pytest.raises(alerts.AlertConfigurationError, match="boolean"):
        alerts._configured_alert_enabled({"SECURITY_ALERT_ENABLED": "maybe"})
    with pytest.raises(alerts.AlertConfigurationError, match="invalid"):
        alerts._configured_alert_min_severity({"SECURITY_ALERT_MIN_SEVERITY": "invalid"})
    for value, message in (("bad", "numeric"), ("31", "between 1 and 30")):
        with pytest.raises(alerts.AlertConfigurationError, match=message):
            alerts._configured_alert_timeout_seconds(
                {"SECURITY_ALERT_TIMEOUT_SECONDS": value}
            )
    for value, message in (("bad", "integer"), ("10", "between 60 and 86400")):
        with pytest.raises(alerts.AlertConfigurationError, match=message):
            alerts._configured_alert_dedupe_ttl_seconds(
                {"SECURITY_ALERT_DEDUPE_TTL_SECONDS": value}
            )
    with pytest.raises(alerts.AlertConfigurationError, match="not readable"):
        alerts._read_webhook_url_file(str(tmp_path / "missing"))
    webhook_file = tmp_path / "webhook"
    webhook_file.write_text("https://example.test/fake-hook\n", encoding="utf-8")
    assert alerts.configured_alert_webhook_url(
        {"SECURITY_ALERT_WEBHOOK_URL_FILE": str(webhook_file)}
    ) == "https://example.test/fake-hook"
    with app.app_context():
        app.config["SECURITY_ALERT_WEBHOOK_URL"] = None
        app.config["SECURITY_ALERT_WEBHOOK_URL_FILE"] = str(webhook_file)
        assert alerts.configured_alert_webhook_url() == "https://example.test/fake-hook"
    with pytest.raises(alerts.AlertConfigurationError, match="HTTPS"):
        alerts._validated_webhook_url("http://example.test/hook")


def test_database_integrity_state_roundtrip_and_validation(tmp_path):
    path = tmp_path / "state" / "integrity.json"
    state = {"tables": {"users": {"count": 1, "max_id": 1}}}
    alerts._write_database_integrity_state(path, state)
    assert alerts._load_database_integrity_state(path) == state
    assert alerts._load_database_integrity_state(tmp_path / "missing.json") is None

    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{", encoding="utf-8")
    with pytest.raises(alerts.AlertConfigurationError, match="must contain JSON"):
        alerts._load_database_integrity_state(invalid_json)
    invalid_object = tmp_path / "list.json"
    invalid_object.write_text("[]", encoding="utf-8")
    with pytest.raises(alerts.AlertConfigurationError, match="JSON object"):
        alerts._load_database_integrity_state(invalid_object)
    missing_tables = tmp_path / "missing-tables.json"
    missing_tables.write_text("{}", encoding="utf-8")
    with pytest.raises(alerts.AlertConfigurationError, match="missing table metrics"):
        alerts._load_database_integrity_state(missing_tables)


def test_database_integrity_regression_alerts_fail_closed_and_report_rewind():
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    assert alerts._database_integrity_regression_alerts(
        None,
        {"tables": {}},
        current_time=now,
    ) == []
    with pytest.raises(alerts.AlertConfigurationError, match="malformed"):
        alerts._database_integrity_regression_alerts(
            {"tables": []},
            {"tables": {}},
            current_time=now,
        )

    table = next(iter(alerts.DATABASE_INTEGRITY_TABLES))
    result = alerts._database_integrity_regression_alerts(
        {"tables": {table: {"count": 5, "max_id": 9}}},
        {"tables": {table: {"count": 4, "max_id": 8}}},
        current_time=now,
    )
    assert result[0]["alert_type"] == "database_table_regression"
    assert result[0]["source"] == f"table:{table}"
    assert alerts._state_int("bad") == 0
    assert alerts._state_optional_int(None) is None
    assert alerts._state_optional_int("bad") is None


def test_delivery_sanitization_and_discord_helpers_cover_edge_values():
    assert alerts._is_sensitive_delivery_key("authorization")
    assert not alerts._is_sensitive_delivery_key("alert_type")
    assert alerts._looks_like_sensitive_delivery_value("") is False
    assert alerts._looks_like_sensitive_delivery_value("[redacted]") is True
    assert alerts._looks_like_sensitive_delivery_value("Bearer fake") is True
    assert alerts._looks_like_sensitive_delivery_value(
        "-----BEGIN " + "PRIVATE KEY-----"
    ) is True
    assert alerts._looks_like_sensitive_delivery_value(
        "12345678-1234-5678-1234-567812345678"
    ) is False
    assert alerts._sanitize_delivery_value(
        {"token": "fake", "nested": [{"safe": "value"}]},
        "metadata",
        depth=0,
    ) == {"token": alerts.REDACTED_VALUE, "nested": [{"safe": "value"}]}
    assert alerts._sanitize_delivery_value("a1" * 100, "value", depth=4) == (
        alerts.REDACTED_VALUE
    )

    generated_at = "2026-01-02T03:04:05Z"
    many = [
        {
            "alert_type": f"type-{index}",
            "severity": "critical" if index == 0 else "low",
            "source": "test",
            "count": 1,
            "window_seconds": 60,
        }
        for index in range(alerts.DISCORD_EMBED_FIELD_LIMIT + 2)
    ]
    payload = alerts._discord_alert_payload(many, generated_at=generated_at)
    fields = payload["embeds"][0]["fields"]
    assert fields[-1]["name"] == "Additional alerts"
    assert payload["allowed_mentions"] == {"parse": []}
    assert alerts._discord_embed_color(many) == 0xD92D20
    assert alerts._discord_embed_color([{"severity": "high"}]) == 0xDC6803
    assert alerts._discord_embed_color([{"severity": "medium"}]) == 0xF79009
    assert alerts._discord_embed_color([]) == 0x1570EF
    assert alerts._format_window_seconds("bad") == "immediate"
    assert alerts._format_window_seconds(90) == "90 second(s)"
    assert alerts._format_window_seconds(120) == "2 minute(s)"


def test_event_grouping_and_safe_reference_fallbacks():
    event = SimpleNamespace(
        event_type=next(iter(alerts.TRANSACTION_EVENT_TYPES)),
        outcome="blocked",
        user_id=4,
        event_metadata={"transaction_ref": "safe_ref"},
        session_ref="session_ref",
        ip_address="192.0.2.10",
    )
    assert alerts._is_transaction_failure(event)
    assert "user:4:transaction_ref:safe_ref" in alerts._transaction_group(event)
    assert alerts._event_source(event) == "session_ref:session_ref"
    event.event_metadata = {"principal_ref": "principal_ref"}
    assert alerts._event_source(event) == "principal_ref:principal_ref"
    event.event_metadata = []
    event.session_ref = None
    assert alerts._event_source(event) == "ip:192.0.2.10"
    event.ip_address = None
    assert alerts._event_source(event) == "unknown"
    assert alerts._safe_ref("unsafe/value") is None
    assert alerts._safe_secret_text("  ") is None
    assert alerts._safe_text("Bearer fake-token", 100) == alerts.REDACTED_VALUE
    alert = alerts._alert(
        "test",
        current_time=datetime(2026, 1, 2, tzinfo=timezone.utc),
        severity="high",
        count=1,
        window_seconds=0,
        source="unit",
        omitted=None,
    )
    assert "omitted" not in alert


def test_alert_dedupe_requires_context(monkeypatch):
    monkeypatch.setattr(alerts, "has_app_context", lambda: False)
    with pytest.raises(alerts.AlertConfigurationError, match="Application context"):
        alerts._dedupe_alerts([], ttl_seconds=300)


def test_alert_dedupe_reuses_expired_record_and_rolls_back(app, monkeypatch):
    expired = SimpleNamespace(
        expires_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        count=9,
        first_seen_at=None,
        last_seen_at=None,
        event_type=None,
    )

    class Result:
        def scalar_one_or_none(self):
            return expired

    monkeypatch.setattr(alerts.db.session, "execute", lambda _statement: Result())
    monkeypatch.setattr(alerts.db.session, "commit", lambda: None)
    with app.app_context():
        deliverable, status = alerts._dedupe_alerts(
            [{"alert_type": "test", "severity": "high", "source": "unit"}],
            ttl_seconds=300,
        )
    assert len(deliverable) == 1
    assert status["suppressed"] == 0
    assert expired.count == 1

    rollbacks = []
    monkeypatch.setattr(
        alerts.db.session,
        "commit",
        lambda: (_ for _ in ()).throw(RuntimeError("commit failed")),
    )
    monkeypatch.setattr(alerts.db.session, "rollback", lambda: rollbacks.append(True))
    with app.app_context(), pytest.raises(alerts.AlertConfigurationError, match="dedupe failed"):
        alerts._dedupe_alerts(
            [{"alert_type": "test", "severity": "high", "source": "unit"}],
            ttl_seconds=300,
        )
    assert rollbacks == [True]
