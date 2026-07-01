from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.ops import commands


def test_production_check_reports_details_success_and_failure(app, monkeypatch):
    runner = app.test_cli_runner()
    monkeypatch.setattr(
        commands,
        "validate_production_security_prerequisites",
        lambda _app, *, app_mode: SimpleNamespace(
            details={"app_mode": app_mode},
            failures=[],
        ),
    )
    result = runner.invoke(args=["production-check"])
    assert result.exit_code == 0
    assert "app_mode: customer" in result.output
    assert "readiness checks passed" in result.output

    monkeypatch.setattr(
        commands,
        "validate_production_security_prerequisites",
        lambda _app, *, app_mode: SimpleNamespace(
            details={"app_mode": app_mode},
            failures=["clearly fake failure"],
        ),
    )
    result = runner.invoke(args=["production-check"])
    assert result.exit_code != 0
    assert "clearly fake failure" in result.output


@pytest.mark.parametrize(
    ("command", "attribute", "success", "expected"),
    [
        (
            "verify-runtime-db-privileges",
            "verify_runtime_database_privileges",
            SimpleNamespace(
                runtime_role="runtime",
                migration_role="owner",
                probe_table="probe",
                audit_table="public.audit",
                extension_probe="citext",
            ),
            "Runtime database privilege checks passed",
        ),
        (
            "apply-runtime-db-privileges",
            "apply_runtime_audit_table_privileges",
            SimpleNamespace(
                runtime_role="runtime",
                migration_role="owner",
                audit_table="public.audit",
            ),
            "Runtime database privilege application passed",
        ),
        (
            "apply-admin-runtime-db-privileges",
            "apply_admin_runtime_database_privileges",
            SimpleNamespace(
                admin_role="admin_runtime",
                migration_role="owner",
                database="sitbank",
                schema="public",
            ),
            "Admin runtime database privilege application passed",
        ),
    ],
)
def test_database_privilege_commands_report_sanitized_success(
    app,
    monkeypatch,
    command,
    attribute,
    success,
    expected,
):
    app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://runtime:fake@db/sitbank"
    app.config["SQLALCHEMY_MIGRATION_DATABASE_URI"] = "postgresql://owner:fake@db/sitbank"
    monkeypatch.setenv("ADMIN_DATABASE_URL", "postgresql://admin:fake@db/sitbank")
    monkeypatch.setattr(commands, attribute, lambda **_kwargs: success)

    result = app.test_cli_runner().invoke(args=[command])

    assert result.exit_code == 0
    assert expected in result.output
    assert "fake@db" not in result.output


def test_database_privilege_command_failure_delivers_alert(app, monkeypatch):
    alerts = []
    monkeypatch.setattr(
        commands,
        "verify_runtime_database_privileges",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("safe failure")),
    )
    monkeypatch.setattr(
        commands,
        "_deliver_ops_failure_alert",
        lambda *args: alerts.append(args),
    )

    result = app.test_cli_runner().invoke(args=["verify-runtime-db-privileges"])

    assert result.exit_code != 0
    assert "safe failure" in result.output
    assert alerts[0][:2] == (
        "runtime_db_privilege_verification_failed",
        "verify-runtime-db-privileges",
    )


def test_audit_alert_expiry_and_cleanup_commands(app, monkeypatch, tmp_path):
    runner = app.test_cli_runner()
    anchor = {"event_id": 1, "event_hash": "0" * 64}
    monkeypatch.setattr(commands, "audit_log_anchor", lambda: anchor)
    exported = runner.invoke(args=["export-audit-log-anchor"])
    assert exported.exit_code == 0
    assert json.loads(exported.output) == anchor

    anchor_path = tmp_path / "anchor.json"
    anchor_path.write_text(json.dumps(anchor), encoding="utf-8")
    monkeypatch.setattr(
        commands,
        "verify_audit_hash_chain",
        lambda *, anchor: {"valid": True, "anchor": anchor},
    )
    verified = runner.invoke(
        args=["verify-audit-log-chain", "--anchor", str(anchor_path)]
    )
    assert verified.exit_code == 0
    assert json.loads(verified.output)["valid"] is True

    monkeypatch.setattr(
        commands,
        "build_security_alert_report",
        lambda *, deliver: {
            "alert_count": 1,
            "delivery": {"attempted": deliver, "delivered": False},
        },
    )
    report_only = runner.invoke(args=["check-security-alerts", "--report-only"])
    assert report_only.exit_code == 0
    assert json.loads(report_only.output)["alert_count"] == 1
    blocking = runner.invoke(args=["check-security-alerts"])
    assert blocking.exit_code != 0
    assert "Security alerts active" in blocking.output

    from app.auth import password_reset
    from app.security import state_cleanup

    monkeypatch.setattr(password_reset, "expire_manual_recovery_requests", lambda *, limit: limit)
    expired = runner.invoke(args=["expire-manual-recovery-requests", "--limit", "7"])
    assert expired.exit_code == 0
    assert json.loads(expired.output) == {"expired_count": 7}

    monkeypatch.setattr(
        state_cleanup,
        "cleanup_expired_security_state",
        lambda *, limit: {"limit": limit},
    )
    cleaned = runner.invoke(args=["cleanup-security-state", "--limit", "8"])
    assert cleaned.exit_code == 0
    assert json.loads(cleaned.output) == {"limit": 8}


def test_ops_helpers_normalize_time_anchor_env_and_alert_metadata(tmp_path, monkeypatch):
    naive = datetime(2026, 1, 2, 3, 4, 5)
    offset = datetime(2026, 1, 2, 11, 4, 5, tzinfo=timezone(timedelta(hours=8)))
    assert commands._utc_iso_or_none(None) is None
    assert commands._aware_utc(naive).tzinfo == timezone.utc
    assert commands._aware_utc(offset) == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    invalid = tmp_path / "invalid.json"
    invalid.write_text("[]", encoding="utf-8")
    with pytest.raises(Exception, match="JSON object"):
        commands._load_audit_anchor(invalid)
    with pytest.raises(Exception, match="could not be read"):
        commands._load_audit_anchor(tmp_path / "missing.json")

    monkeypatch.setenv("VALUE", "direct")
    monkeypatch.setenv("VALUE_FILE", str(invalid))
    with pytest.raises(Exception, match="must not both"):
        commands._env_or_file("VALUE")
    monkeypatch.delenv("VALUE_FILE")
    assert commands._env_or_file("VALUE") == "direct"
    monkeypatch.delenv("VALUE")
    with pytest.raises(Exception, match="is required"):
        commands._env_or_file("VALUE")

    assert commands._audit_chain_failure_alert({"errors": [], "anchor_errors": ["bad"]})[
        "alert_type"
    ] == "audit_anchor_mismatch"
    assert commands._audit_chain_failure_alert({"errors": ["bad"]})["count"] == 1
