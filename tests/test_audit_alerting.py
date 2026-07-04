from __future__ import annotations

import os
import secrets
from pathlib import Path

from _auth_flow_helpers import *


def test_audit_metadata_strips_control_characters_and_redacts_secrets(app):
    from app.security.audit import audit_event

    with app.test_request_context("/"):
        audit_event(
            "audit_hygiene",
            "success",
            metadata={
                "note": "line1\r\nline2\tend",
                "password\nfield": "secret-value",
                "amount": "10.00",
            },
        )

    event = db.session.query(SecurityAuditEvent).filter_by(event_type="audit_hygiene").one()

    assert event.event_metadata["note"] == "line1 line2 end"
    assert event.event_metadata["password field"] == "[redacted]"
    assert event.event_metadata["amount"] == "10.00"

def test_structured_audit_log_output_is_sanitized(app, caplog):
    from app.security.audit import audit_event

    raw_session_id = "raw-session-id-should-not-be-logged"
    caplog.set_level("INFO", logger=app.logger.name)
    with app.test_request_context(
        "/audit/hygiene?token=query-secret",
        method="POST",
        environ_overrides={"REMOTE_ADDR": "198.51.100.44"},
        headers={"User-Agent": "AuditTest/1.0"},
    ):
        audit_event(
            "audit_hygiene",
            "success",
            metadata={
                "note": "line1\nline2",
                "password": "plain-password",
                "totp_code": "123456",
                "csrf_token": "csrf-secret",
                "bearer_token": "Bearer token-secret",
                "session_id": raw_session_id,
                "account_number": "1234 5678 9012 3456",
            },
            session_id=raw_session_id,
        )

    logs = "\n".join(record.getMessage() for record in caplog.records)
    payload = log_payloads(caplog, "security_audit_event")[-1]

    assert payload["path"] == "/audit/hygiene"
    assert payload["method"] == "POST"
    assert payload["session_ref"] != raw_session_id
    assert len(payload["session_ref"]) == 16
    assert payload["hash_algorithm"] == "hmac-sha256-v1"
    assert len(payload["event_hash"]) == 64
    assert len(payload["previous_event_hash"]) == 64
    assert payload["metadata"]["note"] == "line1 line2"
    assert payload["metadata"]["password"] == "[redacted]"
    assert payload["metadata"]["totp_code"] == "[redacted]"
    assert payload["metadata"]["csrf_token"] == "[redacted]"
    assert payload["metadata"]["bearer_token"] == "[redacted]"
    assert payload["metadata"]["session_id"] == "[redacted]"
    assert payload["metadata"]["account_number"] == "[redacted]"
    for forbidden in (
        "query-secret",
        "plain-password",
        "123456",
        "csrf-secret",
        "token-secret",
        raw_session_id,
        "1234 5678 9012 3456",
    ):
        assert forbidden not in logs

def test_audit_write_failure_warning_is_sanitized(app, caplog, monkeypatch):
    from app.security.audit import audit_event

    def fail_commit():
        raise RuntimeError("database password leaked")

    monkeypatch.setattr(db.session, "commit", fail_commit)
    caplog.set_level("WARNING", logger=app.logger.name)

    with app.test_request_context("/audit/fail", method="POST"):
        audit_event(
            "audit_failure",
            "failure",
            metadata={
                "password": "plain-password",
                "token": "Bearer token-secret",
            },
        )

    logs = "\n".join(record.getMessage() for record in caplog.records)
    payload = log_payloads(caplog, "security_audit_write_failed")[-1]

    assert payload["event_type"] == "audit_failure"
    assert payload["error_type"] == "RuntimeError"
    assert payload["metadata"]["password"] == "[redacted]"
    assert payload["metadata"]["token"] == "[redacted]"
    assert "database password leaked" not in logs
    assert "plain-password" not in logs
    assert "token-secret" not in logs

def test_required_audit_write_failure_raises_and_logs_sanitized_warning(app, caplog, monkeypatch):
    from app.security.audit import AuditWriteError, audit_event_required

    def fail_flush(_objects=None):
        raise RuntimeError("database password leaked")

    monkeypatch.setattr(db.session, "flush", fail_flush)
    caplog.set_level("WARNING", logger=app.logger.name)

    with app.test_request_context("/audit/required", method="POST"):
        with pytest.raises(AuditWriteError):
            audit_event_required(
                "banking_transaction_authorization",
                "approved",
                metadata={
                    "transaction_ref": "TXN-001",
                    "authorization": "Bearer token-secret",
                },
            )

    logs = "\n".join(record.getMessage() for record in caplog.records)
    payload = log_payloads(caplog, "security_audit_write_failed")[-1]

    assert payload["event_type"] == "banking_transaction_authorization"
    assert payload["metadata"]["authorization"] == "[redacted]"
    assert "database password leaked" not in logs
    assert "token-secret" not in logs

def test_required_audit_waits_for_caller_commit_before_persisting(app):
    from app.security.audit import audit_event_required

    user = User(
        username="auditboundary",
        email="auditboundary@example.com",
        password_hash=hash_password("correct horse battery staple"),
        full_name="Audit Boundary",
        phone_number="81234567",
        account_number="012345678000",
    )
    db.session.add(user)
    db.session.commit()
    user_id = user.id

    user.full_name = "Unexpected Commit"
    with app.test_request_context("/audit/required-boundary", method="POST"):
        audit_event_required("required_boundary", "success", user=user)

    db.session.rollback()

    persisted = db.session.get(User, user_id)
    assert persisted.full_name == "Audit Boundary"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="required_boundary").count() == 0

def test_required_audit_success_is_committed_by_the_caller(app):
    from app.security.audit import audit_event_required

    user = User(
        username="auditcommit",
        email="auditcommit@example.com",
        password_hash=hash_password("correct horse battery staple"),
        full_name="Audit Commit",
        phone_number="82345678",
        account_number="012456789000",
    )
    db.session.add(user)
    db.session.commit()
    user_id = user.id

    user.full_name = "Caller Commit"
    with app.test_request_context("/audit/required-commit", method="POST"):
        audit_event_required("required_commit", "success", user=user)
    db.session.commit()

    persisted = db.session.get(User, user_id)
    event = db.session.query(SecurityAuditEvent).filter_by(event_type="required_commit").one()
    assert persisted.full_name == "Caller Commit"
    assert event.outcome == "success"
    assert event.user_id == user_id

def test_required_audit_failure_leaves_business_rollback_to_caller(app, monkeypatch):
    from app.security import audit as audit_module

    user = User(
        username="auditfailure",
        email="auditfailure@example.com",
        password_hash=hash_password("correct horse battery staple"),
        full_name="Audit Failure",
        phone_number="83456789",
        account_number="012567890000",
    )
    db.session.add(user)
    db.session.commit()
    user_id = user.id

    def fail_latest_hash():
        raise RuntimeError("audit writer unavailable")

    monkeypatch.setattr(audit_module, "_latest_audit_event_hash", fail_latest_hash)
    user.full_name = "Should Roll Back"
    with app.test_request_context("/audit/required-fail", method="POST"):
        with pytest.raises(audit_module.AuditWriteError):
            audit_module.audit_event_required("required_failure", "success", user=user)

    db.session.rollback()

    persisted = db.session.get(User, user_id)
    assert persisted.full_name == "Audit Failure"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="required_failure").count() == 0

def test_audit_system_writer_uses_append_only_runtime_read_path(app, monkeypatch):
    from app.security import audit as audit_module

    def reject_row_locks(execute_state):
        if getattr(execute_state.statement, "_for_update_arg", None) is not None:
            raise AssertionError("audit writer must not issue SELECT FOR UPDATE")

    sqlalchemy_event.listen(Session, "do_orm_execute", reject_row_locks)
    monkeypatch.setattr(db.engine.dialect, "name", "postgresql", raising=False)
    monkeypatch.setattr(audit_module, "_lock_audit_chain_for_insert", lambda: None)
    try:
        audit_module.audit_system_event(
            "runtime_audit_writer_probe",
            "success",
            metadata={"probe": "append_only_runtime"},
        )
    finally:
        sqlalchemy_event.remove(Session, "do_orm_execute", reject_row_locks)

    event = db.session.execute(
        db.select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "runtime_audit_writer_probe")
    ).scalar_one()
    verification = audit_module.verify_audit_hash_chain()

    assert event.outcome == "success"
    assert event.previous_event_hash == audit_module.AUDIT_CHAIN_START_HASH
    assert event.hash_algorithm == audit_module.AUDIT_HASH_ALGORITHM
    assert event.event_metadata["actor"] == "system"
    assert verification["valid"] is True
    assert verification["event_count"] == 1
    assert verification["latest_event_hash"] == event.event_hash

def test_audit_hash_chain_records_verifies_and_exports_anchor(app, tmp_path):
    from app.security.audit import audit_event, audit_log_anchor, verify_audit_hash_chain

    with app.test_request_context("/audit/chain-one", method="POST"):
        audit_event("chain_one", "success", metadata={"note": "top-secret-note"})
    with app.test_request_context("/audit/chain-two", method="POST"):
        audit_event("chain_two", "success", metadata={"note": "second"})

    events = db.session.query(SecurityAuditEvent).order_by(SecurityAuditEvent.id.asc()).all()
    first, second = events
    verification = verify_audit_hash_chain()
    anchor = audit_log_anchor()
    runner = app.test_cli_runner()
    verify_cli = runner.invoke(args=["verify-audit-log-chain"])
    anchor_cli = runner.invoke(args=["export-audit-log-anchor"])
    cli_anchor = json.loads(anchor_cli.output)
    anchor_path = tmp_path / "audit-anchor.json"
    anchor_path.write_text(json.dumps(anchor), encoding="utf-8")
    verify_anchor_cli = runner.invoke(args=["verify-audit-log-chain", "--anchor", str(anchor_path)])
    corrupt_anchor = dict(anchor)
    corrupt_anchor["latest_event_hash"] = "0" * 64
    corrupt_anchor_path = tmp_path / "corrupt-audit-anchor.json"
    corrupt_anchor_path.write_text(json.dumps(corrupt_anchor), encoding="utf-8")
    corrupt_anchor_cli = runner.invoke(
        args=["verify-audit-log-chain", "--anchor", str(corrupt_anchor_path)]
    )
    future_anchor = dict(anchor)
    future_anchor["latest_event_id"] = second.id + 1000
    future_anchor["event_count"] = anchor["event_count"] + 1000
    future_anchor_path = tmp_path / "future-audit-anchor.json"
    future_anchor_path.write_text(json.dumps(future_anchor), encoding="utf-8")
    future_anchor_cli = runner.invoke(
        args=["verify-audit-log-chain", "--anchor", str(future_anchor_path)]
    )
    app.config["SECURITY_AUDIT_ANCHOR_PATH"] = str(anchor_path)
    configured_anchor_cli = runner.invoke(args=["verify-audit-log-chain"])
    configured_export_path = tmp_path / "configured-audit-anchor.json"
    app.config["SECURITY_AUDIT_ANCHOR_PATH"] = str(configured_export_path)
    configured_export_cli = runner.invoke(args=["export-audit-log-anchor"])
    app.config["SECURITY_AUDIT_ANCHOR_PATH"] = str(anchor_path)
    matching_anchor_alert_cli = runner.invoke(
        args=["check-security-alerts", "--report-only", "--no-delivery"]
    )
    with app.test_request_context("/audit/after-anchor", method="POST"):
        audit_event("anchor_drift", "success", metadata={"note": "append-only"})
    drift_anchor_cli = runner.invoke(args=["verify-audit-log-chain", "--anchor", str(anchor_path)])
    drift_anchor_alert_cli = runner.invoke(
        args=["check-security-alerts", "--report-only", "--no-delivery"]
    )
    strict_drift_anchor_alert_cli = runner.invoke(args=["check-security-alerts", "--no-delivery"])
    app.config["SECURITY_AUDIT_ANCHOR_PATH"] = str(corrupt_anchor_path)
    corrupt_anchor_alert_cli = runner.invoke(
        args=["check-security-alerts", "--report-only", "--no-delivery"]
    )
    strict_corrupt_anchor_alert_cli = runner.invoke(args=["check-security-alerts", "--no-delivery"])
    matching_anchor_report = json.loads(matching_anchor_alert_cli.output)
    drift_anchor = json.loads(drift_anchor_cli.output)
    drift_anchor_report = json.loads(drift_anchor_alert_cli.output)
    corrupt_anchor_report = json.loads(corrupt_anchor_alert_cli.output)

    assert first.previous_event_hash == "0" * 64
    assert len(first.event_hash) == 64
    assert first.hash_algorithm == "hmac-sha256-v1"
    assert second.previous_event_hash == first.event_hash
    assert len(second.event_hash) == 64
    assert verification["valid"] is True
    assert verification["event_count"] == 2
    assert verification["latest_event_id"] == second.id
    assert verification["latest_event_hash"] == second.event_hash
    assert anchor["latest_event_id"] == second.id
    assert anchor["latest_event_hash"] == second.event_hash
    assert anchor["event_count"] == 2
    assert "top-secret-note" not in json.dumps(anchor)
    assert verify_cli.exit_code == 0, verify_cli.output
    assert json.loads(verify_cli.output)["valid"] is True
    assert anchor_cli.exit_code == 0, anchor_cli.output
    assert cli_anchor["latest_event_hash"] == second.event_hash
    assert "top-secret-note" not in anchor_cli.output
    assert verify_anchor_cli.exit_code == 0, verify_anchor_cli.output
    assert json.loads(verify_anchor_cli.output)["anchor_validated"] is True
    assert corrupt_anchor_cli.exit_code != 0
    assert "anchor_event_hash_mismatch" in corrupt_anchor_cli.output
    assert future_anchor_cli.exit_code != 0
    assert "anchor_current_behind" in future_anchor_cli.output
    assert configured_anchor_cli.exit_code == 0, configured_anchor_cli.output
    assert json.loads(configured_anchor_cli.output)["anchor_validated"] is True
    assert configured_export_cli.exit_code == 0, configured_export_cli.output
    assert configured_export_path.exists()
    if os.name != "nt":
        assert configured_export_path.stat().st_mode & 0o777 == 0o600
    assert "top-secret-note" not in configured_export_cli.output
    assert matching_anchor_alert_cli.exit_code == 0, matching_anchor_alert_cli.output
    assert matching_anchor_report["audit_chain"]["anchor_validated"] is True
    assert not any(
        alert["alert_type"] == "audit_anchor_mismatch"
        for alert in matching_anchor_report["alerts"]
    )
    assert drift_anchor_cli.exit_code == 0, drift_anchor_cli.output
    assert drift_anchor["valid"] is True
    assert drift_anchor["anchor_validated"] is False
    assert drift_anchor["anchor_stale"] is True
    assert drift_anchor["anchor_refresh_required"] is True
    assert drift_anchor["anchor_event_id"] == second.id
    assert drift_anchor["events_since_anchor"] == 1
    assert drift_anchor_alert_cli.exit_code == 0, drift_anchor_alert_cli.output
    assert strict_drift_anchor_alert_cli.exit_code == 0, strict_drift_anchor_alert_cli.output
    assert drift_anchor_report["audit_chain"]["valid"] is True
    assert drift_anchor_report["audit_chain"]["anchor_status"] == "stale"
    assert drift_anchor_report["audit_chain"]["anchor_stale"] is True
    assert drift_anchor_report["audit_chain"]["anchor_refresh_required"] is True
    assert drift_anchor_report["audit_chain"]["events_since_anchor"] == 1
    assert not any(
        alert["alert_type"] == "audit_anchor_mismatch"
        for alert in drift_anchor_report["alerts"]
    )
    assert corrupt_anchor_alert_cli.exit_code == 0, corrupt_anchor_alert_cli.output
    assert corrupt_anchor_report["audit_chain"]["anchor_validated"] is False
    assert corrupt_anchor_report["audit_chain"]["anchor_status"] == "critical"
    assert any(
        alert["alert_type"] == "audit_anchor_mismatch"
        for alert in corrupt_anchor_report["alerts"]
    )
    assert strict_corrupt_anchor_alert_cli.exit_code != 0
    assert "top-secret-note" not in corrupt_anchor_alert_cli.output

def test_audit_hash_chain_uses_hmac_key_and_reads_legacy_sha_rows(app):
    from app.security import audit as audit_module

    with app.test_request_context("/audit/hmac", method="POST"):
        audit_module.audit_event("chain_hmac", "success", metadata={"note": "keyed"})

    event = db.session.query(SecurityAuditEvent).one()
    original_hash = event.event_hash
    original_key = app.config["SECURITY_AUDIT_HMAC_KEY"]

    app.config["SECURITY_AUDIT_HMAC_KEY"] = "different-test-audit-hmac-key-that-is-long-enough"
    wrong_key = audit_module.verify_audit_hash_chain()
    app.config["SECURITY_AUDIT_HMAC_KEY"] = original_key

    event.hash_algorithm = audit_module.LEGACY_AUDIT_HASH_ALGORITHM
    event.event_hash = audit_module._compute_audit_event_hash(event)
    db.session.commit()
    legacy = audit_module.verify_audit_hash_chain()

    assert original_hash != event.event_hash
    assert wrong_key["valid"] is False
    assert "event_hash_mismatch" in {error["reason"] for error in wrong_key["errors"]}
    assert legacy["valid"] is True
    assert legacy["verified_event_count"] == 1


def test_audit_hash_chain_keeps_missing_hash_and_unsupported_algorithm_critical(app):
    from app.security import audit as audit_module

    with app.test_request_context("/audit/critical-one", method="POST"):
        audit_module.audit_event("chain_one", "success")
    with app.test_request_context("/audit/critical-two", method="POST"):
        audit_module.audit_event("chain_two", "success")

    _first, second = db.session.query(SecurityAuditEvent).order_by(SecurityAuditEvent.id.asc()).all()
    original_hash = second.event_hash
    second.event_hash = None
    db.session.commit()
    missing_hash = audit_module.verify_audit_hash_chain()

    second.event_hash = original_hash
    second.hash_algorithm = "unsupported-test"
    db.session.commit()
    unsupported = audit_module.verify_audit_hash_chain()

    assert missing_hash["valid"] is False
    assert "missing_event_hash" in {error["reason"] for error in missing_hash["errors"]}
    assert unsupported["valid"] is False
    assert "unsupported_hash_algorithm" in {
        error["reason"] for error in unsupported["errors"]
    }


def test_audit_hash_chain_detects_metadata_link_missing_row_and_order_tampering(app):
    from sqlalchemy import text

    from app.security.alerts import build_security_alert_report
    from app.security.audit import audit_event, verify_audit_hash_chain

    with app.test_request_context("/audit/one", method="POST"):
        audit_event("chain_one", "success", metadata={"note": "one"})
    with app.test_request_context("/audit/two", method="POST"):
        audit_event("chain_two", "success", metadata={"note": "two"})
    with app.test_request_context("/audit/three", method="POST"):
        audit_event("chain_three", "success", metadata={"note": "three"})

    first, second, third = db.session.query(SecurityAuditEvent).order_by(SecurityAuditEvent.id.asc()).all()
    first.event_metadata = {"note": "tampered"}
    second.previous_event_hash = "1" * 64
    db.session.commit()

    tampered = verify_audit_hash_chain()
    tampered_alert_report = build_security_alert_report(deliver=False)
    tamper_reasons = {error["reason"] for error in tampered["errors"]}

    assert tampered["valid"] is False
    assert "event_hash_mismatch" in tamper_reasons
    assert "previous_hash_mismatch" in tamper_reasons
    assert any(
        alert["alert_type"] == "audit_chain_verification_failed"
        for alert in tampered_alert_report["alerts"]
    )
    assert "tampered" not in json.dumps(tampered_alert_report, sort_keys=True)

    db.session.delete(second)
    db.session.commit()
    missing_link = verify_audit_hash_chain()

    assert missing_link["valid"] is False
    assert any(error["event_id"] == third.id for error in missing_link["errors"])
    assert "previous_hash_mismatch" in {error["reason"] for error in missing_link["errors"]}

    db.session.execute(
        text("UPDATE security_audit_events SET id = :new_id WHERE id = :event_id"),
        {"new_id": third.id + 100, "event_id": first.id},
    )
    db.session.commit()
    reordered = verify_audit_hash_chain()

    assert reordered["valid"] is False
    assert "previous_hash_mismatch" in {error["reason"] for error in reordered["errors"]}

def test_security_alerts_detect_database_table_regression_from_external_state(app, tmp_path):
    from app.security.alerts import build_security_alert_report
    from app.security.audit import audit_event

    state_path = tmp_path / "security-alert-state.json"
    app.config["SECURITY_ALERT_STATE_PATH"] = str(state_path)
    user = User(
        username="alice01",
        email="alice@example.com",
        password_hash=hash_password("correct horse battery staple"),
        full_name="Alice Test",
        phone_number="91234567",
        account_number="".join(str(secrets.randbelow(10)) for _ in range(12)),
    )
    db.session.add(user)
    db.session.commit()
    with app.test_request_context("/audit/baseline", method="POST"):
        audit_event("baseline", "success", user=user)

    baseline_report = build_security_alert_report(deliver=True)
    assert baseline_report["database_integrity"]["baseline_available"] is False
    assert state_path.exists()

    db.session.execute(db.delete(SecurityAuditEvent))
    db.session.execute(db.delete(User))
    db.session.commit()

    regression_report = build_security_alert_report(deliver=True)
    regression_alerts = [
        alert
        for alert in regression_report["alerts"]
        if alert["alert_type"] == "database_table_regression"
    ]
    regressed_sources = {alert["source"] for alert in regression_alerts}
    persisted_state = json.loads(state_path.read_text(encoding="utf-8"))

    assert regression_report["database_integrity"]["valid"] is False
    assert {"table:security_audit_events", "table:users"} <= regressed_sources
    assert persisted_state["tables"]["security_audit_events"]["count"] == 1
    assert persisted_state["tables"]["users"]["count"] == 1


def test_audit_anchor_refresh_accepts_only_valid_or_append_only_stale_state(
    app,
    tmp_path,
):
    from app.security.audit import (
        audit_event,
        verify_audit_hash_chain,
        write_audit_log_anchor,
    )

    anchor_path = tmp_path / "security-audit.anchor"
    app.config["SECURITY_AUDIT_ANCHOR_PATH"] = str(anchor_path)
    with app.test_request_context("/audit/initial", method="POST"):
        audit_event("anchor_initial", "success")
    write_audit_log_anchor(anchor_path)
    with app.test_request_context("/audit/after", method="POST"):
        audit_event("anchor_after", "success")

    refreshed = app.test_cli_runner().invoke(args=["refresh-audit-log-anchor"])
    refreshed_payload = json.loads(refreshed.output)
    refreshed_anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    verification = verify_audit_hash_chain(anchor=refreshed_anchor)

    assert refreshed.exit_code == 0, refreshed.output
    assert refreshed_payload["previous_anchor_status"] == "stale"
    assert refreshed_payload["anchor_status"] == "validated"
    assert refreshed_payload["anchor_refresh_required"] is False
    assert verification["valid"] is True
    assert verification["anchor_status"] == "validated"

    corrupted = dict(refreshed_anchor)
    corrupted["latest_event_hash"] = "f" * 64
    anchor_path.write_text(json.dumps(corrupted), encoding="utf-8")
    if os.name != "nt":
        anchor_path.chmod(0o600)
    refused = app.test_cli_runner().invoke(args=["refresh-audit-log-anchor"])

    assert refused.exit_code != 0
    assert "validation failed" in refused.output
    assert json.loads(anchor_path.read_text(encoding="utf-8")) == corrupted


def test_audit_anchor_writes_and_refresh_reject_unsafe_file_shapes(app, tmp_path):
    from app.security.audit import refresh_audit_log_anchor, write_audit_log_anchor

    directory_target = tmp_path / "anchor-directory"
    directory_target.mkdir()
    with pytest.raises(RuntimeError, match="regular file"):
        write_audit_log_anchor(directory_target)

    malformed = tmp_path / "malformed.anchor"
    malformed.write_text("{", encoding="utf-8")
    object_list = tmp_path / "list.anchor"
    object_list.write_text("[]", encoding="utf-8")
    if os.name != "nt":
        malformed.chmod(0o600)
        object_list.chmod(0o600)

    with pytest.raises(RuntimeError, match="unreadable or malformed"):
        refresh_audit_log_anchor(malformed)
    with pytest.raises(RuntimeError, match="JSON object"):
        refresh_audit_log_anchor(object_list)


def test_security_alert_rebaseline_is_acknowledged_audited_and_atomic(
    app,
    tmp_path,
):
    from app.security.audit import audit_event, write_audit_log_anchor

    anchor_path = tmp_path / "security-audit.anchor"
    state_path = tmp_path / "security-alert-state.json"
    app.config["SECURITY_AUDIT_ANCHOR_PATH"] = str(anchor_path)
    app.config["SECURITY_ALERT_STATE_PATH"] = str(state_path)
    with app.test_request_context("/audit/current", method="POST"):
        audit_event("rebaseline_current", "success")
    write_audit_log_anchor(anchor_path)
    stale_state = {
        "message": "security_alert_database_integrity_state",
        "version": 1,
        "generated_at": "2026-07-01T00:00:00Z",
        "tables": {
            "security_audit_events": {"count": 999, "max_id": 999},
            "users": {"count": 999, "max_id": 999},
        },
    }
    state_path.write_text(json.dumps(stale_state), encoding="utf-8")
    if os.name != "nt":
        state_path.chmod(0o600)

    runner = app.test_cli_runner()
    no_ack = runner.invoke(
        args=["rebaseline-security-alert-state", "--reason", "approved reset"]
    )
    no_reason = runner.invoke(
        args=["rebaseline-security-alert-state", "--intentional-reset"]
    )
    raw_reason = "Approved staging reset; fake ticket SEC-411"
    completed = runner.invoke(
        args=[
            "rebaseline-security-alert-state",
            "--intentional-reset",
            "--reason",
            raw_reason,
        ]
    )

    assert no_ack.exit_code != 0
    assert no_reason.exit_code != 0
    assert completed.exit_code == 0, completed.output
    payload = json.loads(completed.output)
    assert payload["message"] == "security_alert_state_rebaselined"
    assert payload["backup_path"]
    assert Path(payload["backup_path"]).exists()
    assert json.loads(Path(payload["backup_path"]).read_text(encoding="utf-8")) == stale_state
    assert raw_reason not in completed.output
    assert raw_reason not in state_path.read_text(encoding="utf-8")
    outcomes = [
        event.outcome
        for event in db.session.query(SecurityAuditEvent)
        .filter_by(event_type="security_alert_state_rebaseline")
        .order_by(SecurityAuditEvent.id)
    ]
    assert outcomes == ["started", "completed"]
    assert all(
        raw_reason not in json.dumps(event.event_metadata)
        for event in db.session.query(SecurityAuditEvent).all()
    )


def test_security_alert_rebaseline_restores_backup_when_atomic_write_fails(
    app,
    tmp_path,
    monkeypatch,
):
    from app.security import alerts
    from app.security.audit import audit_event, write_audit_log_anchor

    anchor_path = tmp_path / "security-audit.anchor"
    state_path = tmp_path / "security-alert-state.json"
    app.config["SECURITY_AUDIT_ANCHOR_PATH"] = str(anchor_path)
    app.config["SECURITY_ALERT_STATE_PATH"] = str(state_path)
    with app.test_request_context("/audit/current", method="POST"):
        audit_event("rebaseline_write_failure", "success")
    write_audit_log_anchor(anchor_path)
    original_state = {
        "message": "security_alert_database_integrity_state",
        "version": 1,
        "generated_at": "2026-07-01T00:00:00Z",
        "tables": {
            "security_audit_events": {"count": 99, "max_id": 99},
            "users": {"count": 99, "max_id": 99},
        },
    }
    state_path.write_text(json.dumps(original_state), encoding="utf-8")
    if os.name != "nt":
        state_path.chmod(0o600)
    monkeypatch.setattr(
        alerts,
        "_write_database_integrity_state",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            alerts.AlertConfigurationError("fake atomic write failure")
        ),
    )

    with pytest.raises(
        alerts.AlertConfigurationError,
        match="fake atomic write failure",
    ):
        alerts.rebaseline_database_integrity_state(
            intentional_reset=True,
            reason="Approved fake recovery drill",
        )

    assert json.loads(state_path.read_text(encoding="utf-8")) == original_state
    outcomes = [
        event.outcome
        for event in db.session.query(SecurityAuditEvent)
        .filter_by(event_type="security_alert_state_rebaseline")
        .order_by(SecurityAuditEvent.id)
    ]
    assert outcomes == ["started", "failed"]


def test_security_alert_rebaseline_refuses_blank_reason_and_missing_paths(
    app,
    tmp_path,
):
    from app.security import alerts

    with app.app_context():
        with pytest.raises(alerts.AlertConfigurationError, match="non-empty"):
            alerts.rebaseline_database_integrity_state(
                intentional_reset=True,
                reason="",
            )

        app.config["SECURITY_ALERT_STATE_PATH"] = None
        app.config["SECURITY_AUDIT_ANCHOR_PATH"] = None
        with pytest.raises(alerts.AlertConfigurationError, match="STATE_PATH"):
            alerts.rebaseline_database_integrity_state(
                intentional_reset=True,
                reason="Approved fake reset",
            )

        app.config["SECURITY_ALERT_STATE_PATH"] = str(tmp_path / "state.json")
        with pytest.raises(alerts.AlertConfigurationError, match="ANCHOR_PATH"):
            alerts.rebaseline_database_integrity_state(
                intentional_reset=True,
                reason="Approved fake reset",
            )

def test_security_alert_evaluator_cli_and_output_are_sanitized(app):
    from app.security.alerts import evaluate_security_alerts
    from app.security.audit import audit_event, audit_reference, principal_reference

    raw_identifier = "Victim.User@example.com"
    raw_password = "plain-password"
    raw_token = "Bearer webhook-token-secret"
    raw_account = "1234 5678 9012 3456"
    raw_transaction = "TXN-SECRET-001"
    principal_ref = principal_reference(raw_identifier)
    transaction_ref = audit_reference("transaction", raw_transaction)

    with app.test_request_context(
        "/auth/login",
        method="POST",
        environ_overrides={"REMOTE_ADDR": "198.51.100.50"},
    ):
        for _attempt in range(10):
            audit_event(
                "login",
                "failure",
                metadata={"principal_ref": principal_ref, "password": raw_password},
            )
        for _attempt in range(5):
            audit_event("rate_limit", "blocked", metadata={"authorization": raw_token})
        audit_event("security_audit_write_failed", "failure", metadata={"token": raw_token})
        audit_event("account_lock", "locked", metadata={"reason": "mfa_failed"})
        audit_event("account_freeze", "success", metadata={"reason": "customer_requested"})
        audit_event("session_integrity", "failure", metadata={"reason": "invalid_signature"})

    with app.test_request_context(
        "/banking/transactions",
        method="POST",
        environ_overrides={"REMOTE_ADDR": "198.51.100.51"},
    ):
        for _attempt in range(10):
            audit_event(
                "banking_transaction_authorization",
                "failure",
                user_id=7,
                metadata={
                    "transaction_ref": transaction_ref,
                    "payee_account": raw_account,
                },
            )

    alerts = evaluate_security_alerts()
    alert_types = {alert["alert_type"] for alert in alerts}
    serialized_alerts = json.dumps(alerts, sort_keys=True)
    report_only = app.test_cli_runner().invoke(
        args=["check-security-alerts", "--report-only", "--no-delivery"]
    )
    strict = app.test_cli_runner().invoke(args=["check-security-alerts", "--no-delivery"])

    for expected in (
        "security_audit_write_failed",
        "account_lock",
        "account_freeze",
        "session_integrity_failure",
        "login_failure_burst",
        "auth_backoff_or_rate_limit_burst",
        "transaction_failure_burst",
        "transaction_failure_global_burst",
    ):
        assert expected in alert_types
    for forbidden in (
        raw_identifier,
        raw_password,
        "webhook-token-secret",
        raw_account,
        raw_transaction,
    ):
        assert forbidden not in serialized_alerts
        assert forbidden not in report_only.output
    assert report_only.exit_code == 0, report_only.output
    assert json.loads(report_only.output)["alert_count"] >= len(alert_types)
    assert strict.exit_code != 0

def test_security_alert_webhook_delivery_is_sanitized(monkeypatch):
    from app.security.alerts import deliver_security_alerts

    captured = {}

    class FakeResponse:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["body"] = request.data.decode("utf-8")
        captured["user_agent"] = request.headers["User-agent"]
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("app.security.alerts.urllib.request.urlopen", fake_urlopen)
    alerts = [
        {
            "alert_type": "login_failure_burst",
            "severity": "high",
            "count": 10,
            "window_seconds": 300,
            "source": "principal_ref:abc123",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    ]
    result = deliver_security_alerts(
        alerts,
        webhook_url="https://hooks.example.test/services/secret-token",
    )
    serialized_result = json.dumps(result, sort_keys=True)

    assert result["attempted"] is True
    assert result["delivered"] is True
    assert captured["url"].endswith("/secret-token")
    assert captured["user_agent"] == "SITBank-SecurityAlerts/1.0"
    assert "secret-token" not in captured["body"]
    assert "secret-token" not in serialized_result

    def failing_urlopen(_request, timeout):
        del timeout
        raise RuntimeError("secret-token leaked by transport")

    monkeypatch.setattr("app.security.alerts.urllib.request.urlopen", failing_urlopen)
    failed = deliver_security_alerts(
        alerts,
        webhook_url="https://hooks.example.test/services/secret-token",
    )

    assert failed["delivered"] is False
    assert failed["error_type"] == "RuntimeError"
    assert "secret-token" not in json.dumps(failed, sort_keys=True)

    invalid_scheme = deliver_security_alerts(alerts, webhook_url="file:///tmp/secret-token")
    assert invalid_scheme["delivered"] is False
    assert invalid_scheme["error_type"] == "AlertConfigurationError"
    assert "secret-token" not in json.dumps(invalid_scheme, sort_keys=True)

def test_security_alert_webhook_delivery_redacts_final_payload_fields(monkeypatch):
    from app.security.alerts import deliver_security_alerts

    captured_bodies = []

    class FakeResponse:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

    def fake_urlopen(request, timeout):
        del timeout
        captured_bodies.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("app.security.alerts.urllib.request.urlopen", fake_urlopen)
    long_token = "alerttoken" + ("A1" * 24)
    private_key_marker = "BEGIN " + "PRIVATE KEY fake material"
    alert = {
        "alert_type": "manual_security_alert",
        "severity": "critical",
        "summary": "safe summary",
        "generated_at": "2026-06-19T08:00:00Z",
        "display_timestamp": "2026-06-19 16:00:00 UTC+8",
        "correlation_id": "corr-123",
        "public_session_ref": "public-session-ref-123",
        "safe_user_identifier": "user:7",
        "password": "plain-password",
        "Authorization": "Bearer authorization-secret",
        "cookie": "session=cookie-secret",
        "mfa_secret": "mfa-secret",
        "totp_secret": "totp-secret",
        "api_key": "api-secret",
        "private_key": private_key_marker,
        "database_url": "postgresql://user:postgres-password@db/sitbank",
        "redis_url": "redis://:redis-password@redis:6379/0",
        "webhook_url": "https://hooks.example.test/services/webhook-secret",
        "password_reset_token": "password-reset-token-secret",
        "session_id": "session-id-secret",
        "totp_code": "123456",
        "recovery_codes": ["recovery-code-one", "recovery-code-two"],
        "authentication_challenge": "authentication-challenge-secret",
        "authentication_assertion": {
            "clientDataJSON": "client-data-json-secret",
            "authenticatorData": "authenticator-data-secret",
            "signature": "signature-secret",
        },
        "hmac_key": "session-hmac-key-secret",
        "mfa_kek": "mfa-kek-secret",
        "smtp_username": "smtp-user-secret",
        "smtp_password": "smtp-password-secret",
        "nested": {
            "refresh_token": long_token,
            "Authorization": "Basic nested-authorization-secret",
            "note": "safe nested note",
        },
        "list_values": [
            {"csrf_token": "csrf-secret"},
            {"recovery_code": "nested-recovery-code-secret"},
            "safe list note",
        ],
    }
    original_alert = json.loads(json.dumps(alert, sort_keys=True))

    generic = deliver_security_alerts(
        [alert],
        webhook_url="https://hooks.example.test/services/delivery-secret",
    )
    discord = deliver_security_alerts(
        [alert],
        webhook_url="https://discord.com/api/webhooks/123456789012345678/delivery-secret",
    )

    generic_payload = captured_bodies[0]
    discord_payload = captured_bodies[1]
    serialized_generic = json.dumps(generic_payload, sort_keys=True)
    serialized_discord = json.dumps(discord_payload, sort_keys=True)

    assert generic["delivered"] is True
    assert discord["delivered"] is True
    assert alert == original_alert
    delivered_alert = generic_payload["alerts"][0]
    assert delivered_alert["severity"] == "critical"
    assert delivered_alert["summary"] == "safe summary"
    assert delivered_alert["generated_at"] == "2026-06-19T08:00:00Z"
    assert delivered_alert["display_timestamp"] == "2026-06-19 16:00:00 UTC+8"
    assert delivered_alert["correlation_id"] == "corr-123"
    assert delivered_alert["public_session_ref"] == "public-session-ref-123"
    assert delivered_alert["safe_user_identifier"] == "user:7"
    assert delivered_alert["password"] == "[redacted]"
    assert delivered_alert["Authorization"] == "[redacted]"
    assert delivered_alert["cookie"] == "[redacted]"
    assert delivered_alert["mfa_secret"] == "[redacted]"
    assert delivered_alert["totp_secret"] == "[redacted]"
    assert delivered_alert["api_key"] == "[redacted]"
    assert delivered_alert["private_key"] == "[redacted]"
    assert delivered_alert["database_url"] == "[redacted]"
    assert delivered_alert["redis_url"] == "[redacted]"
    assert delivered_alert["webhook_url"] == "[redacted]"
    assert delivered_alert["password_reset_token"] == "[redacted]"
    assert delivered_alert["session_id"] == "[redacted]"
    assert delivered_alert["totp_code"] == "[redacted]"
    assert delivered_alert["recovery_codes"] == "[redacted]"
    assert delivered_alert["authentication_challenge"] == "[redacted]"
    assert delivered_alert["authentication_assertion"] == "[redacted]"
    assert delivered_alert["hmac_key"] == "[redacted]"
    assert delivered_alert["mfa_kek"] == "[redacted]"
    assert delivered_alert["smtp_username"] == "[redacted]"
    assert delivered_alert["smtp_password"] == "[redacted]"
    assert delivered_alert["nested"]["refresh_token"] == "[redacted]"
    assert delivered_alert["nested"]["Authorization"] == "[redacted]"
    assert delivered_alert["nested"]["note"] == "safe nested note"
    assert delivered_alert["list_values"][0]["csrf_token"] == "[redacted]"
    assert delivered_alert["list_values"][1]["recovery_code"] == "[redacted]"
    assert delivered_alert["list_values"][2] == "safe list note"
    assert discord_payload["allowed_mentions"] == {"parse": []}
    assert discord_payload["embeds"][0]["fields"][0]["name"] == "CRITICAL | manual_security_alert"
    for forbidden in (
        "plain-password",
        "authorization-secret",
        "cookie-secret",
        "mfa-secret",
        "totp-secret",
        "api-secret",
        "PRIVATE KEY fake material",
        "postgres-password",
        "redis-password",
        "webhook-secret",
        "delivery-secret",
        long_token,
        "password-reset-token-secret",
        "session-id-secret",
        "123456",
        "recovery-code-one",
        "recovery-code-two",
        "authentication-challenge-secret",
        "client-data-json-secret",
        "authenticator-data-secret",
        "signature-secret",
        "session-hmac-key-secret",
        "mfa-kek-secret",
        "smtp-user-secret",
        "smtp-password-secret",
        "nested-authorization-secret",
        "nested-recovery-code-secret",
    ):
        assert forbidden not in serialized_generic
        assert forbidden not in serialized_discord

def test_security_alert_delivery_formats_discord_webhooks(monkeypatch):
    from app.security.alerts import deliver_security_alerts

    captured = {}

    class FakeResponse:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

    def fake_urlopen(request, timeout):
        del timeout
        captured["body"] = request.data.decode("utf-8")
        captured["content_type"] = request.headers["Content-type"]
        captured["user_agent"] = request.headers["User-agent"]
        return FakeResponse()

    monkeypatch.setattr("app.security.alerts.urllib.request.urlopen", fake_urlopen)
    alerts = [
        {
            "alert_type": "login_failure_burst",
            "severity": "critical",
            "count": 10,
            "window_seconds": 300,
            "source": "principal_ref:abc123",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    ]
    result = deliver_security_alerts(
        alerts,
        webhook_url="https://discord.com/api/webhooks/123456789012345678/example-secret-token",
    )
    payload = json.loads(captured["body"])
    serialized_result = json.dumps(result, sort_keys=True)
    serialized_payload = json.dumps(payload, sort_keys=True)

    assert result["attempted"] is True
    assert result["delivered"] is True
    assert result["provider"] == "discord"
    assert captured["content_type"] == "application/json"
    assert captured["user_agent"] == "SITBank-SecurityAlerts/1.0"
    assert payload["allowed_mentions"] == {"parse": []}
    assert payload["content"] == "SITBank security alerts: 1 active"
    assert payload["embeds"][0]["title"] == "SITBank Security Alerts"
    assert payload["embeds"][0]["color"] == 0xD92D20
    assert "Date: " in payload["embeds"][0]["description"]
    assert "Time: " in payload["embeds"][0]["description"]
    assert "Timezone: UTC+8" in payload["embeds"][0]["description"]
    assert payload["embeds"][0]["fields"][0]["name"] == "CRITICAL | login_failure_burst"
    assert "Source: principal_ref:abc123" in payload["embeds"][0]["fields"][0]["value"]
    assert "Count: 10" in payload["embeds"][0]["fields"][0]["value"]
    assert "Window: 5 minute(s)" in payload["embeds"][0]["fields"][0]["value"]
    assert "example-secret-token" not in serialized_payload
    assert "example-secret-token" not in serialized_result

def test_security_alert_config_validation_and_db_dedupe(app, monkeypatch):
    from app.security.alerts import (
        AlertConfigurationError,
        build_security_alert_report,
        validate_security_alert_config,
    )
    from app.security.audit import audit_event, principal_reference
    from app.models import SecurityAlertDedupe

    captured_bodies = []

    class FakeResponse:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

    def fake_urlopen(request, timeout):
        captured_bodies.append(json.loads(request.data.decode("utf-8")))
        assert timeout == 3.0
        return FakeResponse()

    app.config.update(
        SECURITY_ALERT_ENABLED=True,
        SECURITY_ALERT_WEBHOOK_URL="https://hooks.example.test/sitbank-security-alerts",
        SECURITY_ALERT_MIN_SEVERITY="high",
        SECURITY_ALERT_TIMEOUT_SECONDS=3.0,
        SECURITY_ALERT_DEDUPE_TTL_SECONDS=300,
    )
    monkeypatch.setattr("app.security.alerts.urllib.request.urlopen", fake_urlopen)

    with app.test_request_context(
        "/auth/login",
        method="POST",
        environ_overrides={"REMOTE_ADDR": "198.51.100.90"},
    ):
        principal_ref = principal_reference("victim@example.com")
        for _attempt in range(10):
            audit_event("login", "failure", metadata={"principal_ref": principal_ref})

    first_report = build_security_alert_report(deliver=True)
    second_report = build_security_alert_report(deliver=True)
    with app.test_request_context("/ops/check", method="POST"):
        audit_event("account_lock", "locked", metadata={"reason": "mfa_failed"})
    third_report = build_security_alert_report(deliver=True)

    assert first_report["delivery"]["attempted"] is True
    assert first_report["dedupe"]["suppressed"] == 0
    assert second_report["delivery"]["deduped"] is True
    assert second_report["dedupe"]["suppressed"] >= 1
    assert third_report["delivery"]["attempted"] is True
    assert len(captured_bodies) == 2
    assert db.session.query(SecurityAlertDedupe).count() >= 1

    with pytest.raises(AlertConfigurationError, match="WEBHOOK"):
        validate_security_alert_config(
            require_delivery=True,
            environ={"APP_ENV": "production", "SECURITY_ALERT_ENABLED": "true"},
        )
    with pytest.raises(AlertConfigurationError, match="HTTPS"):
        validate_security_alert_config(
            require_delivery=True,
            environ={
                "APP_ENV": "production",
                "SECURITY_ALERT_ENABLED": "true",
                "SECURITY_ALERT_WEBHOOK_URL": "http://hooks.example.test/insecure",
            },
        )
    with pytest.raises(AlertConfigurationError, match="MIN_SEVERITY"):
        validate_security_alert_config(environ={"SECURITY_ALERT_MIN_SEVERITY": "urgent"})
    with pytest.raises(AlertConfigurationError, match="TIMEOUT"):
        validate_security_alert_config(environ={"SECURITY_ALERT_TIMEOUT_SECONDS": "0"})
    with pytest.raises(AlertConfigurationError, match="DEDUPE"):
        validate_security_alert_config(environ={"SECURITY_ALERT_DEDUPE_TTL_SECONDS": "1"})

def test_500_handler_logs_sanitized_context(mutable_app, caplog):
    mutable_app.config["PROPAGATE_EXCEPTIONS"] = False

    @mutable_app.post("/explode")
    def explode():
        raise RuntimeError("boom")

    caplog.set_level("ERROR", logger=mutable_app.logger.name)
    response = mutable_app.test_client().post(
        "/explode?password=query-secret",
        data={"password": "form-secret"},
        headers={
            "Authorization": "Bearer header-secret",
            "Cookie": "session=cookie-secret",
        },
    )

    logs = "\n".join(record.getMessage() for record in caplog.records)
    payload = log_payloads(caplog, "system_error")[-1]

    assert response.status_code == 500
    assert payload["path"] == "/explode"
    assert payload["method"] == "POST"
    assert payload["exception_type"] == "RuntimeError"
    assert payload["correlation_id"]
    for forbidden in (
        "query-secret",
        "form-secret",
        "header-secret",
        "cookie-secret",
    ):
        assert forbidden not in logs
