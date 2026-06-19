from __future__ import annotations

import copy
import json

from app.models import SecurityAuditEvent
from app.security.audit import _sanitize_metadata


SENSITIVE_KEY_NAMES = (
    "password",
    "passwd",
    "new_password",
    "old_password",
    "token",
    "access_token",
    "refresh_token",
    "csrf",
    "csrf_token",
    "secret",
    "mfa_secret",
    "totp_secret",
    "totp",
    "challenge",
    "credential",
    "ciphertext",
    "cookie",
    "set_cookie",
    "set-cookie",
    "authorization",
    "bearer",
    "api_key",
    "apikey",
    "private_key",
    "webhook_url",
    "discord_webhook_url",
    "slack_webhook_url",
    "database_url",
    "postgres_url",
    "postgresql_url",
    "redis_url",
    "session_id",
    "sid",
    "redis_payload",
)


def test_audit_metadata_sensitive_top_level_keys_are_redacted():
    metadata = {
        key: f"raw-{key}-secret"
        for key in SENSITIVE_KEY_NAMES
    }

    sanitized = _sanitize_metadata(metadata)

    assert set(sanitized) == set(SENSITIVE_KEY_NAMES)
    assert all(value == "[redacted]" for value in sanitized.values())
    assert "raw-" not in json.dumps(sanitized, sort_keys=True)


def test_audit_metadata_sanitizes_nested_dicts_and_lists_without_mutating_input():
    private_key_marker = "BEGIN " + "PRIVATE KEY fake material"
    metadata = {
        "safe": "visible",
        "nested": {
            "password": "nested-password",
            "reason": "safe nested reason",
            "items": [
                {"token": "nested-token"},
                {"reason": "Bearer nested-bearer-token"},
                "safe list value",
            ],
        },
        "events": [
            {"cookie": "session=cookie-secret"},
            {"reason": private_key_marker},
            {"public_session_ref": "public-session-ref-123"},
        ],
    }
    original = copy.deepcopy(metadata)

    first = _sanitize_metadata(metadata)
    second = _sanitize_metadata(metadata)
    serialized = json.dumps(first, sort_keys=True)

    assert metadata == original
    assert first == second
    assert first["safe"] == "visible"
    assert first["nested"]["password"] == "[redacted]"
    assert first["nested"]["reason"] == "safe nested reason"
    assert first["nested"]["items"][0]["token"] == "[redacted]"
    assert first["nested"]["items"][1]["reason"] == "[redacted]"
    assert first["nested"]["items"][2] == "safe list value"
    assert first["events"][0]["cookie"] == "[redacted]"
    assert first["events"][1]["reason"] == "[redacted]"
    assert first["events"][2]["public_session_ref"] == "public-session-ref-123"
    for forbidden in (
        "nested-password",
        "nested-token",
        "nested-bearer-token",
        "cookie-secret",
        "PRIVATE KEY fake material",
    ):
        assert forbidden not in serialized


def test_audit_metadata_value_based_redaction_patterns():
    private_key_marker = "BEGIN " + "PRIVATE KEY fake material"
    rsa_private_key_marker = "BEGIN " + "RSA PRIVATE KEY fake material"
    long_token = "auditToken" + ("A1" * 24)
    metadata = {
        "bearer_value": "Bearer bearer-secret",
        "basic_value": "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "postgres_value": "postgresql://user:postgres-password@db/sitbank",
        "redis_value": "redis://:redis-password@redis:6379/0",
        "private_key_value": private_key_marker,
        "rsa_private_key_value": rsa_private_key_marker,
        "webhook_value": "https://hooks.example.test/services/webhook-secret",
        "discord_webhook_value": "https://discord.com/api/webhooks/1234567890/webhook-secret",
        "long_token_value": long_token,
        "control_text": "line-one\nline-two\r\x00line-three",
    }

    sanitized = _sanitize_metadata(metadata)
    serialized = json.dumps(sanitized, sort_keys=True)

    for key in (
        "bearer_value",
        "basic_value",
        "postgres_value",
        "redis_value",
        "private_key_value",
        "rsa_private_key_value",
        "webhook_value",
        "discord_webhook_value",
        "long_token_value",
    ):
        assert sanitized[key] == "[redacted]"
    assert sanitized["control_text"] == "line-one line-two line-three"
    for forbidden in (
        "bearer-secret",
        "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "postgres-password",
        "redis-password",
        "PRIVATE KEY fake material",
        "webhook-secret",
        long_token,
        "\n",
        "\r",
        "\x00",
    ):
        assert forbidden not in serialized


def test_audit_metadata_safe_fields_remain_useful_when_harmless():
    metadata = {
        "event_type": "login",
        "outcome": "success",
        "correlation_id": "corr-123",
        "session_ref": "session-ref-123",
        "public_session_ref": "public-session-ref-123",
        "user_id": 42,
        "ip_address": "203.0.113.10",
        "user_agent": "Mozilla/5.0 Test",
        "reason": "normal login",
        "credential_device_type": "single_device",
    }

    assert _sanitize_metadata(metadata) == metadata


def test_audit_metadata_safe_field_names_redact_sensitive_values_only():
    metadata = {
        "reason": "redis://:redis-password@redis:6379/0",
        "user_agent": "Bearer user-agent-token",
        "correlation_id": "corr-123",
        "session_ref": "session-ref-123",
        "public_session_ref": "public-session-ref-123",
    }

    sanitized = _sanitize_metadata(metadata)

    assert sanitized["reason"] == "[redacted]"
    assert sanitized["user_agent"] == "[redacted]"
    assert sanitized["correlation_id"] == "corr-123"
    assert sanitized["session_ref"] == "session-ref-123"
    assert sanitized["public_session_ref"] == "public-session-ref-123"


def test_audit_event_storage_and_logs_do_not_leak_sensitive_metadata(app, caplog):
    from app.security.audit import audit_event

    raw_values = (
        "plain-password",
        "postgres-password",
        "redis-password",
        "webhook-secret",
        "Bearer bearer-secret",
    )
    caplog.set_level("INFO", logger=app.logger.name)

    with app.test_request_context("/audit/sanitize", method="POST"):
        audit_event(
            "audit_metadata_sanitization",
            "success",
            metadata={
                "reason": "postgresql://user:postgres-password@db/sitbank",
                "nested": {
                    "password": "plain-password",
                    "redis": "redis://:redis-password@redis:6379/0",
                },
                "events": [
                    "https://hooks.example.test/services/webhook-secret",
                    "Bearer bearer-secret",
                ],
            },
        )

    event = (
        app.extensions["sqlalchemy"]
        .session.query(SecurityAuditEvent)
        .filter_by(event_type="audit_metadata_sanitization")
        .one()
    )
    serialized_event = json.dumps(event.event_metadata, sort_keys=True)
    serialized_logs = "\n".join(record.getMessage() for record in caplog.records)

    assert event.event_metadata["reason"] == "[redacted]"
    assert event.event_metadata["nested"]["password"] == "[redacted]"
    assert event.event_metadata["nested"]["redis"] == "[redacted]"
    assert event.event_metadata["events"] == ["[redacted]", "[redacted]"]
    for forbidden in raw_values:
        assert forbidden not in serialized_event
        assert forbidden not in serialized_logs
