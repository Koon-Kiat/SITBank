from __future__ import annotations

import time

import pytest

from app.security.alerts import _sanitize_alert_for_delivery
from app.security.audit import _sanitize_metadata
from app.security.sensitive_values import (
    contains_credential_url,
    contains_sensitive_url,
    contains_webhook_url,
)


@pytest.mark.parametrize(
    "value",
    (
        "postgresql://user:password@db/sitbank",
        "prefix redis://:password@redis:6379/0 suffix",
        "POSTGRES://service:secret@db/sitbank",
        "Straße POSTGRESQL://service:secret@db/sitbank",
    ),
)
def test_credential_url_scanner_detects_supported_urls(value):
    assert contains_credential_url(value)
    assert contains_sensitive_url(value)


@pytest.mark.parametrize(
    "value",
    (
        "xpostgresql://user:password@db/sitbank",
        "postgresql://user@db/sitbank",
        "postgresql://user:password/db@sitbank",
        "redis://cache:6379/0",
    ),
)
def test_credential_url_scanner_rejects_noncredential_text(value):
    assert not contains_credential_url(value)


@pytest.mark.parametrize(
    "value",
    (
        "https://hooks.example.test/services/webhook-secret",
        "https://discord.com/api/webhooks/1234567890/webhook-secret",
        "HTTPS://DISCORDAPP.COM/SERVICES/webhook-secret",
        "Straße HTTPS://HOOKS.EXAMPLE.TEST/SERVICES/webhook-secret",
    ),
)
def test_webhook_url_scanner_detects_supported_urls(value):
    assert contains_webhook_url(value)
    assert contains_sensitive_url(value)


@pytest.mark.parametrize(
    "value",
    (
        "http://hooks.example.test/services/webhook-secret",
        "https://discord.example.test/api/webhooks/123/secret",
        "https://example.test/services/webhook-secret",
        "https://hooks.example.test/services/",
        "https://hooks.example.test bad/services/webhook-secret",
        "https://hooks.example.test/not-a-webhook/secret",
    ),
)
def test_webhook_url_scanner_rejects_unrelated_urls(value):
    assert not contains_webhook_url(value)


@pytest.mark.parametrize(
    "value",
    (
        "postgresql://user:" + ("a:" * 50_000),
        "https://" + ("hookshooks" * 10_000),
    ),
    ids=("credential", "webhook"),
)
def test_sensitive_url_scanner_rejects_long_attack_text_quickly(value):
    started = time.perf_counter()

    assert not contains_sensitive_url(value)

    assert time.perf_counter() - started < 0.5


@pytest.mark.parametrize(
    ("sanitize", "limit"),
    (
        (_sanitize_metadata, 256),
        (_sanitize_alert_for_delivery, 512),
    ),
)
def test_sanitizers_scan_full_values_before_applying_output_limits(sanitize, limit):
    credential_url = "postgresql://user:" + ("p" * (limit * 2)) + "@db/sitbank"
    webhook_url = "https://hooks.example.test/services/" + ("s" * (limit * 2))

    assert sanitize({"reason": credential_url})["reason"] == "[redacted]"
    assert sanitize({"reason": webhook_url})["reason"] == "[redacted]"


@pytest.mark.parametrize(
    ("sanitize", "limit"),
    (
        (_sanitize_metadata, 256),
        (_sanitize_alert_for_delivery, 512),
    ),
)
def test_sanitizers_bound_long_nonsensitive_output(sanitize, limit):
    sanitized = sanitize({"reason": "a" * (limit * 2)})

    assert sanitized["reason"] == "a" * limit
