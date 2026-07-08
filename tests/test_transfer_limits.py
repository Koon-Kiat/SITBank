from __future__ import annotations

import time
from decimal import Decimal

import pytest
import pyotp

from _auth_flow_helpers import enable_mfa_for_user, login, mark_recent_mfa, register
from app.auth.services import AuthError
from app.banking.limits import (
    LOCAL_TRANSFER_DAILY_LIMIT_MAX,
    LOCAL_TRANSFER_DAILY_LIMIT_MIN,
    PAYUP_DAILY_LIMIT_MAX,
    PAYUP_DAILY_LIMIT_MIN,
)
from app.banking.services import resolve_local_transfer_limit_choice, resolve_transfer_limit_choice
from app.extensions import db
from app.models import User


@pytest.fixture()
def limits_context(client):
    register(client, username="alice01", email="alice@example.com", full_name="Alice Sender", phone_number="91234567")
    login(client, identifier="alice01")
    alice, alice_secret = enable_mfa_for_user("alice01")
    mark_recent_mfa(client, alice)
    return {"alice": alice, "alice_secret": alice_secret}


def _fresh_totp(secret: str, monkeypatch) -> str:
    stepup_time = int(time.time())
    code = pyotp.TOTP(secret, digits=6, interval=30).at(stepup_time)
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)
    return code


def test_transfer_limits_get_preselects_default_preset(client, limits_context):
    response = client.get("/banking/settings/transfer-limits")

    assert response.status_code == 200
    assert b'selected value="500"' in response.data


def test_transfer_limits_get_preselects_custom_for_nonpreset_value(client, limits_context):
    alice = limits_context["alice"]
    alice.payup_daily_limit = Decimal("750.00")
    db.session.commit()

    response = client.get("/banking/settings/transfer-limits")

    assert response.status_code == 200
    assert b'selected value="custom"' in response.data
    assert b'value="750.00"' in response.data


def test_transfer_limits_get_preselects_local_transfer_default_preset(client, limits_context):
    response = client.get("/banking/settings/transfer-limits")

    assert response.status_code == 200
    assert b'name="local_transfer_limit"' in response.data


def test_transfer_limits_get_preselects_custom_for_nonpreset_local_transfer_value(client, limits_context):
    alice = limits_context["alice"]
    alice.local_transfer_daily_limit = Decimal("750.00")
    db.session.commit()

    response = client.get("/banking/settings/transfer-limits")

    assert response.status_code == 200
    assert b'name="local_transfer_limit_custom"' in response.data
    assert b'value="750.00"' in response.data


def test_transfer_limits_post_updates_with_valid_preset_and_totp(client, limits_context, monkeypatch):
    from app.security.email import password_reset_outbox

    alice = limits_context["alice"]
    alice.transfer_activity_email_enabled = False
    db.session.commit()
    before_count = len(password_reset_outbox())
    alice_secret = limits_context["alice_secret"]
    code = _fresh_totp(alice_secret, monkeypatch)

    response = client.post(
        "/banking/settings/transfer-limits",
        data={"payup_limit": "1000", "local_transfer_limit": "500", "totp_code": code},
    )

    assert response.status_code == 302
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.payup_daily_limit)) == Decimal("1000")
    deliveries = password_reset_outbox()[before_count:]
    assert [item["subject"] for item in deliveries] == [
        "SITBank transfer limit change successful",
    ]
    delivery = deliveries[0]
    assert delivery["to"] == "alice@example.com"
    assert "we updated your daily limit for PayUp from SGD 500.00 to SGD 1,000.00" in delivery["body"]
    assert "Local Transfer" not in delivery["body"]


def test_transfer_limits_post_updates_both_channels_lists_both_in_email(client, limits_context, monkeypatch):
    from app.security.email import password_reset_outbox

    alice = limits_context["alice"]
    before_count = len(password_reset_outbox())
    alice_secret = limits_context["alice_secret"]
    code = _fresh_totp(alice_secret, monkeypatch)

    response = client.post(
        "/banking/settings/transfer-limits",
        data={"payup_limit": "1000", "local_transfer_limit": "custom", "local_transfer_limit_custom": "750", "totp_code": code},
    )

    assert response.status_code == 302
    deliveries = password_reset_outbox()[before_count:]
    delivery = deliveries[-1]
    assert delivery["subject"] == "SITBank transfer limit change successful"
    assert "we updated your daily limit for PayUp from SGD 500.00 to SGD 1,000.00" in delivery["body"]
    assert "we updated your daily limit for Local Transfer from SGD 500.00 to SGD 750.00" in delivery["body"]


def test_transfer_limits_post_custom_amount_above_100_succeeds(client, limits_context, monkeypatch):
    alice_secret = limits_context["alice_secret"]
    code = _fresh_totp(alice_secret, monkeypatch)

    response = client.post(
        "/banking/settings/transfer-limits",
        data={
            "payup_limit": "custom",
            "payup_limit_custom": "750.00",
            "local_transfer_limit": "500",
            "totp_code": code,
        },
    )

    assert response.status_code == 302
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.payup_daily_limit)) == Decimal("750.00")


def test_transfer_limits_post_custom_amount_at_minimum_succeeds(client, limits_context, monkeypatch):
    alice_secret = limits_context["alice_secret"]
    code = _fresh_totp(alice_secret, monkeypatch)

    response = client.post(
        "/banking/settings/transfer-limits",
        data={
            "payup_limit": "custom",
            "payup_limit_custom": "100.00",
            "local_transfer_limit": "500",
            "totp_code": code,
        },
    )

    assert response.status_code == 302
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.payup_daily_limit)) == PAYUP_DAILY_LIMIT_MIN


def test_transfer_limits_post_custom_amount_below_minimum_rejected(client, limits_context, monkeypatch):
    alice_secret = limits_context["alice_secret"]
    code = _fresh_totp(alice_secret, monkeypatch)

    response = client.post(
        "/banking/settings/transfer-limits",
        data={
            "payup_limit": "custom",
            "payup_limit_custom": "99.99",
            "local_transfer_limit": "500",
            "totp_code": code,
        },
    )

    assert response.status_code == 400
    assert b"at least SGD 100.00" in response.data
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.payup_daily_limit)) == Decimal("500.00")


def test_transfer_limits_post_custom_amount_above_maximum_rejected(client, limits_context, monkeypatch):
    alice_secret = limits_context["alice_secret"]
    code = _fresh_totp(alice_secret, monkeypatch)

    response = client.post(
        "/banking/settings/transfer-limits",
        data={
            "payup_limit": "custom",
            "payup_limit_custom": "10000.01",
            "local_transfer_limit": "500",
            "totp_code": code,
        },
    )

    assert response.status_code == 400
    assert b"must not exceed SGD 10000.00" in response.data
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.payup_daily_limit)) == Decimal("500.00")


@pytest.mark.parametrize(
    ("choice", "custom_value", "expected"),
    [
        ("100", None, PAYUP_DAILY_LIMIT_MIN),
        ("custom", "100.00", PAYUP_DAILY_LIMIT_MIN),
        ("custom", "10000.00", PAYUP_DAILY_LIMIT_MAX),
        ("custom", "750.55", Decimal("750.55")),
    ],
)
def test_transfer_limit_resolver_accepts_bounded_values(choice, custom_value, expected):
    assert resolve_transfer_limit_choice(choice, custom_value) == expected


@pytest.mark.parametrize(
    ("choice", "custom_value"),
    [
        ("custom", ""),
        ("custom", "99.99"),
        ("custom", "10000.01"),
        ("custom", "750.001"),
        ("custom", "not-a-number"),
        ("custom", "NaN"),
        ("custom", "Infinity"),
        ("bogus", "750.00"),
    ],
)
def test_transfer_limit_resolver_rejects_unbounded_or_malformed_values(choice, custom_value):
    with pytest.raises(AuthError):
        resolve_transfer_limit_choice(choice, custom_value)


@pytest.mark.parametrize(
    ("choice", "custom_value", "expected"),
    [
        ("100", None, LOCAL_TRANSFER_DAILY_LIMIT_MIN),
        ("custom", "100.00", LOCAL_TRANSFER_DAILY_LIMIT_MIN),
        ("custom", "10000.00", LOCAL_TRANSFER_DAILY_LIMIT_MAX),
        ("custom", "750.55", Decimal("750.55")),
    ],
)
def test_local_transfer_limit_resolver_accepts_bounded_values(choice, custom_value, expected):
    assert resolve_local_transfer_limit_choice(choice, custom_value) == expected


@pytest.mark.parametrize(
    ("choice", "custom_value"),
    [
        ("custom", ""),
        ("custom", "99.99"),
        ("custom", "10000.01"),
        ("custom", "750.001"),
        ("custom", "not-a-number"),
        ("custom", "NaN"),
        ("custom", "Infinity"),
        ("bogus", "750.00"),
    ],
)
def test_local_transfer_limit_resolver_rejects_unbounded_or_malformed_values(choice, custom_value):
    with pytest.raises(AuthError):
        resolve_local_transfer_limit_choice(choice, custom_value)


def test_transfer_limits_post_missing_totp_fails_closed(client, limits_context):
    response = client.post(
        "/banking/settings/transfer-limits",
        data={"payup_limit": "1000", "local_transfer_limit": "1000"},
    )

    assert response.status_code == 400
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.payup_daily_limit)) == Decimal("500.00")
    assert Decimal(str(alice.local_transfer_daily_limit)) == Decimal("500.00")


def test_transfer_limits_post_wrong_totp_fails_closed(client, limits_context):
    from app.security.email import password_reset_outbox

    alice = limits_context["alice"]
    alice.transfer_activity_email_enabled = False
    db.session.commit()
    before_count = len(password_reset_outbox())

    response = client.post(
        "/banking/settings/transfer-limits",
        data={"payup_limit": "1000", "local_transfer_limit": "1000", "totp_code": "000000"},
    )

    assert response.status_code == 401
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.payup_daily_limit)) == Decimal("500.00")
    assert Decimal(str(alice.local_transfer_daily_limit)) == Decimal("500.00")
    deliveries = password_reset_outbox()[before_count:]
    assert [item["subject"] for item in deliveries] == [
        "SITBank transfer limit change unsuccessful",
    ]
    delivery = deliveries[0]
    assert delivery["to"] == "alice@example.com"


def test_transfer_limits_post_updates_local_transfer_limit_with_valid_preset_and_totp(
    client, limits_context, monkeypatch
):
    alice_secret = limits_context["alice_secret"]
    code = _fresh_totp(alice_secret, monkeypatch)

    response = client.post(
        "/banking/settings/transfer-limits",
        data={"payup_limit": "500", "local_transfer_limit": "1000", "totp_code": code},
    )

    assert response.status_code == 302
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.local_transfer_daily_limit)) == Decimal("1000")


def test_transfer_limits_post_local_transfer_custom_amount_below_minimum_rejected(
    client, limits_context, monkeypatch
):
    alice_secret = limits_context["alice_secret"]
    code = _fresh_totp(alice_secret, monkeypatch)

    response = client.post(
        "/banking/settings/transfer-limits",
        data={
            "payup_limit": "500",
            "local_transfer_limit": "custom",
            "local_transfer_limit_custom": "99.99",
            "totp_code": code,
        },
    )

    assert response.status_code == 400
    assert b"at least SGD 100.00" in response.data
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.local_transfer_daily_limit)) == Decimal("500.00")
