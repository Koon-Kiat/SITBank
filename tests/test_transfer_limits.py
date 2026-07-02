from __future__ import annotations

import time
from decimal import Decimal

import pytest
import pyotp

from _auth_flow_helpers import enable_mfa_for_user, login, mark_recent_mfa, register
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


def test_transfer_limits_post_updates_with_valid_preset_and_totp(client, limits_context, monkeypatch):
    alice_secret = limits_context["alice_secret"]
    code = _fresh_totp(alice_secret, monkeypatch)

    response = client.post(
        "/banking/settings/transfer-limits",
        data={"payup_limit": "1000", "totp_code": code},
    )

    assert response.status_code == 302
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.payup_daily_limit)) == Decimal("1000")


def test_transfer_limits_post_custom_amount_above_100_succeeds(client, limits_context, monkeypatch):
    alice_secret = limits_context["alice_secret"]
    code = _fresh_totp(alice_secret, monkeypatch)

    response = client.post(
        "/banking/settings/transfer-limits",
        data={"payup_limit": "custom", "payup_limit_custom": "750.00", "totp_code": code},
    )

    assert response.status_code == 302
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.payup_daily_limit)) == Decimal("750.00")


def test_transfer_limits_post_custom_amount_not_above_100_rejected(client, limits_context, monkeypatch):
    alice_secret = limits_context["alice_secret"]
    code = _fresh_totp(alice_secret, monkeypatch)

    response = client.post(
        "/banking/settings/transfer-limits",
        data={"payup_limit": "custom", "payup_limit_custom": "100.00", "totp_code": code},
    )

    assert response.status_code == 400
    assert b"greater than SGD 100" in response.data
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.payup_daily_limit)) == Decimal("500.00")


def test_transfer_limits_post_missing_totp_fails_closed(client, limits_context):
    response = client.post(
        "/banking/settings/transfer-limits",
        data={"payup_limit": "1000"},
    )

    assert response.status_code == 400
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.payup_daily_limit)) == Decimal("500.00")


def test_transfer_limits_post_wrong_totp_fails_closed(client, limits_context):
    response = client.post(
        "/banking/settings/transfer-limits",
        data={"payup_limit": "1000", "totp_code": "000000"},
    )

    assert response.status_code == 401
    db.session.expire_all()
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert Decimal(str(alice.payup_daily_limit)) == Decimal("500.00")
