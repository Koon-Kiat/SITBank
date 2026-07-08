from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pyotp

from _auth_flow_helpers import enable_mfa_for_user, login, register
from app.extensions import db
from app.models import KnownDevice, SecurityAuditEvent, User
from app.security.email import password_reset_outbox


def _known_devices(user_id: int):
    return (
        db.session.execute(db.select(KnownDevice).where(KnownDevice.user_id == user_id))
        .scalars()
        .all()
    )


def _login_with_totp(client, secret, *, identifier="alice01", step_offset=0):
    """Log in and complete MFA with a code from a distinct 30s time step.

    Repeated logins in the same test would otherwise reuse the same
    pyotp.now() code within one 30s window, which TOTP replay protection
    correctly rejects on the second attempt (matching the .at(timestamp)
    pattern already used elsewhere, e.g. tests/test_account_security_actions.py).
    """
    login_response = login(client, identifier=identifier)
    at_time = datetime.now(timezone.utc) + timedelta(seconds=30 * step_offset)
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(at_time)},
    )
    return login_response, mfa_response


def test_first_login_from_new_device_sends_mandatory_email_and_sets_cookie(client):
    register(client)
    user, secret = enable_mfa_for_user()
    client.post("/logout")

    before_count = len(password_reset_outbox())
    login_response, mfa_response = _login_with_totp(client, secret)

    assert login_response.status_code == 302
    assert mfa_response.status_code == 200
    assert "sitbank_device" in mfa_response.headers.get("Set-Cookie", "")

    devices = _known_devices(user.id)
    assert len(devices) == 1

    deliveries = password_reset_outbox()
    assert len(deliveries) == before_count + 1
    new_device_email = deliveries[-1]
    assert new_device_email["to"] == user.email
    assert new_device_email["subject"] == "SITBank new device sign-in"
    assert "terminate the current session" in new_device_email["body"]
    assert "freeze" in new_device_email["body"].casefold()

    assert (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="new_device_login_notification", outcome="queued", user_id=user.id)
        .count()
        == 1
    )


def test_known_device_reusing_cookie_does_not_send_second_email(client):
    register(client)
    user, secret = enable_mfa_for_user()
    client.post("/logout")
    _login_with_totp(client, secret, step_offset=0)

    devices_after_first = _known_devices(user.id)
    assert len(devices_after_first) == 1
    count_after_first = len(password_reset_outbox())

    client.post("/logout")
    login_response, mfa_response = _login_with_totp(client, secret, step_offset=1)
    assert mfa_response.status_code == 200

    devices_after_second = _known_devices(user.id)
    assert len(devices_after_second) == 1
    assert devices_after_second[0].id == devices_after_first[0].id
    assert len(password_reset_outbox()) == count_after_first


def test_cookie_from_different_user_is_treated_as_new_device(client):
    register(client, username="alice01", email="alice@example.com", phone_number="91234567")
    alice, alice_secret = enable_mfa_for_user(username="alice01")
    client.post("/logout")
    _login_with_totp(client, alice_secret, identifier="alice01")
    client.post("/logout")

    register(client, username="bob02", email="bob@example.com", phone_number="98765432")
    bob, bob_secret = enable_mfa_for_user(username="bob02")
    client.post("/logout")

    count_before_bob = len(password_reset_outbox())
    login_response, mfa_response = _login_with_totp(client, bob_secret, identifier="bob02")

    assert mfa_response.status_code == 200
    bob_devices = _known_devices(bob.id)
    assert len(bob_devices) == 1
    assert len(password_reset_outbox()) == count_before_bob + 1
    assert password_reset_outbox()[-1]["to"] == bob.email


def test_no_cookie_new_browser_is_treated_as_new_device(client):
    register(client)
    user, secret = enable_mfa_for_user()
    client.post("/logout")

    login_response, mfa_response = _login_with_totp(client, secret)

    assert mfa_response.status_code == 200
    assert len(_known_devices(user.id)) == 1


def test_expired_known_device_is_treated_as_new_again(client):
    register(client)
    user, secret = enable_mfa_for_user()
    client.post("/logout")
    _login_with_totp(client, secret, step_offset=0)

    device = _known_devices(user.id)[0]
    device.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.session.commit()

    count_before = len(password_reset_outbox())
    client.post("/logout")
    login_response, mfa_response = _login_with_totp(client, secret, step_offset=1)
    assert mfa_response.status_code == 200

    assert len(_known_devices(user.id)) == 2
    assert len(password_reset_outbox()) == count_before + 1


def test_new_device_email_is_not_suppressed_by_transfer_activity_preference(client):
    register(client)
    user, secret = enable_mfa_for_user()
    user.transfer_activity_email_enabled = False
    db.session.commit()
    client.post("/logout")

    count_before = len(password_reset_outbox())
    login_response, mfa_response = _login_with_totp(client, secret)

    assert mfa_response.status_code == 200
    deliveries = password_reset_outbox()
    assert len(deliveries) == count_before + 1
    assert deliveries[-1]["subject"] == "SITBank new device sign-in"


def test_email_delivery_failure_does_not_break_login(client, monkeypatch):
    from app.security.email import send_security_email as original_send_security_email

    register(client)
    user, secret = enable_mfa_for_user()
    client.post("/logout")

    def _raise(*args, **kwargs):
        raise RuntimeError("smtp unavailable")

    monkeypatch.setattr("app.security.device_recognition.send_security_email", _raise)

    login_response, mfa_response = _login_with_totp(client, secret)

    assert login_response.status_code == 302
    assert mfa_response.status_code == 200
    assert len(_known_devices(user.id)) == 0
    assert (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="new_device_login_notification", outcome="failure", user_id=user.id)
        .count()
        == 1
    )

    monkeypatch.setattr(
        "app.security.device_recognition.send_security_email",
        original_send_security_email,
    )
    client.post("/logout")
    count_before_retry = len(password_reset_outbox())
    _login_with_totp(client, secret, step_offset=1)

    assert len(_known_devices(user.id)) == 1
    assert len(password_reset_outbox()) == count_before_retry + 1
    assert password_reset_outbox()[-1]["subject"] == "SITBank new device sign-in"


def test_login_that_requires_mfa_setup_still_records_new_device(client):
    register(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    before_count = len(password_reset_outbox())

    response = client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "correct horse battery staple"},
    )

    assert response.status_code == 200
    assert response.get_json()["mfa_setup_required"] is True
    assert "sitbank_device" in response.headers.get("Set-Cookie", "")
    assert len(_known_devices(user.id)) == 1
    assert len(password_reset_outbox()) == before_count + 1
    assert password_reset_outbox()[-1]["subject"] == "SITBank new device sign-in"


def test_new_device_email_body_has_no_links_or_raw_token(client):
    register(client)
    user, secret = enable_mfa_for_user()
    client.post("/logout")
    _login_with_totp(client, secret)

    body = password_reset_outbox()[-1]["body"]
    assert "http://" not in body
    assert "https://" not in body

    device = _known_devices(user.id)[0]
    assert device.device_token_hash not in body


def test_device_recognition_is_not_wired_into_admin_login_paths():
    import app.admin.routes as admin_routes
    import app.admin.services as admin_services

    for module in (admin_routes, admin_services):
        source = open(module.__file__, encoding="utf-8").read()
        assert "device_recognition" not in source
