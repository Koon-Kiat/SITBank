from __future__ import annotations

import time
from datetime import datetime, timezone

import pyotp
import pytest

from _auth_flow_helpers import enable_mfa_for_user, login, register
from app.extensions import db
from app.models import SecurityAuditEvent, ServerSideSession, StaffInvite, User
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password
from app.security.sessions import AUTH_CREATED_AT_KEY, session_lookup_hash
from conftest import TestConfig


ROOT_EMAIL = "root1@sit.singaporetech.edu.sg"
ROOT_PASSWORD = "correct horse battery staple"


@pytest.fixture()
def admin_app(monkeypatch):
    from app import create_app
    from app.security import passwords

    monkeypatch.setattr(passwords, "_is_password_pwned_by_hibp", lambda _password: False)
    flask_app = create_app(TestConfig, app_mode="admin")
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def admin_client(admin_app):
    return admin_app.test_client()


def _totp(secret: str) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).now()


def _create_root_admin() -> tuple[User, str]:
    user = User(
        username="root-admin",
        email=ROOT_EMAIL,
        password_hash=hash_password(ROOT_PASSWORD),
        account_type="root_admin",
        account_status="active",
        full_name="Root Admin",
        phone_number="91234567",
        account_number=None,
        workplace_email_verified_at=datetime.now(timezone.utc),
    )
    db.session.add(user)
    db.session.flush()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    db.session.commit()
    return user, secret


def _login_admin(client, secret: str):
    password_response = client.post(
        "/login",
        json={"workplace_email": ROOT_EMAIL, "password": ROOT_PASSWORD},
    )
    verify_response = client.post("/mfa/verify", json={"totp_code": _totp(secret)})
    assert password_response.status_code == 200
    assert verify_response.status_code == 200
    return verify_response


def _set_session_age(client, *, seconds_old: int) -> str:
    now = int(time.time())
    with client.session_transaction() as sess:
        sess[AUTH_CREATED_AT_KEY] = now - seconds_old
        sess["last_activity_at"] = now
        return sess.sid


def _current_auth_created_at(client) -> int:
    with client.session_transaction() as sess:
        return int(sess[AUTH_CREATED_AT_KEY])


def test_customer_login_records_auth_created_at_and_activity_does_not_refresh(app, client):
    register(client)
    login(client)
    fixed_auth_time = int(time.time()) - 60
    with client.session_transaction() as sess:
        assert isinstance(sess[AUTH_CREATED_AT_KEY], int)
        sess[AUTH_CREATED_AT_KEY] = fixed_auth_time

    response = client.get("/mfa/setup")

    assert response.status_code == 200
    assert _current_auth_created_at(client) == fixed_auth_time
    assert app.config["SESSION_ABSOLUTE_LIFETIME_SECONDS"] == app.config[
        "CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS"
    ]


def test_customer_absolute_lifetime_expiry_revokes_session_and_audits(app, client):
    register(client)
    login(client)
    app.config["SESSION_ABSOLUTE_LIFETIME_SECONDS"] = 60
    session_id = _set_session_age(client, seconds_old=61)

    response = client.get("/auth/sessions")
    record = db.session.execute(
        db.select(ServerSideSession).where(
            ServerSideSession.session_lookup_hash == session_lookup_hash(session_id)
        )
    ).scalar_one()
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_absolute_lifetime",
        outcome="expired",
    ).one()

    assert response.status_code == 401
    assert response.get_json()["error"] == "Session expired"
    assert "__Host-sitbank_session=;" in response.headers["Set-Cookie"]
    assert record.ended_reason == "absolute_lifetime"
    assert event.event_metadata["app_mode"] == "customer"
    assert event.event_metadata["lifetime_seconds"] == 60
    assert "session_id" not in event.event_metadata
    assert "payload" not in event.event_metadata
    assert "redis" not in event.event_metadata


def test_customer_high_risk_totp_rotation_preserves_auth_created_at(client):
    register(client)
    login(client)
    _user, secret = enable_mfa_for_user()
    fixed_auth_time = int(time.time()) - 120
    with client.session_transaction() as sess:
        original_session_id = sess.sid
        sess[AUTH_CREATED_AT_KEY] = fixed_auth_time

    response = client.post(
        "/auth/mfa/recovery-codes/regenerate",
        json={"totp_code": _totp(secret)},
    )
    with client.session_transaction() as sess:
        rotated_session_id = sess.sid
        current_auth_time = sess[AUTH_CREATED_AT_KEY]

    assert response.status_code == 200
    assert rotated_session_id != original_session_id
    assert current_auth_time == fixed_auth_time


def test_admin_mfa_login_records_admin_auth_created_at(admin_app, admin_client):
    _root, secret = _create_root_admin()

    _login_admin(admin_client, secret)

    with admin_client.session_transaction() as sess:
        assert isinstance(sess[AUTH_CREATED_AT_KEY], int)
        assert sess["auth_context"] == "admin_password+totp"
    assert admin_app.config["SESSION_ABSOLUTE_LIFETIME_SECONDS"] == admin_app.config[
        "ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS"
    ]


def test_admin_absolute_lifetime_expiry_uses_admin_cookie_and_audits(admin_app, admin_client):
    _root, secret = _create_root_admin()
    _login_admin(admin_client, secret)
    admin_app.config["SESSION_ABSOLUTE_LIFETIME_SECONDS"] = 60
    session_id = _set_session_age(admin_client, seconds_old=61)

    response = admin_client.get("/")
    record = db.session.execute(
        db.select(ServerSideSession).where(
            ServerSideSession.session_lookup_hash == session_lookup_hash(session_id)
        )
    ).scalar_one()
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_absolute_lifetime",
        outcome="expired",
    ).one()

    assert response.status_code == 401
    assert response.get_json()["error"] == "Session expired"
    assert "__Host-sitbank_admin_session=;" in response.headers["Set-Cookie"]
    assert "__Host-sitbank_session=;" not in response.headers["Set-Cookie"]
    assert record.component == "admin"
    assert record.ended_reason == "absolute_lifetime"
    assert event.event_metadata["app_mode"] == "admin"


def test_admin_totp_stepup_does_not_refresh_auth_created_at(admin_client):
    _root, secret = _create_root_admin()
    _login_admin(admin_client, secret)
    fixed_auth_time = int(time.time()) - 120
    with admin_client.session_transaction() as sess:
        sess[AUTH_CREATED_AT_KEY] = fixed_auth_time

    response = admin_client.post(
        "/invites",
        json={
            "personal_email": "staff.person@gmail.com",
            "workplace_email": "staff.person@sit.singaporetech.edu.sg",
            "role": "staff",
            "totp_code": _totp(secret),
        },
    )

    assert response.status_code == 201
    assert db.session.query(StaffInvite).count() == 1
    assert _current_auth_created_at(admin_client) == fixed_auth_time
