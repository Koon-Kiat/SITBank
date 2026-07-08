from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import pyotp
import pytest

from _auth_flow_helpers import enable_mfa_for_user, register
from app.extensions import db
from app.models import SecurityAuditEvent, ServerSideSession, User
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password
from app.security.sessions import (
    AUTH_CREATED_AT_KEY,
    SESSION_RISK_CONTEXT_KEY,
    SESSION_RISK_FINGERPRINT_KEY,
    SESSION_RISK_REAUTH_REQUIRED_KEY,
    session_lookup_hash,
)
from conftest import TestConfig


CUSTOMER_IP = "198.51.100.10"
CUSTOMER_CHANGED_IP = "203.0.113.20"
CHROME_120 = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
)
CHROME_121 = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36"
)
FIREFOX_122 = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "Gecko/20100101 Firefox/122.0"
)
ROOT_EMAIL = "root1@sit.singaporetech.edu.sg"
ROOT_PASSWORD = "correct horse battery staple"


def _request_context(ip_address: str, user_agent: str) -> dict:
    return {
        "environ_overrides": {"REMOTE_ADDR": ip_address},
        "headers": {"User-Agent": user_agent},
    }


def _login_customer(client, *, ip_address: str, user_agent: str) -> tuple[User, str]:
    register(client)
    user, secret = enable_mfa_for_user()
    context = _request_context(ip_address, user_agent)
    password_response = client.post(
        "/login",
        data={
            "identifier": user.username,
            "password": "correct horse battery staple",
        },
        **context,
    )
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).now()},
        **context,
    )
    assert password_response.status_code == 302
    assert mfa_response.status_code == 200
    return user, secret


@pytest.fixture()
def admin_app(monkeypatch):
    from app import create_app
    from app.security import passwords

    monkeypatch.setattr(
        passwords,
        "_is_password_pwned_by_hibp",
        lambda _password: False,
    )
    flask_app = create_app(TestConfig, app_mode="admin")
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def admin_client(admin_app):
    return admin_app.test_client()


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
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(
        secret,
        user.id,
    )
    user.mfa_enabled = True
    db.session.commit()
    return user, secret


def _login_admin(client, secret: str, *, ip_address: str, user_agent: str, monkeypatch=None) -> None:
    context = _request_context(ip_address, user_agent)
    mfa_time = int(time.time())
    if monkeypatch is not None:
        monkeypatch.setattr("app.auth.services.time.time", lambda: mfa_time)
    password_response = client.post(
        "/login",
        json={"workplace_email": ROOT_EMAIL, "password": ROOT_PASSWORD},
        **context,
    )
    mfa_response = client.post(
        "/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(mfa_time)},
        **context,
    )
    assert password_response.status_code == 200
    assert mfa_response.status_code == 200


def _current_session_id(client) -> str:
    with client.session_transaction() as sess:
        return sess.sid


def _session_record(session_id: str) -> ServerSideSession:
    return db.session.execute(
        db.select(ServerSideSession).where(
            ServerSideSession.session_lookup_hash == session_lookup_hash(
                session_id
            )
        )
    ).scalar_one()


def test_authenticated_customer_session_stores_hashed_context(client):
    _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )

    with client.session_transaction() as sess:
        context = dict(sess[SESSION_RISK_CONTEXT_KEY])
        assert sess["mfa_verified_at"]
        assert sess[AUTH_CREATED_AT_KEY]

    serialized = json.dumps(context)
    assert context["version"] == 1
    assert context["last_checked_at"] > 0
    assert set(context) == {
        "version",
        "ip_network_hash",
        "user_agent_family_hash",
        "user_agent_hash",
        "last_checked_at",
    }
    assert CUSTOMER_IP not in serialized
    assert CHROME_120 not in serialized


def test_authenticated_admin_session_stores_hashed_context(admin_client, monkeypatch):
    _root, secret = _create_root_admin()
    _login_admin(
        admin_client,
        secret,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
        monkeypatch=monkeypatch,
    )

    with admin_client.session_transaction() as sess:
        context = dict(sess[SESSION_RISK_CONTEXT_KEY])
        assert sess["auth_context"] == "admin_password+totp"

    serialized = json.dumps(context)
    assert context["version"] == 1
    assert context["last_checked_at"] > 0
    assert CUSTOMER_IP not in serialized
    assert CHROME_120 not in serialized


def test_same_context_customer_request_continues_and_checks_risk(client):
    _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )
    with client.session_transaction() as sess:
        previous_check = sess[SESSION_RISK_CONTEXT_KEY]["last_checked_at"]

    response = client.get(
        "/dashboard",
        **_request_context(CUSTOMER_IP, CHROME_120),
    )

    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert (
            sess[SESSION_RISK_CONTEXT_KEY]["last_checked_at"]
            >= previous_check
        )
        assert not sess.get(SESSION_RISK_REAUTH_REQUIRED_KEY)


def test_matching_legacy_fingerprint_without_context_requires_reauthentication(
    client,
):
    _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )
    with client.session_transaction() as sess:
        assert sess.get(SESSION_RISK_FINGERPRINT_KEY)
        sess.pop(SESSION_RISK_CONTEXT_KEY)

    response = client.get(
        "/dashboard",
        **_request_context(CUSTOMER_IP, CHROME_120),
    )

    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert sess[SESSION_RISK_CONTEXT_KEY]["version"] == 1
        assert sess.get(SESSION_RISK_REAUTH_REQUIRED_KEY) is True
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk",
        outcome="reauth_required",
    ).one()
    assert event.event_metadata["signals"] == ["session_context"]


def test_missing_session_risk_context_with_tampered_fingerprint_requires_reauth(
    client,
):
    _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )
    with client.session_transaction() as sess:
        sess.pop(SESSION_RISK_CONTEXT_KEY)
        sess[SESSION_RISK_FINGERPRINT_KEY] = "tampered"

    response = client.get(
        "/dashboard",
        **_request_context(CUSTOMER_IP, CHROME_120),
    )

    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert sess[SESSION_RISK_CONTEXT_KEY]["version"] == 1
        assert sess.get(SESSION_RISK_REAUTH_REQUIRED_KEY) is True
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk",
        outcome="reauth_required",
    ).one()
    assert event.event_metadata["signals"] == ["session_context"]


@pytest.mark.parametrize(
    "stored_context",
    [
        "malformed",
        {"version": 999},
    ],
)
def test_unsupported_customer_session_context_requires_reauthentication(
    client,
    stored_context,
):
    _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )
    with client.session_transaction() as sess:
        sess[SESSION_RISK_CONTEXT_KEY] = stored_context

    response = client.get(
        "/dashboard",
        **_request_context(CUSTOMER_IP, CHROME_120),
    )

    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert sess[SESSION_RISK_CONTEXT_KEY]["version"] == 1
        assert sess.get(SESSION_RISK_REAUTH_REQUIRED_KEY) is True


def test_malformed_current_customer_session_context_revokes_session(client):
    _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )
    session_id = _current_session_id(client)
    with client.session_transaction() as sess:
        sess[SESSION_RISK_CONTEXT_KEY] = {"version": 1}

    response = client.get(
        "/dashboard",
        **_request_context(CUSTOMER_IP, CHROME_120),
    )

    assert response.status_code == 302
    assert _session_record(session_id).ended_reason == "risk_change"


@pytest.mark.parametrize(
    "stored_context",
    [
        None,
        "malformed",
        {"version": 999},
        {"version": 1},
    ],
)
def test_invalid_admin_session_context_always_revokes(
    admin_client,
    monkeypatch,
    stored_context,
):
    _root, secret = _create_root_admin()
    _login_admin(
        admin_client,
        secret,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
        monkeypatch=monkeypatch,
    )
    session_id = _current_session_id(admin_client)
    with admin_client.session_transaction() as sess:
        if stored_context is None:
            sess.pop(SESSION_RISK_CONTEXT_KEY)
        else:
            sess[SESSION_RISK_CONTEXT_KEY] = stored_context

    response = admin_client.get(
        "/",
        **_request_context(CUSTOMER_IP, CHROME_120),
    )

    assert response.status_code == 401
    assert _session_record(session_id).ended_reason == "risk_change"


def test_customer_browser_version_change_is_logged_without_lockout(client):
    _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )

    response = client.get(
        "/dashboard",
        **_request_context(CUSTOMER_IP, CHROME_121),
    )
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk",
        outcome="changed",
    ).one()

    assert response.status_code == 200
    assert event.event_metadata["severity"] == "low"
    assert event.event_metadata["signals"] == ["user_agent"]
    with client.session_transaction() as sess:
        assert not sess.get(SESSION_RISK_REAUTH_REQUIRED_KEY)


def test_suspicious_customer_context_requires_reauth_for_sensitive_action(
    client,
):
    user, secret = _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )

    safe_response = client.get(
        "/dashboard",
        **_request_context(CUSTOMER_CHANGED_IP, CHROME_120),
    )
    sensitive_response = client.post(
        "/profile",
        data={
            "username": user.username,
            "email": "changed@example.com",
            "phone_number": user.phone_number,
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
        },
        **_request_context(CUSTOMER_CHANGED_IP, CHROME_120),
    )
    db.session.refresh(user)

    assert safe_response.status_code == 200
    assert sensitive_response.status_code == 401
    assert user.email == "alice@example.com"
    events = db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk",
        outcome="reauth_required",
    ).all()
    assert len(events) == 1
    assert events[0].user_id == user.id
    assert events[0].event_metadata["signals"] == ["ip_network"]


def test_admin_context_change_revokes_session_under_stricter_policy(
    admin_client,
    monkeypatch,
):
    _root, secret = _create_root_admin()
    _login_admin(
        admin_client,
        secret,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
        monkeypatch=monkeypatch,
    )
    session_id = _current_session_id(admin_client)

    response = admin_client.get(
        "/",
        **_request_context(CUSTOMER_IP, CHROME_121),
    )
    record = _session_record(session_id)
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk",
        outcome="revoked",
    ).one()

    assert response.status_code == 401
    assert response.get_json()["error"] == "Session verification required"
    assert record.ended_reason == "risk_change"
    assert event.event_metadata == {
        "app_mode": "admin",
        "severity": "high",
        "signals": ["user_agent"],
    }


def test_high_risk_customer_context_change_revokes_session(client):
    _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )
    session_id = _current_session_id(client)

    response = client.get(
        "/dashboard",
        **_request_context(CUSTOMER_CHANGED_IP, FIREFOX_122),
    )
    record = _session_record(session_id)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login?session_expired=1")
    assert record.ended_reason == "risk_change"


def test_context_checks_preserve_absolute_authentication_time(client):
    _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )
    fixed_authentication_time = int(time.time()) - 60
    with client.session_transaction() as sess:
        sess[AUTH_CREATED_AT_KEY] = fixed_authentication_time

    response = client.get(
        "/dashboard",
        **_request_context(CUSTOMER_IP, CHROME_120),
    )

    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert sess[AUTH_CREATED_AT_KEY] == fixed_authentication_time


def test_idle_timeout_takes_precedence_over_context_risk(client, app):
    _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )
    session_id = _current_session_id(client)
    with client.session_transaction() as sess:
        sess["last_activity_at"] = (
            int(time.time()) - app.config["SESSION_INACTIVITY_SECONDS"] - 1
        )

    response = client.get(
        "/auth/sessions",
        **_request_context(CUSTOMER_CHANGED_IP, FIREFOX_122),
    )
    record = _session_record(session_id)

    assert response.status_code == 401
    assert record.ended_reason == "expired"
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk"
    ).count() == 0


def test_context_checks_do_not_bypass_csrf(client, app):
    _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )
    app.config["WTF_CSRF_ENABLED"] = True

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "changed@example.com",
            "phone_number": "91234567",
            "totp_code": "000000",
        },
        **_request_context(CUSTOMER_CHANGED_IP, CHROME_120),
    )

    assert response.status_code == 400


def test_session_risk_audit_metadata_excludes_cookie_and_raw_session_id(
    client,
):
    _login_customer(
        client,
        ip_address=CUSTOMER_IP,
        user_agent=CHROME_120,
    )
    session_id = _current_session_id(client)

    client.get(
        "/dashboard",
        **_request_context(CUSTOMER_CHANGED_IP, CHROME_120),
    )
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk",
        outcome="reauth_required",
    ).one()

    serialized_metadata = json.dumps(event.event_metadata, sort_keys=True)
    assert session_id not in serialized_metadata
    assert session_id != event.session_ref
    assert CUSTOMER_CHANGED_IP not in serialized_metadata
    assert CHROME_120 not in serialized_metadata
    assert "cookie" not in serialized_metadata.casefold()


def test_customer_and_admin_context_policies_use_isolated_keys():
    from app import create_app
    from app.security.sessions import (
        _risk_context_hash,
        _session_risk_severity,
    )

    customer_app = create_app(TestConfig, app_mode="customer")
    admin_app = create_app(TestConfig, app_mode="admin")
    with customer_app.app_context():
        customer_hash = _risk_context_hash("ip_network", "198.51.100.0/24")
        assert _session_risk_severity({"user_agent"}) == "low"
    with admin_app.app_context():
        admin_hash = _risk_context_hash("ip_network", "198.51.100.0/24")
        assert _session_risk_severity({"user_agent"}) == "high"

    assert customer_hash != admin_hash
    assert (
        customer_app.config["SESSION_COOKIE_NAME"]
        != admin_app.config["SESSION_COOKIE_NAME"]
    )
