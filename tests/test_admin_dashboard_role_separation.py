from __future__ import annotations

import time
from datetime import datetime, timezone

import pyotp
import pytest

from app.extensions import db
from app.models import SecurityAuditEvent, User
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password
from conftest import TestConfig


ROOT_EMAIL = "root1@sit.singaporetech.edu.sg"
ROOT_PASSWORD = "correct horse battery staple"
_FIXED_TOTP_TIME = int(time.time())


@pytest.fixture(autouse=True)
def freeze_totp_verifier_time(monkeypatch):
    global _FIXED_TOTP_TIME
    _FIXED_TOTP_TIME = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: _FIXED_TOTP_TIME)


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


def _create_identity(
    *,
    username: str,
    email: str,
    account_type: str,
    phone_number: str,
    active: bool = True,
) -> tuple[User, str]:
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(ROOT_PASSWORD),
        account_type=account_type,
        account_status="active" if active else "setup_pending",
        full_name=username.replace("-", " ").title(),
        phone_number=phone_number,
        account_number="100000001" if account_type == "customer" else None,
        workplace_email_verified_at=datetime.now(timezone.utc) if active and account_type != "customer" else None,
        mfa_enabled=False,
    )
    db.session.add(user)
    db.session.flush()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = active
    db.session.commit()
    return user, secret


def _login_admin(client, secret: str, email: str):
    primary = client.post(
        "/login",
        json={"workplace_email": email, "password": ROOT_PASSWORD},
    )
    assert primary.status_code == 200
    verify = client.post(
        "/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(_FIXED_TOTP_TIME)},
    )
    assert verify.status_code == 200
    return verify


def test_admin_dashboard_denies_unauthenticated_and_customer_sessions(admin_client):
    unauthenticated = admin_client.get("/")
    customer, _secret = _create_identity(
        username="customer-user",
        email="customer@example.com",
        account_type="customer",
        phone_number="91234567",
    )
    with admin_client.session_transaction() as sess:
        sess["user_id"] = customer.id

    customer_response = admin_client.get("/")
    denied_event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="admin_access_denied",
        outcome="blocked",
    ).one()

    assert unauthenticated.status_code == 401
    assert customer_response.status_code == 403
    assert denied_event.event_metadata["reason"] == "not_active_staff"
    assert "password" not in str(denied_event.event_metadata).casefold()
    assert "csrf" not in str(denied_event.event_metadata).casefold()


def test_staff_dashboard_gets_business_placeholder_and_no_technical_links(admin_client):
    _staff, secret = _create_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    dashboard = admin_client.get("/")
    body = dashboard.get_data(as_text=True)
    direct_audit = admin_client.get("/audit-logs")
    direct_staff = admin_client.get("/staff")
    direct_invites = admin_client.get("/invites")

    assert dashboard.status_code == 200
    assert "Business Operations" in body
    assert "Customer support queues" in body
    assert "Not implemented" in body
    assert "Audit logs" not in body
    assert "Staff/admin users" not in body
    assert "Staff invites" not in body
    assert [direct_audit.status_code, direct_staff.status_code, direct_invites.status_code] == [403, 403, 403]


def test_admin_and_root_navigation_are_server_rendered_by_role(admin_client):
    _admin, admin_secret = _create_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, admin_secret, "security.admin@sit.singaporetech.edu.sg")
    admin_body = admin_client.get("/").get_data(as_text=True)

    assert "Audit logs" in admin_body
    assert "Alerts" in admin_body
    assert "Staff/admin users" in admin_body
    assert "Staff invites" not in admin_body
    assert "Manual recovery" not in admin_body

    admin_client.post("/logout")
    _root, root_secret = _create_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234568",
    )
    _login_admin(admin_client, root_secret, ROOT_EMAIL)
    root_body = admin_client.get("/").get_data(as_text=True)

    assert "Audit logs" in root_body
    assert "Staff invites" in root_body
    assert "Manual recovery" in root_body


def test_lower_roles_cannot_create_or_promote_staff_accounts(admin_client):
    _admin, admin_secret = _create_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, admin_secret, "security.admin@sit.singaporetech.edu.sg")
    admin_attempt = admin_client.post(
        "/invites",
        json={
            "personal_email": "person@gmail.com",
            "workplace_email": "new.admin@sit.singaporetech.edu.sg",
            "role": "admin",
            "totp_code": pyotp.TOTP(admin_secret, digits=6, interval=30).at(_FIXED_TOTP_TIME),
        },
    )

    admin_client.post("/logout")
    _root, root_secret = _create_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234568",
    )
    _login_admin(admin_client, root_secret, ROOT_EMAIL)
    root_promotion_attempt = admin_client.post(
        "/invites",
        json={
            "personal_email": "person@gmail.com",
            "workplace_email": "new.root@sit.singaporetech.edu.sg",
            "role": "root_admin",
            "totp_code": pyotp.TOTP(root_secret, digits=6, interval=30).at(_FIXED_TOTP_TIME),
        },
    )

    assert admin_attempt.status_code == 403
    assert root_promotion_attempt.status_code == 400
    assert db.session.query(User).filter_by(email="new.admin@sit.singaporetech.edu.sg").one_or_none() is None
    assert db.session.query(User).filter_by(email="new.root@sit.singaporetech.edu.sg").one_or_none() is None
