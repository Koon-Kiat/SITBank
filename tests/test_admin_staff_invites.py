from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone

import pyotp
import pytest

from app.extensions import db
from app.models import PersonIdentityLink, SecurityAuditEvent, StaffInvite, User
from app.security.crypto import encrypt_mfa_secret
from app.security.email import password_reset_outbox
from app.security.passwords import hash_password
from conftest import TestConfig


ROOT_EMAIL = "root1@sit.singaporetech.edu.sg"
ROOT_PASSWORD = "correct horse battery staple"
STAFF_PASSWORD = "another correct horse battery staple"


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


def _create_staff_identity(
    *,
    username: str,
    email: str,
    account_type: str,
    phone_number: str,
    password: str = ROOT_PASSWORD,
    active: bool = True,
    personal_email: str | None = None,
) -> tuple[User, str]:
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        account_type=account_type,
        account_status="active" if active else "setup_pending",
        full_name=username.replace("-", " ").title(),
        phone_number=phone_number,
        account_number=None,
        staff_personal_email=personal_email,
        workplace_email_verified_at=datetime.now(timezone.utc) if active else None,
    )
    db.session.add(user)
    db.session.flush()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = active
    db.session.commit()
    return user, secret


def _login_admin(client, secret: str, email: str = ROOT_EMAIL, password: str = ROOT_PASSWORD):
    password_response = client.post(
        "/login",
        json={"workplace_email": email, "password": password},
    )
    assert password_response.status_code == 200
    verify_response = client.post(
        "/mfa/verify",
        json={"totp_code": _stable_totp(secret)},
    )
    assert verify_response.status_code == 200
    return verify_response


def _stable_totp(secret: str) -> str:
    seconds_into_step = time.time() % 30
    if seconds_into_step > 20:
        time.sleep(30 - seconds_into_step + 0.25)
    return pyotp.TOTP(secret, digits=6, interval=30).now()


def _create_invite(client, secret: str, **overrides):
    payload = {
        "personal_email": "staff.person@gmail.com",
        "workplace_email": "staff.person@sit.singaporetech.edu.sg",
        "role": "staff",
        "totp_code": _stable_totp(secret),
    }
    payload.update(overrides)
    return client.post("/invites", json=payload)


def _latest_invite_token() -> str:
    body = password_reset_outbox()[-1]["body"]
    match = re.search(r"/invites/accept/([A-Za-z0-9_-]{32,256})", body)
    assert match, body
    return match.group(1)


def _latest_workplace_code() -> str:
    body = password_reset_outbox()[-1]["body"]
    match = re.search(r"\b([0-9]{6})\b", body)
    assert match, body
    return match.group(1)


def test_root_admin_can_create_hashed_staff_invite(admin_client):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)

    response = _create_invite(admin_client, secret)
    token = _latest_invite_token()
    invite = db.session.execute(db.select(StaffInvite)).scalar_one()
    events = db.session.query(SecurityAuditEvent).filter_by(event_type="staff_invite_created").all()

    assert response.status_code == 201
    assert response.get_json()["invite"]["workplace_email"] == "staff.person@sit.singaporetech.edu.sg"
    assert invite.token_hash != token
    assert token not in json.dumps(invite.__dict__, default=str)
    assert invite.expires_at.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc)
    assert password_reset_outbox()[-1]["to"] == "staff.person@gmail.com"
    assert "temporary password" not in password_reset_outbox()[-1]["body"].casefold()
    assert events and "token" not in json.dumps(events[0].event_metadata).casefold()


def test_only_root_admin_with_totp_stepup_can_create_invites(admin_client):
    _staff, staff_secret = _create_staff_identity(
        username="staff-admin",
        email="staff.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, staff_secret, email="staff.admin@sit.singaporetech.edu.sg")

    non_root = _create_invite(admin_client, staff_secret)
    assert non_root.status_code == 403

    admin_client.post("/logout")
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234568",
    )
    _login_admin(admin_client, root_secret)
    missing_stepup = admin_client.post(
        "/invites",
        json={
            "personal_email": "person@gmail.com",
            "workplace_email": "person@sit.singaporetech.edu.sg",
            "role": "staff",
        },
    )

    assert missing_stepup.status_code == 400
    assert db.session.query(StaffInvite).count() == 0


def test_invite_creation_validates_server_side_email_and_role_policy(admin_client):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)

    cases = [
        {"workplace_email": "staff@sit.singaporetech.edu.sg.evil.com"},
        {"workplace_email": "staff@gmail.com"},
        {"personal_email": "staff+tag@gmail.com"},
        {"personal_email": "staff@sit.singaporetech.edu.sg"},
        {"personal_email": ROOT_EMAIL},
        {"role": "root_admin"},
    ]
    responses = [_create_invite(admin_client, secret, **case) for case in cases]

    assert [response.status_code for response in responses] == [400, 400, 400, 400, 400, 400]
    assert db.session.query(StaffInvite).count() == 0


def test_invite_creation_accepts_configured_admin_email_domains(admin_client):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)

    response = _create_invite(
        admin_client,
        secret,
        personal_email="staff.second-domain@gmail.com",
        workplace_email="staff.second-domain@singaporetech.edu.sg",
    )

    assert response.status_code == 201
    assert response.get_json()["invite"]["workplace_email"] == "staff.second-domain@singaporetech.edu.sg"


def test_invite_acceptance_requires_turnstile_when_enabled(admin_app, admin_client, monkeypatch):
    admin_app.config["TURNSTILE_ENABLED"] = True
    admin_app.config["TURNSTILE_SECRET_KEY"] = "turnstile-secret"
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret)
    assert _create_invite(admin_client, secret).status_code == 201
    token = _latest_invite_token()

    missing = admin_client.post(
        f"/invites/accept/{token}/start",
        json={
            "full_name": "Staff Person",
            "phone_number": "91234568",
            "password": STAFF_PASSWORD,
            "confirm_password": STAFF_PASSWORD,
        },
    )

    calls = []

    def fake_verify(token_value):
        calls.append(token_value)

    monkeypatch.setattr("app.admin.services.verify_turnstile_token", fake_verify)
    valid = admin_client.post(
        f"/invites/accept/{token}/start",
        json={
            "full_name": "Staff Person",
            "phone_number": "91234568",
            "password": STAFF_PASSWORD,
            "confirm_password": STAFF_PASSWORD,
            "turnstile_token": "browser-token",
        },
    )

    assert missing.status_code == 400
    assert valid.status_code == 200
    assert calls == ["browser-token"]


def test_turnstile_verifier_rejects_non_https_verify_url(admin_app):
    from app.security.turnstile import TurnstileError, verify_turnstile_token

    admin_app.config["TURNSTILE_ENABLED"] = True
    admin_app.config["TURNSTILE_SECRET_KEY"] = "turnstile-secret"
    admin_app.config["TURNSTILE_VERIFY_URL"] = "file:///tmp/not-a-verifier"

    with admin_app.test_request_context("/invites/accept/token/start", method="POST"):
        with pytest.raises(TurnstileError):
            verify_turnstile_token("browser-token")


def test_staff_invite_acceptance_activates_only_after_workplace_code_and_totp(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, root_secret)
    assert _create_invite(admin_client, root_secret).status_code == 201
    token = _latest_invite_token()

    info = admin_client.get(f"/invites/accept/{token}")
    forged_start = admin_client.post(
        f"/invites/accept/{token}/start",
        json={
            "full_name": "Staff Person",
            "phone_number": "91234568",
            "password": STAFF_PASSWORD,
            "confirm_password": STAFF_PASSWORD,
            "role": "admin",
        },
    )
    start = admin_client.post(
        f"/invites/accept/{token}/start",
        json={
            "full_name": "Staff Person",
            "phone_number": "91234568",
            "password": STAFF_PASSWORD,
            "confirm_password": STAFF_PASSWORD,
        },
    )
    setup = start.get_json()["totp_setup"]
    staff_user = db.session.execute(
        db.select(User).where(User.email == "staff.person@sit.singaporetech.edu.sg")
    ).scalar_one()
    login_before_activation = admin_client.post(
        "/login",
        json={"workplace_email": staff_user.email, "password": STAFF_PASSWORD},
    )
    workplace_code = _latest_workplace_code()
    totp_code = _stable_totp(setup["manual_entry_secret"])
    verify = admin_client.post(
        f"/invites/accept/{token}/verify",
        json={"totp_code": totp_code, "workplace_verification_code": workplace_code},
    )
    reuse = admin_client.get(f"/invites/accept/{token}")
    db.session.refresh(staff_user)

    assert info.status_code == 200
    assert info.get_json()["invite"]["role"] == "staff"
    assert forged_start.status_code == 400
    assert start.status_code == 200
    assert staff_user.account_type == "staff"
    assert staff_user.account_status == "active"
    assert staff_user.account_number is None
    assert staff_user.workplace_email_verified_at is not None
    assert login_before_activation.status_code == 401
    assert verify.status_code == 200
    assert reuse.status_code == 401
    assert db.session.query(User).filter_by(account_type="customer").count() == 0


def test_customer_registration_cannot_create_staff_or_admin_roles(client):
    from _auth_flow_helpers import register

    response = register(client)
    forged = client.post(
        "/auth/register",
        json={
            "username": "staff01",
            "email": "staff@sit.singaporetech.edu.sg",
            "full_name": "Staff User",
            "phone_number": "91234568",
            "password": STAFF_PASSWORD,
            "confirm_password": STAFF_PASSWORD,
            "account_type": "admin",
            "role": "admin",
        },
    )
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()

    assert response.status_code == 302
    assert forged.status_code == 400
    assert user.account_type == "customer"
    assert user.account_status == "active"


def test_admin_login_creates_only_admin_session_cookie(admin_app, admin_client):
    _root, secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )

    response = _login_admin(admin_client, secret)
    cookies = "\n".join(response.headers.getlist("Set-Cookie"))

    assert "__Host-sitbank_admin_session=" in cookies
    assert "__Host-sitbank_session=" not in cookies
    assert admin_client.get("/").status_code == 200


def test_separation_guard_blocks_linked_staff_acting_on_own_customer(admin_app):
    from app.admin.separation import assert_not_self_customer_action
    from app.auth.services import AuthError

    staff, _secret = _create_staff_identity(
        username="staff-user",
        email="staff.user@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234567",
        personal_email="same.person@gmail.com",
    )
    customer = User(
        username="customer-user",
        email="same.person@gmail.com",
        password_hash=hash_password(STAFF_PASSWORD),
        account_type="customer",
        account_status="active",
        full_name="Same Person",
        phone_number="91234568",
        account_number="012123456",
    )
    db.session.add(customer)
    db.session.flush()
    db.session.add(
        PersonIdentityLink(
            staff_user_id=staff.id,
            customer_user_id=customer.id,
            created_by_user_id=staff.id,
            verified_at=datetime.now(timezone.utc),
        )
    )
    db.session.commit()

    with pytest.raises(AuthError):
        assert_not_self_customer_action(staff, customer, "balance_edit")

    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_self_customer_action_blocked",
        outcome="blocked",
    ).one()
    assert event.user_id == staff.id
    assert event.event_metadata["action_type"] == "balance_edit"
    assert "012123456" not in json.dumps(event.event_metadata)
