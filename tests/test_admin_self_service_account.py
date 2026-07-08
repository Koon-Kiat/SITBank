from __future__ import annotations

import time
from datetime import datetime, timezone

import pyotp
import pytest

from app.extensions import db
from app.models import PersonIdentityLink, SecurityAuditEvent, User
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password, verify_password


ROOT_EMAIL = "root1@sit.singaporetech.edu.sg"
STAFF_PASSWORD = "correct horse battery staple"
_FIXED_TOTP_TIME = int(time.time())


@pytest.fixture(autouse=True)
def freeze_totp_verifier_time(monkeypatch):
    global _FIXED_TOTP_TIME
    _FIXED_TOTP_TIME = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: _FIXED_TOTP_TIME)


def _create_staff_identity(
    *,
    username: str,
    email: str,
    account_type: str = "staff",
    phone_number: str,
) -> tuple[User, str]:
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(STAFF_PASSWORD),
        account_type=account_type,
        account_status="active",
        full_name=username.replace("-", " ").title(),
        phone_number=phone_number,
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


def _create_customer(
    *,
    username: str,
    email: str,
    phone_number: str,
    is_frozen: bool = False,
    security_lock_reason: str | None = None,
) -> User:
    customer = User(
        username=username,
        email=email,
        password_hash=hash_password("correct horse battery staple"),
        account_type="customer",
        account_status="active",
        full_name=username.replace("-", " ").title(),
        phone_number=phone_number,
        account_number=f"1{abs(hash(username)) % 10**11:011d}",
        is_frozen=is_frozen,
        security_lock_reason=security_lock_reason,
        security_locked_at=datetime.now(timezone.utc) if security_lock_reason else None,
    )
    db.session.add(customer)
    db.session.commit()
    return customer


def _totp(secret: str, *, at: int | None = None) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).at(at if at is not None else _FIXED_TOTP_TIME)


def _login_admin(client, secret: str, email: str):
    primary = client.post("/login", json={"workplace_email": email, "password": STAFF_PASSWORD})
    assert primary.status_code == 200
    verify = client.post("/mfa/verify", json={"totp_code": _totp(secret)})
    assert verify.status_code == 200


# ── Change Password ─────────────────────────────────────────────────────────


def test_password_change_happy_path_forces_relogin_and_audits(admin_client):
    staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    response = admin_client.post(
        "/account/password",
        json={
            "current_password": STAFF_PASSWORD,
            "new_password": "a totally different passphrase 42",
            "confirm_new_password": "a totally different passphrase 42",
            "totp_code": _totp(secret),
        },
    )

    assert response.status_code == 200
    db.session.refresh(staff)
    assert verify_password("a totally different passphrase 42", staff.password_hash)
    assert not verify_password(STAFF_PASSWORD, staff.password_hash)
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="admin_password_change", outcome="success"
    ).count() == 1

    follow_up = admin_client.get("/", headers={"Accept": "application/json"})
    assert follow_up.status_code == 401


def test_password_change_rejects_wrong_current_password(admin_client):
    staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    response = admin_client.post(
        "/account/password",
        json={
            "current_password": "definitely not the password",
            "new_password": "a totally different passphrase 42",
            "confirm_new_password": "a totally different passphrase 42",
            "totp_code": _totp(secret),
        },
    )

    assert response.status_code == 401
    db.session.refresh(staff)
    assert verify_password(STAFF_PASSWORD, staff.password_hash)


def test_password_change_rejects_reused_current_password(admin_client):
    staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    response = admin_client.post(
        "/account/password",
        json={
            "current_password": STAFF_PASSWORD,
            "new_password": STAFF_PASSWORD,
            "confirm_new_password": STAFF_PASSWORD,
            "totp_code": _totp(secret),
        },
    )

    assert response.status_code == 400
    db.session.refresh(staff)
    assert verify_password(STAFF_PASSWORD, staff.password_hash)


def test_password_change_requires_valid_totp_step_up(admin_client):
    staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    response = admin_client.post(
        "/account/password",
        json={
            "current_password": STAFF_PASSWORD,
            "new_password": "a totally different passphrase 42",
            "confirm_new_password": "a totally different passphrase 42",
            "totp_code": "000000",
        },
    )

    assert response.status_code == 403
    db.session.refresh(staff)
    assert verify_password(STAFF_PASSWORD, staff.password_hash)


def test_password_change_requires_authentication(admin_client):
    response = admin_client.post(
        "/account/password",
        json={
            "current_password": STAFF_PASSWORD,
            "new_password": "a totally different passphrase 42",
            "confirm_new_password": "a totally different passphrase 42",
            "totp_code": "000000",
        },
    )
    assert response.status_code == 401


# ── Change MFA ───────────────────────────────────────────────────────────────


def test_mfa_change_start_stages_new_secret_without_disabling_old(admin_client, monkeypatch):
    staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    start = admin_client.post("/account/mfa/start", json={"totp_code": _totp(secret)})
    assert start.status_code == 200
    new_secret = start.get_json()["totp_setup"]["manual_entry_secret"]
    assert new_secret != secret

    db.session.refresh(staff)
    assert staff.mfa_enabled is True

    other_client_login = admin_client.post("/logout", json={})
    assert other_client_login.status_code == 200
    relogin = admin_client.post(
        "/login",
        json={"workplace_email": "bank.staff@sit.singaporetech.edu.sg", "password": STAFF_PASSWORD},
    )
    assert relogin.status_code == 200
    # Advance the mocked clock to a fresh time step (admin MFA login uses a
    # zero-tolerance window, so the server's "now" and the code must move
    # together) to avoid replaying the exact code already consumed above,
    # proving the old secret genuinely still verifies.
    fresh_time = _FIXED_TOTP_TIME + 31
    monkeypatch.setattr("app.auth.services.time.time", lambda: fresh_time)
    old_code_still_works = admin_client.post(
        "/mfa/verify",
        json={"totp_code": _totp(secret, at=fresh_time)},
    )
    assert old_code_still_works.status_code == 200, old_code_still_works.get_data(as_text=True)


def test_mfa_change_start_rejects_invalid_totp(admin_client):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    response = admin_client.post("/account/mfa/start", json={"totp_code": "000000"})
    assert response.status_code == 403


def test_mfa_change_confirm_activates_new_secret_and_forces_relogin(admin_client):
    staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    start = admin_client.post("/account/mfa/start", json={"totp_code": _totp(secret)})
    assert start.status_code == 200
    new_secret = start.get_json()["totp_setup"]["manual_entry_secret"]

    confirm = admin_client.post("/account/mfa/confirm", json={"totp_code": _totp(new_secret)})
    assert confirm.status_code == 200
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="admin_mfa_change", outcome="success"
    ).count() == 1

    follow_up = admin_client.get("/", headers={"Accept": "application/json"})
    assert follow_up.status_code == 401

    relogin = admin_client.post(
        "/login",
        json={"workplace_email": "bank.staff@sit.singaporetech.edu.sg", "password": STAFF_PASSWORD},
    )
    assert relogin.status_code == 200
    old_code_rejected = admin_client.post("/mfa/verify", json={"totp_code": _totp(secret)})
    assert old_code_rejected.status_code == 401
    new_code_accepted = admin_client.post("/mfa/verify", json={"totp_code": _totp(new_secret)})
    assert new_code_accepted.status_code == 200


def test_mfa_change_confirm_without_start_is_rejected(admin_client):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    response = admin_client.post("/account/mfa/confirm", json={"totp_code": "123456"})
    assert response.status_code == 409


def test_mfa_change_confirm_rejects_wrong_new_code(admin_client):
    staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    start = admin_client.post("/account/mfa/start", json={"totp_code": _totp(secret)})
    assert start.status_code == 200

    confirm = admin_client.post("/account/mfa/confirm", json={"totp_code": "000000"})
    assert confirm.status_code == 401
    db.session.refresh(staff)
    assert staff.mfa_enabled is True


# ── Customer self-freeze unfreeze ────────────────────────────────────────────


def test_customer_unfreeze_list_excludes_automatic_lockouts(admin_client):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")
    self_frozen = _create_customer(
        username="self-frozen-customer",
        email="self.frozen@example.test",
        phone_number="81234567",
        is_frozen=True,
    )
    _create_customer(
        username="auto-locked-customer",
        email="auto.locked@example.test",
        phone_number="81234568",
        is_frozen=True,
        security_lock_reason="password_failed_attempts",
    )

    response = admin_client.get("/customer-unfreeze", headers={"Accept": "application/json"})
    assert response.status_code == 200
    usernames = {entry["username"] for entry in response.get_json()["customers"]}
    assert usernames == {self_frozen.username}


@pytest.mark.parametrize("account_type", ["admin", "root_admin"])
def test_customer_unfreeze_denied_for_admin_and_root_admin(admin_client, account_type):
    email = ROOT_EMAIL if account_type == "root_admin" else "security.admin@sit.singaporetech.edu.sg"
    _actor, secret = _create_staff_identity(
        username=f"{account_type}-user",
        email=email,
        account_type=account_type,
        phone_number="91234569",
    )
    _login_admin(admin_client, secret, email)

    list_response = admin_client.get("/customer-unfreeze", headers={"Accept": "application/json"})
    assert list_response.status_code == 403

    post_response = admin_client.post(
        "/customers/999999/unfreeze",
        json={"reason": "test", "totp_code": "000000"},
    )
    assert post_response.status_code == 403


def test_customer_unfreeze_happy_path_records_reason_in_audit(admin_client):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")
    customer = _create_customer(
        username="self-frozen-customer",
        email="self.frozen@example.test",
        phone_number="81234567",
        is_frozen=True,
    )

    response = admin_client.post(
        f"/customers/{customer.id}/unfreeze",
        json={"reason": "verified customer identity by phone, confirmed no fraud", "totp_code": _totp(secret)},
    )

    assert response.status_code == 200
    db.session.refresh(customer)
    assert customer.is_frozen is False
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="customer_self_freeze_unlock", outcome="success"
    ).one()
    assert event.event_metadata["reason"] == "verified customer identity by phone, confirmed no fraud"


def test_customer_unfreeze_rejects_missing_reason(admin_client):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")
    customer = _create_customer(
        username="self-frozen-customer",
        email="self.frozen@example.test",
        phone_number="81234567",
        is_frozen=True,
    )

    response = admin_client.post(
        f"/customers/{customer.id}/unfreeze",
        json={"reason": "", "totp_code": _totp(secret)},
    )

    assert response.status_code == 400
    db.session.refresh(customer)
    assert customer.is_frozen is True


def test_customer_unfreeze_rejects_automatic_lock_target(admin_client):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")
    customer = _create_customer(
        username="auto-locked-customer",
        email="auto.locked@example.test",
        phone_number="81234568",
        is_frozen=True,
        security_lock_reason="password_failed_attempts",
    )

    response = admin_client.post(
        f"/customers/{customer.id}/unfreeze",
        json={"reason": "trying anyway", "totp_code": _totp(secret)},
    )

    assert response.status_code == 409
    db.session.refresh(customer)
    assert customer.is_frozen is True


def test_customer_unfreeze_requires_valid_totp_step_up(admin_client):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")
    customer = _create_customer(
        username="self-frozen-customer",
        email="self.frozen@example.test",
        phone_number="81234567",
        is_frozen=True,
    )

    response = admin_client.post(
        f"/customers/{customer.id}/unfreeze",
        json={"reason": "trying anyway", "totp_code": "000000"},
    )

    assert response.status_code == 403
    db.session.refresh(customer)
    assert customer.is_frozen is True


def test_customer_unfreeze_blocks_staff_own_linked_customer(admin_client):
    staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    customer = _create_customer(
        username="self-frozen-customer",
        email="self.frozen@example.test",
        phone_number="81234567",
        is_frozen=True,
    )
    db.session.add(PersonIdentityLink(staff_user_id=staff.id, customer_user_id=customer.id))
    db.session.commit()
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    response = admin_client.post(
        f"/customers/{customer.id}/unfreeze",
        json={"reason": "trying anyway", "totp_code": _totp(secret)},
    )

    assert response.status_code == 403
    db.session.refresh(customer)
    assert customer.is_frozen is True
