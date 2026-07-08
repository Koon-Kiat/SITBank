from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from app.admin import services as admin_services
from app.extensions import db
from app.models import PersonIdentityLink, SecurityAuditEvent, ServerSideSession, User
from app.security.audit import AuditWriteError
from app.security.crypto import encrypt_mfa_secret
from app.security.email import password_reset_outbox
from app.security.passwords import hash_password


ROOT_EMAIL = "root1@sit.singaporetech.edu.sg"
STAFF_PASSWORD = "correct horse battery staple"


@pytest.fixture(autouse=True)
def freeze_totp_verifier_time(monkeypatch):
    import time

    fixed_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: fixed_time)
    return fixed_time


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
    account_status: str = "active",
) -> User:
    customer = User(
        username=username,
        email=email,
        password_hash=hash_password("correct horse battery staple"),
        account_type="customer",
        account_status=account_status,
        full_name=username.replace("-", " ").title(),
        phone_number=phone_number,
        account_number=f"1{abs(hash(username)) % 10**11:011d}",
        is_frozen=is_frozen,
    )
    db.session.add(customer)
    db.session.commit()
    return customer


def _totp(secret: str, *, at: int) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).at(at)


def _login_admin(client, secret: str, email: str, *, at: int):
    primary = client.post("/login", json={"workplace_email": email, "password": STAFF_PASSWORD})
    assert primary.status_code == 200
    verify = client.post("/mfa/verify", json={"totp_code": _totp(secret, at=at)})
    assert verify.status_code == 200


def test_freeze_lookup_finds_eligible_active_customer(admin_client, freeze_totp_verifier_time):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg", at=freeze_totp_verifier_time)
    customer = _create_customer(
        username="active-customer",
        email="active.customer@example.test",
        phone_number="81234567",
    )

    response = admin_client.get(
        "/customer-freeze",
        query_string={"identifier": customer.username},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 200
    assert response.get_json()["candidate"]["username"] == customer.username


def test_freeze_lookup_excludes_already_frozen_customer(admin_client, freeze_totp_verifier_time):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg", at=freeze_totp_verifier_time)
    customer = _create_customer(
        username="already-frozen",
        email="already.frozen@example.test",
        phone_number="81234568",
        is_frozen=True,
    )

    response = admin_client.get(
        "/customer-freeze",
        query_string={"identifier": customer.username},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 200
    assert response.get_json()["candidate"] is None


@pytest.mark.parametrize("account_type", ["admin", "root_admin"])
def test_freeze_denied_for_admin_and_root_admin(admin_client, account_type, freeze_totp_verifier_time):
    email = ROOT_EMAIL if account_type == "root_admin" else "security.admin@sit.singaporetech.edu.sg"
    _actor, secret = _create_staff_identity(
        username=f"{account_type}-user",
        email=email,
        account_type=account_type,
        phone_number="91234569",
    )
    _login_admin(admin_client, secret, email, at=freeze_totp_verifier_time)

    lookup_response = admin_client.get(
        "/customer-freeze",
        query_string={"identifier": "anyone"},
        headers={"Accept": "application/json"},
    )
    assert lookup_response.status_code == 403

    freeze_response = admin_client.post(
        "/customers/999999/freeze",
        json={"reason": "test", "totp_code": "000000"},
    )
    assert freeze_response.status_code == 403


def test_freeze_happy_path_records_reason_and_notifies_customer(admin_client, freeze_totp_verifier_time):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg", at=freeze_totp_verifier_time)
    customer = _create_customer(
        username="active-customer",
        email="active.customer@example.test",
        phone_number="81234567",
    )
    before_count = len(password_reset_outbox())

    response = admin_client.post(
        f"/customers/{customer.id}/freeze",
        json={
            "reason": "suspected fraudulent transaction, freezing pending review",
            "totp_code": _totp(secret, at=freeze_totp_verifier_time),
        },
    )

    assert response.status_code == 200
    db.session.refresh(customer)
    assert customer.is_frozen is True
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="customer_freeze_as_staff", outcome="success"
    ).one()
    assert event.event_metadata["reason"] == "suspected fraudulent transaction, freezing pending review"

    deliveries = password_reset_outbox()[before_count:]
    assert deliveries[0]["to"] == customer.email
    assert deliveries[0]["subject"] == "SITBank account frozen by staff"


def test_freeze_rejects_missing_reason(admin_client, freeze_totp_verifier_time):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg", at=freeze_totp_verifier_time)
    customer = _create_customer(
        username="active-customer",
        email="active.customer@example.test",
        phone_number="81234567",
    )

    response = admin_client.post(
        f"/customers/{customer.id}/freeze",
        json={"reason": "", "totp_code": _totp(secret, at=freeze_totp_verifier_time)},
    )

    assert response.status_code == 400
    db.session.refresh(customer)
    assert customer.is_frozen is False


def test_freeze_rejects_already_frozen_target(admin_client, freeze_totp_verifier_time):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg", at=freeze_totp_verifier_time)
    customer = _create_customer(
        username="already-frozen",
        email="already.frozen@example.test",
        phone_number="81234568",
        is_frozen=True,
    )

    response = admin_client.post(
        f"/customers/{customer.id}/freeze",
        json={"reason": "trying anyway", "totp_code": _totp(secret, at=freeze_totp_verifier_time)},
    )

    assert response.status_code == 409


def test_freeze_requires_valid_totp_step_up(admin_client, freeze_totp_verifier_time):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg", at=freeze_totp_verifier_time)
    customer = _create_customer(
        username="active-customer",
        email="active.customer@example.test",
        phone_number="81234567",
    )

    response = admin_client.post(
        f"/customers/{customer.id}/freeze",
        json={"reason": "trying anyway", "totp_code": "000000"},
    )

    assert response.status_code == 403
    db.session.refresh(customer)
    assert customer.is_frozen is False


def test_freeze_happy_path_revokes_target_customer_sessions(admin_client, freeze_totp_verifier_time):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg", at=freeze_totp_verifier_time)
    customer = _create_customer(
        username="active-customer",
        email="active.customer@example.test",
        phone_number="81234567",
    )
    active_session = ServerSideSession(
        component="customer",
        session_lookup_hash=f"lookup-{customer.id}",
        payload=b"fake-payload",
        user_id=customer.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.session.add(active_session)
    db.session.commit()

    response = admin_client.post(
        f"/customers/{customer.id}/freeze",
        json={
            "reason": "suspected fraudulent transaction, freezing pending review",
            "totp_code": _totp(secret, at=freeze_totp_verifier_time),
        },
    )

    assert response.status_code == 200
    assert response.get_json()["revoked_sessions"] == 1
    db.session.refresh(active_session)
    assert active_session.ended_at is not None
    assert active_session.revoked_at is not None


def test_freeze_persists_distinct_reason_excluded_from_voluntary_queue(admin_client, freeze_totp_verifier_time):
    staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg", at=freeze_totp_verifier_time)
    customer = _create_customer(
        username="active-customer",
        email="active.customer@example.test",
        phone_number="81234567",
    )

    response = admin_client.post(
        f"/customers/{customer.id}/freeze",
        json={
            "reason": "suspected fraudulent transaction, freezing pending review",
            "totp_code": _totp(secret, at=freeze_totp_verifier_time),
        },
    )

    assert response.status_code == 200
    db.session.refresh(customer)
    assert customer.security_lock_reason == admin_services.STAFF_FRAUD_FREEZE_REASON
    assert customer.security_locked_at is not None

    voluntary_queue = admin_services.self_frozen_customers_for_staff(staff)
    assert all(item["id"] != customer.id for item in voluntary_queue)


def test_unfreeze_customer_as_staff_rejects_staff_fraud_frozen_target(admin_client, freeze_totp_verifier_time):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg", at=freeze_totp_verifier_time)
    customer = _create_customer(
        username="active-customer",
        email="active.customer@example.test",
        phone_number="81234567",
    )
    freeze_response = admin_client.post(
        f"/customers/{customer.id}/freeze",
        json={
            "reason": "suspected fraudulent transaction, freezing pending review",
            "totp_code": _totp(secret, at=freeze_totp_verifier_time),
        },
    )
    assert freeze_response.status_code == 200

    unfreeze_response = admin_client.post(
        f"/customers/{customer.id}/unfreeze",
        json={"reason": "trying anyway", "totp_code": _totp(secret, at=freeze_totp_verifier_time)},
    )

    assert unfreeze_response.status_code == 409


def test_freeze_survives_required_audit_failure(admin_client, freeze_totp_verifier_time, monkeypatch):
    _staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg", at=freeze_totp_verifier_time)
    customer = _create_customer(
        username="active-customer",
        email="active.customer@example.test",
        phone_number="81234567",
    )
    before_count = len(password_reset_outbox())

    def _broken_audit_event_required(*_args, **_kwargs):
        raise AuditWriteError("simulated required audit failure")

    monkeypatch.setattr(admin_services, "audit_event_required", _broken_audit_event_required)

    with pytest.raises(AuditWriteError):
        admin_client.post(
            f"/customers/{customer.id}/freeze",
            json={
                "reason": "suspected fraudulent transaction, freezing pending review",
                "totp_code": _totp(secret, at=freeze_totp_verifier_time),
            },
        )

    db.session.rollback()
    refreshed = db.session.get(User, customer.id)
    assert refreshed.is_frozen is False
    assert refreshed.security_lock_reason is None
    assert password_reset_outbox()[before_count:] == []


def test_freeze_blocks_staff_own_linked_customer(admin_client, freeze_totp_verifier_time):
    staff, secret = _create_staff_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        phone_number="91234567",
    )
    customer = _create_customer(
        username="active-customer",
        email="active.customer@example.test",
        phone_number="81234567",
    )
    db.session.add(PersonIdentityLink(staff_user_id=staff.id, customer_user_id=customer.id))
    db.session.commit()
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg", at=freeze_totp_verifier_time)

    response = admin_client.post(
        f"/customers/{customer.id}/freeze",
        json={"reason": "trying anyway", "totp_code": _totp(secret, at=freeze_totp_verifier_time)},
    )

    assert response.status_code == 403
    db.session.refresh(customer)
    assert customer.is_frozen is False
