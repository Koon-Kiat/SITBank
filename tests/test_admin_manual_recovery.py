from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from app.extensions import db
from app.models import ManualRecoveryRequest, SecurityAuditEvent, User
from app.security.crypto import encrypt_mfa_secret
from app.security.email import password_reset_outbox
from app.security.passwords import hash_password
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


def _rules(flask_app):
    return {
        rule.rule: rule.endpoint
        for rule in flask_app.url_map.iter_rules()
        if rule.endpoint != "static"
    }


def _create_staff_identity(
    *,
    username: str,
    email: str,
    account_type: str,
    phone_number: str,
    password: str = ROOT_PASSWORD,
) -> tuple[User, str]:
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
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


def _create_customer(username: str = "recover-admin01") -> tuple[User, str]:
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash=hash_password("Correct-Horse-Battery-Staple-2026!"),
        account_type="customer",
        account_status="active",
        full_name="Recover Customer",
        phone_number=f"8{int(datetime.now(timezone.utc).timestamp()) % 10000000:07d}",
        account_number=f"123{int(datetime.now(timezone.utc).timestamp()) % 1000000:06d}",
    )
    db.session.add(user)
    db.session.flush()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    db.session.commit()
    return user, secret


def _create_manual_recovery_request(
    user: User,
    *,
    status: str = "pending",
    expired: bool = False,
) -> ManualRecoveryRequest:
    now = datetime.now(timezone.utc)
    request_record = ManualRecoveryRequest(
        identifier_ref=f"manual-request-ref-{user.id}",
        user_id=user.id,
        status=status,
        requested_ip="203.0.113.10",
        requested_user_agent="unit-test",
        request_count=1,
        created_at=now,
        updated_at=now,
        last_submitted_at=now,
        expires_at=now - timedelta(minutes=1) if expired else now + timedelta(days=7),
        status_changed_at=now,
    )
    db.session.add(request_record)
    db.session.commit()
    return request_record


def _login_admin(client, secret: str, email: str = ROOT_EMAIL, password: str = ROOT_PASSWORD):
    password_response = client.post(
        "/login",
        json={"workplace_email": email, "password": password},
    )
    assert password_response.status_code == 200
    verify_response = client.post(
        "/mfa/verify",
        json={"totp_code": _totp(secret)},
    )
    assert verify_response.status_code == 200
    return verify_response


def _totp(secret: str) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).now()


def _assert_no_sensitive_recovery_material(payload: dict) -> None:
    body = json.dumps(payload, sort_keys=True).casefold()
    forbidden = [
        "identifier_ref",
        "requested_ip",
        "requested_user_agent",
        "reset_token",
        "recovery_code",
        "mfa_secret",
        "mfa_secret_nonce",
        "mfa_secret_ciphertext",
        "password_hash",
        "session_id",
        "session_lookup",
        "hmac",
    ]
    for item in forbidden:
        assert item not in body


def test_manual_recovery_routes_are_admin_app_only():
    from app import create_app

    customer_app = create_app(TestConfig, app_mode="customer")
    admin_app = create_app(TestConfig, app_mode="admin")

    customer_rules = _rules(customer_app)
    admin_rules = _rules(admin_app)

    assert "/manual-recovery/requests" not in customer_rules
    assert not any(rule.startswith("/manual-recovery") for rule in customer_rules)
    assert admin_rules["/manual-recovery/requests"] == "admin.manual_recovery_requests"
    assert (
        admin_rules["/manual-recovery/requests/<int:request_id>/transition"]
        == "admin.manual_recovery_transition"
    )
    assert (
        admin_rules["/manual-recovery/requests/<int:request_id>/complete"]
        == "admin.manual_recovery_complete"
    )


def test_manual_recovery_routes_require_authentication(admin_client):
    assert admin_client.get("/manual-recovery/requests").status_code == 401
    assert admin_client.post("/manual-recovery/requests/1/transition", json={}).status_code == 401
    assert admin_client.post("/manual-recovery/requests/1/complete", json={}).status_code == 401


def test_non_root_staff_cannot_review_or_mutate_manual_recovery(admin_client):
    _staff, staff_secret = _create_staff_identity(
        username="staff-admin",
        email="staff.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-staff-denied")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, staff_secret, email="staff.admin@sit.singaporetech.edu.sg")

    listed = admin_client.get("/manual-recovery/requests")
    transitioned = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={"status": "under_review", "reason": "identity review", "totp_code": _totp(staff_secret)},
    )
    completed = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/complete",
        json={"reason": "identity verified", "totp_code": _totp(staff_secret)},
    )

    assert listed.status_code == 403
    assert transitioned.status_code == 403
    assert completed.status_code == 403


def test_root_admin_can_list_pending_manual_recovery_requests(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-list")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret)

    response = admin_client.get("/manual-recovery/requests")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["requests"][0]["id"] == request_record.id
    assert payload["requests"][0]["status"] == "pending"
    assert payload["requests"][0]["linked_customer"] is True
    _assert_no_sensitive_recovery_material(payload)


def test_root_admin_transition_requires_totp_and_preserves_status(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-transition-denied")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret)

    missing_totp = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={"status": "under_review", "reason": "identity review"},
    )
    invalid_totp = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={"status": "under_review", "reason": "identity review", "totp_code": "000000"},
    )

    db.session.refresh(request_record)
    assert missing_totp.status_code == 400
    assert invalid_totp.status_code == 403
    assert request_record.status == "pending"


def test_root_admin_cannot_transition_own_customer_manual_recovery(admin_client):
    root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-self-root")
    root.staff_personal_email = customer.email
    request_record = _create_manual_recovery_request(customer)
    db.session.commit()
    _login_admin(admin_client, root_secret)

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={"status": "under_review", "reason": "identity review", "totp_code": _totp(root_secret)},
    )
    db.session.refresh(request_record)
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_self_customer_action_blocked",
        outcome="blocked",
    ).one()

    assert response.status_code == 403
    assert request_record.status == "pending"
    assert event.user_id == root.id
    assert event.event_metadata["action_type"] == "manual_recovery_transition"


def test_root_admin_can_transition_manual_recovery_to_review_and_approval(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-transition")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret)

    under_review = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={
            "status": "under_review",
            "reason": "identity review started",
            "totp_code": _totp(root_secret),
        },
    )
    approved = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={
            "status": "approved",
            "reason": "identity verified",
            "totp_code": _totp(root_secret),
        },
    )

    assert under_review.status_code == 200
    assert under_review.get_json()["request"]["status"] == "under_review"
    assert approved.status_code == 200
    assert approved.get_json()["request"]["status"] == "approved"
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="manual_recovery_admin_transition",
        outcome="success",
    ).count() == 2


def test_root_admin_cannot_complete_manual_recovery_before_approval(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-complete-denied")
    request_record = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root_secret)

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/complete",
        json={"reason": "identity verified", "totp_code": _totp(root_secret)},
    )

    assert response.status_code == 409
    db.session.refresh(request_record)
    assert request_record.status == "pending"


def test_root_admin_can_complete_approved_manual_recovery(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-complete")
    request_record = _create_manual_recovery_request(customer, status="approved")
    _login_admin(admin_client, root_secret)

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/complete",
        json={"reason": "identity verified", "totp_code": _totp(root_secret)},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["request"]["status"] == "completed"
    assert payload["request"]["mfa_reenrollment_required"] is True
    _assert_no_sensitive_recovery_material(payload)
    db.session.refresh(customer)
    db.session.refresh(request_record)
    assert customer.mfa_enabled is False
    assert customer.mfa_secret_nonce is None
    assert customer.mfa_secret_ciphertext is None
    assert request_record.completed_at is not None
    assert "SITBank manual recovery completed" in [
        item["subject"] for item in password_reset_outbox()
    ]
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="manual_recovery_completed",
        outcome="success",
    ).count() == 1
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="manual_recovery_admin_complete",
        outcome="success",
    ).count() == 1


def test_expired_manual_recovery_request_is_safely_rejected(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer, _customer_secret = _create_customer("recover-expired")
    request_record = _create_manual_recovery_request(customer, expired=True)
    _login_admin(admin_client, root_secret)

    response = admin_client.post(
        f"/manual-recovery/requests/{request_record.id}/transition",
        json={
            "status": "under_review",
            "reason": "identity review",
            "totp_code": _totp(root_secret),
        },
    )

    assert response.status_code == 409
    db.session.refresh(request_record)
    assert request_record.status == "expired"
