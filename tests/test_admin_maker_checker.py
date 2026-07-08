from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from app.extensions import db
from app.models import (
    AdminActionRequest,
    AuthAttemptCounter,
    ManualRecoveryRequest,
    PersonIdentityLink,
    SecurityAuditEvent,
    ServerSideSession,
    User,
)
from app.security.audit import AuditWriteError
from app.security.crypto import encrypt_mfa_secret
from app.security.email import password_reset_outbox
from app.security.passwords import hash_password


ROOT1_EMAIL = "root1@sit.singaporetech.edu.sg"
ROOT2_EMAIL = "root2@sit.singaporetech.edu.sg"
ROOT_PASSWORD = "correct horse battery staple"
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
        account_number=None,
        workplace_email_verified_at=datetime.now(timezone.utc) if active else None,
    )
    db.session.add(user)
    db.session.flush()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = active
    db.session.commit()
    return user, secret


def _create_customer(username: str = "maker-customer") -> User:
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash=hash_password("Correct-Horse-Battery-Staple-2026!"),
        account_type="customer",
        account_status="active",
        full_name="Maker Customer",
        phone_number=f"8{len(username):07d}",
        account_number=f"123{len(username):09d}",
    )
    db.session.add(user)
    db.session.commit()
    return user


def _create_manual_recovery_request(user: User, *, status: str = "pending") -> ManualRecoveryRequest:
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
        expires_at=now + timedelta(days=7),
        status_changed_at=now,
    )
    db.session.add(request_record)
    db.session.commit()
    return request_record


def _create_admin_action_request(
    requester: User,
    *,
    operation_type: str,
    target_type: str,
    target_id: str,
    operation_payload: dict,
    reason_present: bool = False,
) -> AdminActionRequest:
    from app.admin.services import _admin_action_request_hmac

    now = datetime.now(timezone.utc)
    request_record = AdminActionRequest(
        operation_type=operation_type,
        target_type=target_type,
        target_id=str(target_id),
        operation_payload=operation_payload,
        requester_id=requester.id,
        requester_role=requester.account_type,
        status="pending",
        reason_present=reason_present,
        reason_length=12 if reason_present else 0,
        metadata_hmac="pending",
        created_at=now,
        updated_at=now,
        expires_at=now + timedelta(hours=24),
    )
    db.session.add(request_record)
    db.session.flush()
    request_record.metadata_hmac = _admin_action_request_hmac(request_record)
    db.session.commit()
    return request_record


def _lock_customer_for_security_failures(
    customer: User,
    *,
    reason: str = "password_failed_attempts",
) -> None:
    now = datetime.now(timezone.utc)
    customer.is_frozen = True
    customer.failed_login_count = 9
    customer.security_locked_at = now
    customer.security_lock_reason = reason
    db.session.add_all(
        [
            AuthAttemptCounter(
                scope="user_security:password",
                principal_hash=f"{customer.id:064x}",
                user_id=customer.id,
                failure_count=9,
                window_started_at=now,
                window_expires_at=now + timedelta(hours=1),
            ),
            AuthAttemptCounter(
                scope="user_security:mfa",
                principal_hash=f"{customer.id:064x}",
                user_id=customer.id,
                failure_count=5,
                window_started_at=now,
                window_expires_at=now + timedelta(hours=1),
            ),
            AuthAttemptCounter(
                scope="password_reset",
                principal_hash=f"{customer.id:064x}",
                user_id=customer.id,
                failure_count=2,
                window_started_at=now,
                window_expires_at=now + timedelta(hours=1),
            ),
            ServerSideSession(
                component="customer",
                session_lookup_hash=f"{customer.id:064x}",
                session_ref="customer-session",
                payload=b"unit-test-session-payload",
                user_id=customer.id,
                expires_at=now + timedelta(hours=1),
                ip_address="203.0.113.20",
                user_agent="unit-test",
                risk_fingerprint="e" * 64,
            ),
        ]
    )
    db.session.commit()


def _login_admin(client, secret: str, email: str):
    password_response = client.post(
        "/login",
        json={"workplace_email": email, "password": ROOT_PASSWORD},
    )
    assert password_response.status_code == 200
    verify_response = client.post("/mfa/verify", json={"totp_code": _totp(secret)})
    assert verify_response.status_code == 200
    return verify_response


def _totp(secret: str) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).at(_FIXED_TOTP_TIME)


def _invalid_totp(secret: str) -> str:
    current = _totp(secret)
    return "000000" if current != "000000" else "111111"


def _logout(client) -> None:
    client.post("/logout")


def _assert_no_sensitive_action_material(payload: dict) -> None:
    body = json.dumps(payload, sort_keys=True).casefold()
    for forbidden in (
        "password_hash",
        "mfa_secret",
        "mfa_secret_nonce",
        "mfa_secret_ciphertext",
        "totp_code",
        "session_id",
        "session_lookup",
        "csrf",
        "cookie",
        "identifier_ref",
        "requested_ip",
        "requested_user_agent",
        "metadata_hmac",
    ):
        assert forbidden not in body


def test_staff_lifecycle_executes_directly_for_root_admin(admin_client):
    _root1, root1_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    target, _target_secret = _create_staff_identity(
        username="target-admin",
        email="target.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234569",
    )
    _login_admin(admin_client, root1_secret, ROOT1_EMAIL)

    requested = admin_client.post(
        f"/staff/{target.id}/deactivate",
        json={"totp_code": _totp(root1_secret)},
    )
    db.session.refresh(target)

    assert requested.status_code == 200
    requested_payload = requested.get_json()
    assert requested_payload["message"] == "Staff account updated"
    assert requested_payload["account"]["workplace_email"] == "target.admin@sit.singaporetech.edu.sg"
    db.session.refresh(target)
    assert target.account_status == "revoked"
    assert db.session.query(AdminActionRequest).count() == 0
    _assert_no_sensitive_action_material(requested_payload)
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_account_deactivated",
        outcome="success",
    ).count() == 1


def test_customer_security_unlock_executes_directly_and_clears_only_lock_state(
    admin_client,
):
    _root1, root1_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer = _create_customer("locked-customer")
    _lock_customer_for_security_failures(customer)
    _login_admin(admin_client, root1_secret, ROOT1_EMAIL)

    unlocked = admin_client.post(
        f"/customers/{customer.id}/security-unlock-requests",
        json={
            "reason": "Customer completed the support identity review.",
            "totp_code": _totp(root1_secret),
        },
    )
    db.session.refresh(customer)

    assert unlocked.status_code == 200
    db.session.refresh(customer)
    customer_session = db.session.execute(
        db.select(ServerSideSession).where(ServerSideSession.user_id == customer.id)
    ).scalar_one()
    remaining_scopes = set(
        db.session.execute(
            db.select(AuthAttemptCounter.scope).where(
                AuthAttemptCounter.user_id == customer.id
            )
        ).scalars()
    )
    assert customer.is_frozen is False
    assert customer.failed_login_count == 0
    assert customer.security_locked_at is None
    assert customer.security_lock_reason is None
    assert customer_session.revoked_at is not None
    assert customer_session.ended_reason == "security_unlock"
    assert remaining_scopes == {"password_reset"}
    assert db.session.query(AdminActionRequest).count() == 0
    assert "SITBank account security lock cleared" in [
        item["subject"] for item in password_reset_outbox()
    ]
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="customer_security_unlock_completed",
        outcome="success",
    ).count() == 1
    _assert_no_sensitive_action_material(unlocked.get_json())


@pytest.mark.parametrize(
    "lock_reason",
    ["manual_admin_freeze", "account_compromise", None],
)
def test_customer_security_unlock_rejects_nonautomatic_locks(
    admin_client,
    lock_reason,
):
    _root, root_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer = _create_customer(f"ineligible-{lock_reason or 'none'}")
    _lock_customer_for_security_failures(customer, reason=lock_reason)
    _login_admin(admin_client, root_secret, ROOT1_EMAIL)

    response = admin_client.post(
        f"/customers/{customer.id}/security-unlock-requests",
        json={
            "reason": "Attempt an out-of-policy unlock.",
            "totp_code": _totp(root_secret),
        },
    )

    assert response.status_code == 409
    db.session.refresh(customer)
    assert customer.is_frozen is True
    assert db.session.query(AdminActionRequest).count() == 0


def test_customer_security_unlock_rejects_missing_csrf_before_request_creation(
    admin_client,
):
    _root, root_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer = _create_customer("csrf-locked-customer")
    _lock_customer_for_security_failures(customer)
    _login_admin(admin_client, root_secret, ROOT1_EMAIL)
    admin_client.application.config["WTF_CSRF_ENABLED"] = True

    response = admin_client.post(
        f"/customers/{customer.id}/security-unlock-requests",
        json={
            "reason": "This request is missing its CSRF token.",
            "totp_code": _totp(root_secret),
        },
    )

    assert response.status_code == 400
    assert db.session.query(AdminActionRequest).count() == 0


def test_customer_security_unlock_requires_current_requester_totp(admin_client):
    _root, root_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer = _create_customer("totp-locked-customer")
    _lock_customer_for_security_failures(customer)
    _login_admin(admin_client, root_secret, ROOT1_EMAIL)

    response = admin_client.post(
        f"/customers/{customer.id}/security-unlock-requests",
        json={
            "reason": "The submitted authenticator code is invalid.",
            "totp_code": _invalid_totp(root_secret),
        },
    )

    assert response.status_code == 403
    assert db.session.query(AdminActionRequest).count() == 0


@pytest.mark.parametrize("account_type", ["staff", "admin"])
def test_customer_security_unlock_is_root_only(admin_client, account_type):
    email = f"{account_type}.operator@sit.singaporetech.edu.sg"
    _operator, operator_secret = _create_staff_identity(
        username=f"{account_type}-operator",
        email=email,
        account_type=account_type,
        phone_number="91234567",
    )
    customer = _create_customer(f"{account_type}-locked-customer")
    _lock_customer_for_security_failures(customer)
    _login_admin(admin_client, operator_secret, email)

    response = admin_client.post(
        f"/customers/{customer.id}/security-unlock-requests",
        json={
            "reason": "Lower roles must not create unlock requests.",
            "totp_code": _totp(operator_secret),
        },
    )

    assert response.status_code == 403
    assert db.session.query(AdminActionRequest).count() == 0


def test_customer_security_unlock_fails_closed_for_identity_overlap_and_stale_lock(
    admin_client,
):
    root1, root1_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _root2, root2_secret = _create_staff_identity(
        username="root-two",
        email=ROOT2_EMAIL,
        account_type="root_admin",
        phone_number="91234568",
    )
    linked_customer = _create_customer("linked-customer")
    stale_customer = _create_customer("stale-customer")
    _lock_customer_for_security_failures(linked_customer)
    _lock_customer_for_security_failures(stale_customer)
    db.session.add(
        PersonIdentityLink(
            staff_user_id=root1.id,
            customer_user_id=linked_customer.id,
            created_by_user_id=root1.id,
            verified_at=datetime.now(timezone.utc),
            notes="Explicit unit-test identity link",
        )
    )
    db.session.commit()
    _login_admin(admin_client, root1_secret, ROOT1_EMAIL)
    approver_client = admin_client.application.test_client()
    _login_admin(approver_client, root2_secret, ROOT2_EMAIL)

    linked_response = admin_client.post(
        f"/customers/{linked_customer.id}/security-unlock-requests",
        json={
            "reason": "Must be denied for identity overlap.",
            "totp_code": _totp(root1_secret),
        },
    )
    action_request = _create_admin_action_request(
        root1,
        operation_type="customer_security_unlock",
        target_type="customer_user",
        target_id=str(stale_customer.id),
        operation_payload={
            "action": "unlock",
            "lock_reason": str(stale_customer.security_lock_reason),
            "locked_at": stale_customer.security_locked_at.isoformat(),
        },
        reason_present=True,
    )
    stale_customer.security_locked_at = stale_customer.security_locked_at + timedelta(
        seconds=1
    )
    db.session.commit()
    approved = approver_client.post(
        f"/admin-action-requests/{action_request.id}/approve",
        json={"totp_code": _totp(root2_secret)},
    )

    assert linked_response.status_code == 403
    assert approved.status_code == 409
    db.session.refresh(stale_customer)
    assert stale_customer.is_frozen is True
    assert db.session.get(AdminActionRequest, action_request.id).status == "execution_failed"


def test_staff_lifecycle_audit_failure_rolls_back_direct_target(
    admin_client,
    monkeypatch,
):
    from app.admin import services as admin_services

    _root1, root1_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    target, _target_secret = _create_staff_identity(
        username="target-admin",
        email="target.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234569",
    )
    _login_admin(admin_client, root1_secret, ROOT1_EMAIL)
    original_required_audit = admin_services.audit_event_required

    def fail_staff_lifecycle_audit(event_type, outcome, **kwargs):
        if event_type == "staff_account_deactivated":
            raise AuditWriteError("required audit failed")
        return original_required_audit(event_type, outcome, **kwargs)

    monkeypatch.setattr(
        admin_services,
        "audit_event_required",
        fail_staff_lifecycle_audit,
    )

    failed = admin_client.post(
        f"/staff/{target.id}/deactivate",
        json={"totp_code": _totp(root1_secret)},
    )

    db.session.expire_all()
    persisted_target = db.session.get(User, target.id)

    assert failed.status_code == 409
    assert failed.get_json()["error"] == "Staff account update failed"
    assert persisted_target.account_status == "active"
    assert db.session.query(AdminActionRequest).count() == 0
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="staff_account_deactivated",
        outcome="success",
    ).count() == 0


def test_manual_recovery_approval_and_completion_execute_directly(admin_client):
    _root1, root1_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    customer = _create_customer("maker-recover")
    recovery = _create_manual_recovery_request(customer)
    _login_admin(admin_client, root1_secret, ROOT1_EMAIL)

    under_review = admin_client.post(
        f"/manual-recovery/requests/{recovery.id}/transition",
        json={
            "status": "under_review",
            "reason": "identity review started",
            "totp_code": _totp(root1_secret),
        },
    )
    approved = admin_client.post(
        f"/manual-recovery/requests/{recovery.id}/transition",
        json={
            "status": "approved",
            "reason": "identity verified",
            "totp_code": _totp(root1_secret),
        },
    )
    assert under_review.status_code == 200
    assert approved.status_code == 200
    completed = admin_client.post(
        f"/manual-recovery/requests/{recovery.id}/complete",
        json={"reason": "complete recovery", "totp_code": _totp(root1_secret)},
    )

    assert completed.status_code == 200
    db.session.refresh(recovery)
    db.session.refresh(customer)
    assert recovery.status == "completed"
    assert customer.mfa_enabled is False
    assert "SITBank manual recovery completed" in [
        item["subject"] for item in password_reset_outbox()
    ]
    _assert_no_sensitive_action_material(completed.get_json())
    assert db.session.query(AdminActionRequest).count() == 0
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="manual_recovery_admin_complete",
        outcome="success",
    ).count() == 1


def test_admin_action_request_tampering_and_expiry_fail_closed(admin_client):
    global _FIXED_TOTP_TIME
    _root1, root1_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _root2, root2_secret = _create_staff_identity(
        username="root-two",
        email=ROOT2_EMAIL,
        account_type="root_admin",
        phone_number="91234568",
    )
    target, _target_secret = _create_staff_identity(
        username="target-admin",
        email="target.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234569",
    )
    _login_admin(admin_client, root1_secret, ROOT1_EMAIL)
    action_request = _create_admin_action_request(
        _root1,
        operation_type="staff_reset_activation",
        target_type="staff_user",
        target_id=str(target.id),
        operation_payload={"action": "reset_activation"},
    )
    action_request.operation_payload = {"action": "deactivate"}
    db.session.commit()
    _logout(admin_client)
    _login_admin(admin_client, root2_secret, ROOT2_EMAIL)

    tampered = admin_client.post(
        f"/admin-action-requests/{action_request.id}/approve",
        json={"totp_code": _totp(root2_secret)},
    )
    db.session.refresh(action_request)
    action_request.status = "pending"
    action_request.expires_at = datetime.fromtimestamp(
        _FIXED_TOTP_TIME,
        timezone.utc,
    ) - timedelta(seconds=1)
    db.session.commit()
    _FIXED_TOTP_TIME += 30
    expired = admin_client.post(
        f"/admin-action-requests/{action_request.id}/approve",
        json={"totp_code": _totp(root2_secret)},
    )

    assert tampered.status_code == 409
    assert expired.status_code == 409
    db.session.refresh(target)
    db.session.refresh(action_request)
    assert target.account_status == "active"
    assert action_request.status == "expired"
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="admin_action_request_integrity",
        outcome="failure",
    ).count() == 1


def test_admin_action_request_reject_and_cancel_are_terminal(admin_client):
    _root1, root1_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _root2, root2_secret = _create_staff_identity(
        username="root-two",
        email=ROOT2_EMAIL,
        account_type="root_admin",
        phone_number="91234568",
    )
    target, _target_secret = _create_staff_identity(
        username="target-admin",
        email="target.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234569",
    )
    _login_admin(admin_client, root1_secret, ROOT1_EMAIL)
    approver_client = admin_client.application.test_client()
    _login_admin(approver_client, root2_secret, ROOT2_EMAIL)
    first = _create_admin_action_request(
        _root1,
        operation_type="staff_reactivate",
        target_type="staff_user",
        target_id=str(target.id),
        operation_payload={"action": "reactivate"},
    )
    first_request_id = first.id
    self_reject = admin_client.post(
        f"/admin-action-requests/{first_request_id}/reject",
        json={"totp_code": _totp(root1_secret)},
    )
    rejected = approver_client.post(
        f"/admin-action-requests/{first_request_id}/reject",
        json={"totp_code": _totp(root2_secret)},
    )
    replay = approver_client.post(
        f"/admin-action-requests/{first_request_id}/approve",
        json={"totp_code": _totp(root2_secret)},
    )
    second = _create_admin_action_request(
        _root1,
        operation_type="staff_deactivate",
        target_type="staff_user",
        target_id=str(target.id),
        operation_payload={"action": "deactivate"},
    )
    second_request_id = second.id
    non_requester_cancel = approver_client.post(
        f"/admin-action-requests/{second_request_id}/cancel",
        json={"totp_code": _totp(root2_secret)},
    )
    cancelled = admin_client.post(
        f"/admin-action-requests/{second_request_id}/cancel",
        json={"totp_code": _totp(root1_secret)},
    )

    assert self_reject.status_code == 403
    assert rejected.status_code == 200
    assert replay.status_code == 409
    assert non_requester_cancel.status_code == 403
    assert cancelled.status_code == 200
    assert db.session.get(AdminActionRequest, first_request_id).status == "rejected"
    assert db.session.get(AdminActionRequest, second_request_id).status == "cancelled"
    db.session.refresh(target)
    assert target.account_status == "active"


def test_admin_action_browser_views_and_form_redirects(admin_client):
    _root1, root1_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _root2, root2_secret = _create_staff_identity(
        username="root-two",
        email=ROOT2_EMAIL,
        account_type="root_admin",
        phone_number="91234568",
    )
    target, _target_secret = _create_staff_identity(
        username="target-admin",
        email="target.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234569",
    )
    _login_admin(admin_client, root1_secret, ROOT1_EMAIL)
    approver_client = admin_client.application.test_client()
    _login_admin(approver_client, root2_secret, ROOT2_EMAIL)

    action_request = _create_admin_action_request(
        _root1,
        operation_type="staff_deactivate",
        target_type="staff_user",
        target_id=str(target.id),
        operation_payload={"action": "deactivate"},
    )
    list_page = admin_client.get("/admin-action-requests")
    detail_page = admin_client.get(f"/admin-action-requests/{action_request.id}")
    approved = approver_client.post(
        f"/admin-action-requests/{action_request.id}/approve",
        data={"totp_code": _totp(root2_secret)},
    )

    assert list_page.status_code == 200
    assert b"Admin approvals" in list_page.data
    assert b"Deactivate staff account" in list_page.data
    assert b"root-one" in list_page.data
    assert b"target-admin" in list_page.data
    assert detail_page.status_code == 200
    assert f"Request #{action_request.id}".encode() in detail_page.data
    assert b"Technical details" in detail_page.data
    assert b"Deactivate staff account" in detail_page.data
    assert approved.status_code == 303
    db.session.refresh(target)
    assert target.account_status == "revoked"

    reactivate_request = _create_admin_action_request(
        _root1,
        operation_type="staff_reactivate",
        target_type="staff_user",
        target_id=str(target.id),
        operation_payload={"action": "reactivate"},
    )
    rejected = approver_client.post(
        f"/admin-action-requests/{reactivate_request.id}/reject",
        data={"totp_code": _totp(root2_secret)},
    )

    reset_request = _create_admin_action_request(
        _root1,
        operation_type="staff_reset_activation",
        target_type="staff_user",
        target_id=str(target.id),
        operation_payload={"action": "reset_activation"},
    )
    cancelled = admin_client.post(
        f"/admin-action-requests/{reset_request.id}/cancel",
        data={"totp_code": _totp(root1_secret)},
    )

    assert rejected.status_code == 303
    assert cancelled.status_code == 303


def test_admin_action_review_expires_stale_requests(admin_client):
    _root1, root1_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    target, _target_secret = _create_staff_identity(
        username="target-admin",
        email="target.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234569",
    )
    _login_admin(admin_client, root1_secret, ROOT1_EMAIL)
    action_request = _create_admin_action_request(
        _root1,
        operation_type="staff_deactivate",
        target_type="staff_user",
        target_id=str(target.id),
        operation_payload={"action": "deactivate"},
    )
    action_request.expires_at = datetime.fromtimestamp(
        _FIXED_TOTP_TIME,
        timezone.utc,
    ) - timedelta(seconds=1)
    db.session.commit()

    review = admin_client.get("/admin-action-requests", headers={"Accept": "application/json"})

    assert review.status_code == 200
    db.session.refresh(action_request)
    assert action_request.status == "expired"
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="admin_action_request_expired",
        outcome="success",
    ).count() == 1


def test_admin_action_invalid_totp_stepups_are_rejected(admin_client):
    _root1, root1_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _root2, root2_secret = _create_staff_identity(
        username="root-two",
        email=ROOT2_EMAIL,
        account_type="root_admin",
        phone_number="91234568",
    )
    target, _target_secret = _create_staff_identity(
        username="target-admin",
        email="target.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234569",
    )
    _login_admin(admin_client, root1_secret, ROOT1_EMAIL)
    approver_client = admin_client.application.test_client()
    _login_admin(approver_client, root2_secret, ROOT2_EMAIL)

    deactivate = _create_admin_action_request(
        _root1,
        operation_type="staff_deactivate",
        target_type="staff_user",
        target_id=str(target.id),
        operation_payload={"action": "deactivate"},
    )
    reactivate = _create_admin_action_request(
        _root1,
        operation_type="staff_reactivate",
        target_type="staff_user",
        target_id=str(target.id),
        operation_payload={"action": "reactivate"},
    )
    reset = _create_admin_action_request(
        _root1,
        operation_type="staff_reset_activation",
        target_type="staff_user",
        target_id=str(target.id),
        operation_payload={"action": "reset_activation"},
    )

    invalid_approval = approver_client.post(
        f"/admin-action-requests/{deactivate.id}/approve",
        json={"totp_code": _invalid_totp(root2_secret)},
    )
    invalid_reject = approver_client.post(
        f"/admin-action-requests/{reactivate.id}/reject",
        json={"totp_code": _invalid_totp(root2_secret)},
    )
    invalid_cancel = admin_client.post(
        f"/admin-action-requests/{reset.id}/cancel",
        json={"totp_code": _invalid_totp(root1_secret)},
    )

    assert invalid_approval.status_code == 403
    assert invalid_reject.status_code == 403
    assert invalid_cancel.status_code == 403


def test_admin_action_approval_requires_requester_still_eligible(admin_client):
    root1, root1_secret = _create_staff_identity(
        username="root-one",
        email=ROOT1_EMAIL,
        account_type="root_admin",
        phone_number="91234567",
    )
    _root2, root2_secret = _create_staff_identity(
        username="root-two",
        email=ROOT2_EMAIL,
        account_type="root_admin",
        phone_number="91234568",
    )
    target, _target_secret = _create_staff_identity(
        username="target-admin",
        email="target.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234569",
    )
    _login_admin(admin_client, root1_secret, ROOT1_EMAIL)
    approver_client = admin_client.application.test_client()
    _login_admin(approver_client, root2_secret, ROOT2_EMAIL)
    created = _create_admin_action_request(
        root1,
        operation_type="staff_deactivate",
        target_type="staff_user",
        target_id=str(target.id),
        operation_payload={"action": "deactivate"},
    )
    root1.account_status = "revoked"
    db.session.commit()

    blocked = approver_client.post(
        f"/admin-action-requests/{created.id}/approve",
        json={"totp_code": _totp(root2_secret)},
    )

    assert blocked.status_code == 409
    db.session.refresh(target)
    assert target.account_status == "active"
