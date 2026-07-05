from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from app.admin.services import (
    dispute_detail_for_staff,
    disputes_for_staff,
    transition_dispute_status_for_staff,
)
from app.extensions import db
from app.models import SecurityAuditEvent, Transaction, TransactionDispute, User
from app.security.audit import AuditWriteError
from app.security.transaction_integrity import sign_transaction_integrity
from test_admin_dashboard_role_separation import (
    ROOT_EMAIL,
    _create_identity,
    _login_admin,
    admin_app,
    admin_client,
    freeze_totp_verifier_time,
)


def _create_dispute(admin_app) -> TransactionDispute:
    with admin_app.app_context():
        customer_a = User(
            username="disputer-alice",
            email="disputer-alice@example.com",
            password_hash="not-used",
            account_type="customer",
            account_status="active",
            full_name="Disputer Alice",
            phone_number="91112222",
            account_number="100000002000",
        )
        customer_b = User(
            username="disputer-bob",
            email="disputer-bob@example.com",
            password_hash="not-used",
            account_type="customer",
            account_status="active",
            full_name="Disputer Bob",
            phone_number="91112223",
            account_number="100000003000",
        )
        db.session.add_all([customer_a, customer_b])
        db.session.flush()

        txn_ref = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc)
        digest, key_id, algorithm, version = sign_transaction_integrity(
            transaction_ref=txn_ref,
            sender_id=customer_a.id,
            recipient_id=customer_b.id,
            payee_id=None,
            amount=Decimal("25.00"),
            reference="Role separation test",
            status="completed",
            transaction_type="local_transfer",
            created_at=created_at,
        )
        txn = Transaction(
            transaction_ref=txn_ref,
            transaction_hash=digest,
            transaction_integrity_key_id=key_id,
            transaction_integrity_algorithm=algorithm,
            transaction_integrity_version=version,
            sender_id=customer_a.id,
            recipient_id=customer_b.id,
            amount=Decimal("25.00"),
            reference="Role separation test",
            status="completed",
            transaction_type="local_transfer",
            created_at=created_at,
        )
        db.session.add(txn)
        db.session.flush()

        dispute = TransactionDispute(
            transaction_id=txn.id,
            reporter_id=customer_a.id,
            issue_type="other",
            reason="Role separation test dispute",
            status="open",
        )
        db.session.add(dispute)
        db.session.commit()
        return dispute.id


def test_plain_staff_can_resolve_dispute_without_leaking_note_to_audit_log(admin_client, admin_app):
    dispute_id = _create_dispute(admin_app)
    _staff, secret = _create_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    response = admin_client.post(
        f"/disputes/{dispute_id}/status",
        data={"status": "resolved", "resolution_note": "Refunded via manual bank transfer reference 123456"},
    )
    assert response.status_code == 303

    with admin_app.app_context():
        dispute = db.session.get(TransactionDispute, dispute_id)
        assert dispute.status == "resolved"
        assert dispute.resolution_note == "Refunded via manual bank transfer reference 123456"

        audit_row = db.session.execute(
            db.select(SecurityAuditEvent).where(
                SecurityAuditEvent.event_type == "transaction_dispute_status_change"
            )
        ).scalar_one()
        serialized_metadata = str(audit_row.event_metadata)
        assert "Refunded via manual bank transfer" not in serialized_metadata
        assert audit_row.event_metadata["to_status"] == "resolved"


def test_plain_staff_can_access_dispute_queue(admin_client, admin_app):
    dispute_id = _create_dispute(admin_app)
    _staff, secret = _create_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    list_response = admin_client.get("/disputes")
    detail_response = admin_client.get(f"/disputes/{dispute_id}")

    assert list_response.status_code == 200
    assert "Transaction disputes" in list_response.get_data(as_text=True)
    assert detail_response.status_code == 200
    assert "Role separation test dispute" in detail_response.get_data(as_text=True)


def test_admin_and_root_admin_are_excluded_from_dispute_queue(admin_client, admin_app):
    dispute_id = _create_dispute(admin_app)

    _admin, admin_secret = _create_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, admin_secret, "security.admin@sit.singaporetech.edu.sg")
    assert admin_client.get("/disputes").status_code == 403
    assert admin_client.get(f"/disputes/{dispute_id}").status_code == 403
    assert (
        admin_client.post(
            f"/disputes/{dispute_id}/status",
            data={"status": "resolved", "resolution_note": "n/a"},
        ).status_code
        == 403
    )
    admin_client.post("/logout")

    _root, root_secret = _create_identity(
        username="root-admin",
        email=ROOT_EMAIL,
        account_type="root_admin",
        phone_number="91234568",
    )
    _login_admin(admin_client, root_secret, ROOT_EMAIL)
    assert admin_client.get("/disputes").status_code == 403
    assert admin_client.get(f"/disputes/{dispute_id}").status_code == 403


def test_unauthenticated_request_is_denied(admin_client, admin_app):
    dispute_id = _create_dispute(admin_app)
    assert admin_client.get("/disputes").status_code == 401
    assert admin_client.get(f"/disputes/{dispute_id}").status_code == 401


def test_admin_can_see_dispute_events_via_audit_log_but_not_dispute_ui(admin_client, admin_app):
    dispute_id = _create_dispute(admin_app)
    _staff, staff_secret = _create_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234567",
    )
    _login_admin(admin_client, staff_secret, "bank.staff@sit.singaporetech.edu.sg")
    admin_client.get("/disputes")
    admin_client.get(f"/disputes/{dispute_id}")
    admin_client.post("/logout")

    _admin, admin_secret = _create_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234570",
    )
    _login_admin(admin_client, admin_secret, "security.admin@sit.singaporetech.edu.sg")

    audit_log = admin_client.get("/audit-logs?event_type=dispute_queue_review").get_data(as_text=True)
    assert "dispute_queue_review" in audit_log

    # Confirmed above that this same admin session gets 403 on the actual queue.
    assert admin_client.get("/disputes").status_code == 403


def test_dispute_transition_rolls_back_when_audit_write_fails(admin_app, monkeypatch):
    dispute_id = _create_dispute(admin_app)

    def fail_required_audit(*_args, **_kwargs):
        raise AuditWriteError("audit unavailable")

    monkeypatch.setattr("app.admin.services.audit_event_required", fail_required_audit)

    with admin_app.app_context():
        staff = User(
            username="rollback-staff",
            email="rollback-staff@sit.singaporetech.edu.sg",
            password_hash="not-used",
            account_type="staff",
            account_status="active",
            full_name="Rollback Staff",
            phone_number="91112224",
            mfa_enabled=True,
            workplace_email_verified_at=datetime.now(timezone.utc),
        )
        db.session.add(staff)
        db.session.commit()

        with pytest.raises(AuditWriteError):
            transition_dispute_status_for_staff(staff, dispute_id, "resolved", "should not persist")

        db.session.expire_all()
        dispute = db.session.get(TransactionDispute, dispute_id)
        assert dispute.status == "open"
        assert dispute.resolver_id is None
        assert dispute.resolution_note is None


def test_dispute_queue_read_fails_closed_when_audit_write_fails(admin_app, monkeypatch):
    _create_dispute(admin_app)

    def fail_required_audit(*_args, **_kwargs):
        raise AuditWriteError("audit unavailable")

    monkeypatch.setattr("app.admin.services.audit_event_required", fail_required_audit)

    with admin_app.app_context():
        staff = User(
            username="read-fail-staff",
            email="read-fail-staff@sit.singaporetech.edu.sg",
            password_hash="not-used",
            account_type="staff",
            account_status="active",
            full_name="Read Fail Staff",
            phone_number="91112230",
            mfa_enabled=True,
            workplace_email_verified_at=datetime.now(timezone.utc),
        )
        db.session.add(staff)
        db.session.commit()

        with pytest.raises(AuditWriteError):
            disputes_for_staff(staff)


def test_dispute_detail_read_fails_closed_when_audit_write_fails(admin_app, monkeypatch):
    dispute_id = _create_dispute(admin_app)

    def fail_required_audit(*_args, **_kwargs):
        raise AuditWriteError("audit unavailable")

    monkeypatch.setattr("app.admin.services.audit_event_required", fail_required_audit)

    with admin_app.app_context():
        staff = User(
            username="detail-fail-staff",
            email="detail-fail-staff@sit.singaporetech.edu.sg",
            password_hash="not-used",
            account_type="staff",
            account_status="active",
            full_name="Detail Fail Staff",
            phone_number="91112231",
            mfa_enabled=True,
            workplace_email_verified_at=datetime.now(timezone.utc),
        )
        db.session.add(staff)
        db.session.commit()

        with pytest.raises(AuditWriteError):
            dispute_detail_for_staff(staff, dispute_id)
