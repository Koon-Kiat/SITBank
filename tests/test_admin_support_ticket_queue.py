from __future__ import annotations

from datetime import datetime, timezone

import pytest
import sqlalchemy

import app.admin.services as admin_services
from app.admin.services import (
    support_ticket_detail_for_staff,
    support_tickets_for_staff,
    transition_support_ticket_status_for_staff,
)
from app.extensions import db
from app.models import SecurityAuditEvent, SupportTicket, User
from app.security.audit import AuditWriteError
from test_admin_dashboard_role_separation import (
    ROOT_EMAIL,
    _create_identity,
    _login_admin,
    admin_app,
    admin_client,
    freeze_totp_verifier_time,
)


def _create_ticket(admin_app) -> int:
    with admin_app.app_context():
        customer = User(
            username="ticket-alice",
            email="ticket-alice@example.com",
            password_hash="not-used",
            account_type="customer",
            account_status="active",
            full_name="Ticket Alice",
            phone_number="91114444",
            account_number="100000004000",
        )
        db.session.add(customer)
        db.session.flush()

        ticket = SupportTicket(
            user_id=customer.id,
            category="enquiry",
            subject="Role separation test subject",
            description="Role separation test description",
            status="open",
        )
        db.session.add(ticket)
        db.session.commit()
        return ticket.id


def test_plain_staff_can_resolve_ticket_without_leaking_note_to_audit_log(admin_client, admin_app):
    ticket_id = _create_ticket(admin_app)
    _staff, secret = _create_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    response = admin_client.post(
        f"/support-tickets/{ticket_id}/status",
        data={"status": "resolved", "resolution_note": "Explained the transaction to the customer by phone"},
    )
    assert response.status_code == 303

    with admin_app.app_context():
        ticket = db.session.get(SupportTicket, ticket_id)
        assert ticket.status == "resolved"
        assert ticket.resolution_note == "Explained the transaction to the customer by phone"

        audit_row = db.session.execute(
            db.select(SecurityAuditEvent).where(
                SecurityAuditEvent.event_type == "support_ticket_status_change"
            )
        ).scalar_one()
        serialized_metadata = str(audit_row.event_metadata)
        assert "Explained the transaction" not in serialized_metadata
        assert audit_row.event_metadata["to_status"] == "resolved"


def test_plain_staff_can_access_support_ticket_queue(admin_client, admin_app):
    ticket_id = _create_ticket(admin_app)
    _staff, secret = _create_identity(
        username="bank-staff",
        email="bank.staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91234567",
    )
    _login_admin(admin_client, secret, "bank.staff@sit.singaporetech.edu.sg")

    list_response = admin_client.get("/support-tickets")
    detail_response = admin_client.get(f"/support-tickets/{ticket_id}")

    assert list_response.status_code == 200
    assert "Support tickets" in list_response.get_data(as_text=True)
    assert detail_response.status_code == 200
    assert "Role separation test description" in detail_response.get_data(as_text=True)


def test_admin_and_root_admin_are_excluded_from_support_ticket_queue(admin_client, admin_app):
    ticket_id = _create_ticket(admin_app)

    _admin, admin_secret = _create_identity(
        username="security-admin",
        email="security.admin@sit.singaporetech.edu.sg",
        account_type="admin",
        phone_number="91234567",
    )
    _login_admin(admin_client, admin_secret, "security.admin@sit.singaporetech.edu.sg")
    assert admin_client.get("/support-tickets").status_code == 403
    assert admin_client.get(f"/support-tickets/{ticket_id}").status_code == 403
    assert (
        admin_client.post(
            f"/support-tickets/{ticket_id}/status",
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
    assert admin_client.get("/support-tickets").status_code == 403
    assert admin_client.get(f"/support-tickets/{ticket_id}").status_code == 403


def test_unauthenticated_request_is_denied(admin_client, admin_app):
    ticket_id = _create_ticket(admin_app)
    assert admin_client.get("/support-tickets").status_code == 401
    assert admin_client.get(f"/support-tickets/{ticket_id}").status_code == 401


@pytest.mark.parametrize("terminal_status", ["resolved", "closed"])
def test_terminal_ticket_cannot_be_transitioned_again(admin_client, admin_app, terminal_status):
    ticket_id = _create_ticket(admin_app)
    _staff, secret = _create_identity(
        username="terminal-staff",
        email="terminal-staff@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91112225",
    )
    _login_admin(admin_client, secret, "terminal-staff@sit.singaporetech.edu.sg")

    first = admin_client.post(
        f"/support-tickets/{ticket_id}/status",
        data={"status": terminal_status, "resolution_note": "first decision"},
    )
    assert first.status_code == 303

    second = admin_client.post(
        f"/support-tickets/{ticket_id}/status",
        data={"status": "in_review", "resolution_note": "attempted reopen"},
    )
    assert second.status_code == 409

    with admin_app.app_context():
        ticket = db.session.get(SupportTicket, ticket_id)
        assert ticket.status == terminal_status
        assert ticket.resolution_note == "first decision"


def test_ticket_transition_rejects_stale_concurrent_status_change(admin_client, admin_app, monkeypatch):
    ticket_id = _create_ticket(admin_app)
    staff_a, _secret_a = _create_identity(
        username="racer-staff-a",
        email="racer-staff-a@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91112226",
    )
    _staff_b, secret_b = _create_identity(
        username="racer-staff-b",
        email="racer-staff-b@sit.singaporetech.edu.sg",
        account_type="staff",
        phone_number="91112227",
    )

    original_lookup = admin_services._support_ticket_or_404

    def racy_lookup(ticket_id_arg):
        ticket = original_lookup(ticket_id_arg)
        with db.engine.begin() as conn:
            conn.execute(
                sqlalchemy.text(
                    "UPDATE support_tickets SET status = :status, resolved_by_user_id = :resolved_by WHERE id = :id"
                ),
                {"status": "in_review", "resolved_by": staff_a.id, "id": ticket_id_arg},
            )
        return ticket

    monkeypatch.setattr(admin_services, "_support_ticket_or_404", racy_lookup)

    _login_admin(admin_client, secret_b, "racer-staff-b@sit.singaporetech.edu.sg")
    response = admin_client.post(
        f"/support-tickets/{ticket_id}/status",
        data={"status": "resolved", "resolution_note": "stale decision"},
    )
    assert response.status_code == 409

    with admin_app.app_context():
        ticket = db.session.get(SupportTicket, ticket_id)
        assert ticket.status == "in_review"
        assert ticket.resolved_by_user_id == staff_a.id
        assert ticket.resolution_note is None


def test_support_ticket_queue_read_fails_closed_when_audit_write_fails(admin_app, monkeypatch):
    _create_ticket(admin_app)

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
            support_tickets_for_staff(staff)


def test_support_ticket_detail_read_fails_closed_when_audit_write_fails(admin_app, monkeypatch):
    ticket_id = _create_ticket(admin_app)

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
            support_ticket_detail_for_staff(staff, ticket_id)


def test_ticket_transition_rolls_back_when_audit_write_fails(admin_app, monkeypatch):
    ticket_id = _create_ticket(admin_app)

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
            transition_support_ticket_status_for_staff(staff, ticket_id, "resolved", "should not persist")

        db.session.expire_all()
        ticket = db.session.get(SupportTicket, ticket_id)
        assert ticket.status == "open"
        assert ticket.resolved_by_user_id is None
        assert ticket.resolution_note is None
