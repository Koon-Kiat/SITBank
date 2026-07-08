from __future__ import annotations

from app.extensions import db
from app.models import SecurityAuditEvent, SupportTicket
from app.security.rate_limits import DurableRateLimitExceeded
from test_dashboard import login_with_mfa


def test_support_contact_create_happy_path(client):
    alice = login_with_mfa(client)

    response = client.post(
        "/support/contact",
        data={
            "category": "enquiry",
            "subject": "Question about my account",
            "description": "I have a question about a recent transaction.",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    ticket = db.session.execute(
        db.select(SupportTicket).where(SupportTicket.user_id == alice.id)
    ).scalar_one()
    assert ticket.status == "open"
    assert ticket.category == "enquiry"
    assert ticket.subject == "Question about my account"
    assert ticket.description == "I have a question about a recent transaction."

    audit_row = db.session.execute(
        db.select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "support_ticket_create")
    ).scalar_one()
    serialized_metadata = str(audit_row.event_metadata)
    assert "I have a question about a recent transaction" not in serialized_metadata
    assert audit_row.event_metadata["description_length"] == len(ticket.description)


def test_support_contact_frozen_customer_can_still_submit(client):
    alice = login_with_mfa(client)
    alice.is_frozen = True
    db.session.commit()

    get_response = client.get("/support/contact")
    assert get_response.status_code == 200

    response = client.post(
        "/support/contact",
        data={
            "category": "security_concern",
            "subject": "Why is my account frozen?",
            "description": "I froze my account and want to understand next steps.",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    ticket = db.session.execute(
        db.select(SupportTicket).where(SupportTicket.user_id == alice.id)
    ).scalar_one()
    assert ticket.category == "security_concern"


def test_support_contact_rejects_missing_fields(client):
    login_with_mfa(client)

    response = client.post(
        "/support/contact",
        data={"category": "enquiry", "subject": "", "description": ""},
    )
    assert response.status_code == 400

    tickets = db.session.execute(db.select(SupportTicket)).scalars().all()
    assert tickets == []


def test_support_contact_rejects_invalid_category(client):
    login_with_mfa(client)

    response = client.post(
        "/support/contact",
        data={
            "category": "not_a_real_category",
            "subject": "Tampered field",
            "description": "This should be rejected server-side.",
        },
    )
    assert response.status_code == 400

    tickets = db.session.execute(db.select(SupportTicket)).scalars().all()
    assert tickets == []


def test_support_contact_durable_rate_limit_blocks_without_persisting(client, monkeypatch):
    login_with_mfa(client)

    def block_submission(*_args, **_kwargs):
        raise DurableRateLimitExceeded(3600)

    monkeypatch.setattr("app.web.routes.consume_durable_rate_limit", block_submission)

    response = client.post(
        "/support/contact",
        data={
            "category": "other",
            "subject": "Daily limit should block this",
            "description": "Daily support ticket limit should block this submission.",
        },
        follow_redirects=True,
    )
    assert response.status_code == 429
    assert b"Too many support requests submitted today" in response.data

    tickets = db.session.execute(db.select(SupportTicket)).scalars().all()
    assert tickets == []

    blocked_event = db.session.execute(
        db.select(SecurityAuditEvent).where(
            SecurityAuditEvent.event_type == "support_ticket_create",
            SecurityAuditEvent.outcome == "blocked",
        )
    ).scalar_one()
    assert blocked_event.event_metadata["reason"] == "durable_rate_limit"
    assert blocked_event.event_metadata["retry_after"] == 3600


def test_support_contact_requires_login(client):
    response = client.get("/support/contact")
    assert response.status_code in (302, 401)

    response = client.post(
        "/support/contact",
        data={"category": "enquiry", "subject": "x", "description": "y"},
    )
    assert response.status_code in (302, 401)
