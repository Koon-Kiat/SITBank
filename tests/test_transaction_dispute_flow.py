from __future__ import annotations

from app.extensions import db
from app.models import SecurityAuditEvent, TransactionDispute
from test_dashboard import login_with_mfa
from test_transaction_history_idor import _create_transaction, _second_customer


def test_dispute_create_happy_path(client):
    alice = login_with_mfa(client)
    client.post("/logout")
    bob, bob_secret = _second_customer(client)
    txn = _create_transaction(alice, bob)

    from test_transaction_history_idor import _login_customer

    _login_customer(client, "bob02", bob_secret)

    response = client.post(
        f"/transactions/{txn.id}/dispute",
        data={"issue_type": "incorrect_amount", "reason": "The amount charged was wrong."},
        follow_redirects=True,
    )
    assert response.status_code == 200

    dispute = db.session.execute(
        db.select(TransactionDispute).where(TransactionDispute.transaction_id == txn.id)
    ).scalar_one()
    assert dispute.status == "open"
    assert dispute.reporter_id == bob.id

    audit_row = db.session.execute(
        db.select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "transaction_dispute_create")
    ).scalar_one()
    serialized_metadata = str(audit_row.event_metadata)
    assert "The amount charged was wrong" not in serialized_metadata
    assert audit_row.event_metadata["reason_length"] == len("The amount charged was wrong.")
    assert dispute.issue_type == "incorrect_amount"

    my_disputes = client.get("/disputes").data.decode("utf-8")
    assert "Incorrect amount" in my_disputes


def test_second_open_dispute_on_same_transaction_is_blocked(client):
    alice = login_with_mfa(client)
    client.post("/logout")
    bob, bob_secret = _second_customer(client)
    txn = _create_transaction(alice, bob)

    from test_transaction_history_idor import _login_customer

    _login_customer(client, "bob02", bob_secret)

    first = client.post(
        f"/transactions/{txn.id}/dispute",
        data={"issue_type": "other", "reason": "First report"},
    )
    assert first.status_code == 302

    second = client.post(
        f"/transactions/{txn.id}/dispute",
        data={"issue_type": "other", "reason": "Second report on the same transaction"},
        follow_redirects=True,
    )
    assert second.status_code == 200

    disputes = (
        db.session.execute(
            db.select(TransactionDispute).where(TransactionDispute.transaction_id == txn.id)
        )
        .scalars()
        .all()
    )
    assert len(disputes) == 1
    assert disputes[0].reason == "First report"


def test_dispute_create_rejects_missing_csrf_free_fields(client):
    """Submitting with an unknown issue_type (as if a form field were tampered with) is rejected server-side."""
    alice = login_with_mfa(client)
    client.post("/logout")
    bob, bob_secret = _second_customer(client)
    txn = _create_transaction(alice, bob)

    from test_transaction_history_idor import _login_customer

    _login_customer(client, "bob02", bob_secret)

    response = client.post(
        f"/transactions/{txn.id}/dispute",
        data={"issue_type": "not_a_real_choice", "reason": "Tampered field"},
    )
    assert response.status_code == 400

    disputes = (
        db.session.execute(
            db.select(TransactionDispute).where(TransactionDispute.transaction_id == txn.id)
        )
        .scalars()
        .all()
    )
    assert disputes == []


def test_report_issue_link_hidden_when_counterparty_has_open_dispute(client):
    """The 'already open' state must be transaction-wide, not scoped to the viewer's
    own filed disputes — otherwise a party who didn't file the dispute would see an
    actionable link that the server would then reject on submission."""
    from test_dashboard import enable_mfa, login, mark_recent_mfa, register

    register(client, username="alice01", full_name="Alice Test")
    login(client, identifier="alice01")
    alice, alice_secret = enable_mfa(username="alice01")
    mark_recent_mfa(client, alice)
    client.post("/logout")

    bob, bob_secret = _second_customer(client)
    txn = _create_transaction(alice, bob)

    dispute = TransactionDispute(
        transaction_id=txn.id,
        reporter_id=bob.id,
        issue_type="other",
        reason="Bob's own report",
        status="open",
    )
    db.session.add(dispute)
    db.session.commit()

    from test_transaction_history_idor import _login_customer

    _login_customer(client, "alice01", alice_secret)
    detail = client.get(f"/transactions/{txn.id}")
    assert detail.status_code == 200
    body = detail.data.decode("utf-8")
    assert "Report an Issue" not in body
    assert "already open" in body


def test_dispute_create_requires_reason(client):
    alice = login_with_mfa(client)
    client.post("/logout")
    bob, bob_secret = _second_customer(client)
    txn = _create_transaction(alice, bob)

    from test_transaction_history_idor import _login_customer

    _login_customer(client, "bob02", bob_secret)

    response = client.post(
        f"/transactions/{txn.id}/dispute",
        data={"issue_type": "other", "reason": ""},
    )
    assert response.status_code == 400
