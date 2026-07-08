from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal

import pyotp

from app.extensions import db
from app.models import Transaction, TransactionDispute, User
from app.security.transaction_integrity import sign_transaction_integrity
from test_dashboard import login_with_mfa


def _create_transaction(sender: User, recipient: User, amount: Decimal = Decimal("50.00")) -> Transaction:
    txn_ref = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc)
    digest, key_id, algorithm, version = sign_transaction_integrity(
        transaction_ref=txn_ref,
        sender_id=sender.id,
        recipient_id=recipient.id,
        payee_id=None,
        amount=amount,
        reference="Test transfer",
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
        sender_id=sender.id,
        recipient_id=recipient.id,
        amount=amount,
        reference="Test transfer",
        status="completed",
        transaction_type="local_transfer",
        created_at=created_at,
    )
    db.session.add(txn)
    db.session.commit()
    return txn


def _second_customer(client, username="bob02", email="bob@example.com", phone_number="91234568"):
    """Register a second customer, enable MFA, then log out — returns (user, totp_secret)."""
    from test_dashboard import enable_mfa, login, mark_recent_mfa, register

    register(client, username=username, email=email, full_name="Bob Test", phone_number=phone_number)
    login(client, identifier=username)
    user, secret = enable_mfa(username=username)
    mark_recent_mfa(client, user)
    client.post("/logout")
    return user, secret


def _login_customer(client, username, secret, password="correct horse battery staple"):
    """Re-log-in a customer who already has MFA enabled, completing the real TOTP verify step."""
    from test_dashboard import login

    login(client, identifier=username, password=password)
    verify = client.post("/mfa/verify", json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).now()})
    assert verify.status_code == 302


def _third_customer(client, username="carol03", email="carol@example.com", phone_number="91234569"):
    from test_dashboard import enable_mfa, login, register

    register(client, username=username, email=email, full_name="Carol Test", phone_number=phone_number)
    login(client, identifier=username)
    return enable_mfa(username=username)


def test_party_to_transaction_can_view_it(client):
    alice = login_with_mfa(client)
    client.post("/logout")
    bob, bob_secret = _second_customer(client)
    txn = _create_transaction(alice, bob)

    _login_customer(client, "bob02", bob_secret)
    own_view = client.get(f"/transactions/{txn.id}")
    assert own_view.status_code == 200


def test_non_party_customer_gets_404_on_transaction_detail(client):
    alice = login_with_mfa(client)
    client.post("/logout")
    bob, _bob_secret = _second_customer(client)
    txn = _create_transaction(alice, bob)

    # A third customer, unrelated to this transaction, must not be able to view it.
    _third_customer(client)

    response = client.get(f"/transactions/{txn.id}")
    assert response.status_code == 404


def test_non_party_customer_gets_404_on_dispute_new_and_create(client):
    alice = login_with_mfa(client)
    client.post("/logout")
    bob, _bob_secret = _second_customer(client)
    txn = _create_transaction(alice, bob)

    _third_customer(client)

    get_response = client.get(f"/transactions/{txn.id}/dispute")
    assert get_response.status_code == 404

    post_response = client.post(
        f"/transactions/{txn.id}/dispute",
        data={"issue_type": "other", "reason": "Not my transaction"},
    )
    assert post_response.status_code == 404


def test_non_owner_cannot_view_another_users_dispute(client):
    alice = login_with_mfa(client)
    client.post("/logout")
    bob, bob_secret = _second_customer(client)
    txn = _create_transaction(alice, bob)

    dispute = TransactionDispute(
        transaction_id=txn.id,
        reporter_id=alice.id,
        issue_type="other",
        reason="Some issue only Alice should see",
        status="open",
    )
    db.session.add(dispute)
    db.session.commit()

    _login_customer(client, "bob02", bob_secret)

    # Bob is a party to the transaction, but the dispute was filed by Alice —
    # the transaction detail page must only show his own disputes, not Alice's.
    detail = client.get(f"/transactions/{txn.id}")
    assert detail.status_code == 200
    assert "Some issue only Alice should see" not in detail.data.decode("utf-8")

    my_disputes = client.get("/disputes")
    assert my_disputes.status_code == 200
    assert "Some issue only Alice should see" not in my_disputes.data.decode("utf-8")
