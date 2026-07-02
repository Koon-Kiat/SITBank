from __future__ import annotations

import hashlib
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
import pyotp

from _auth_flow_helpers import enable_mfa_for_user, login, mark_recent_mfa, register
from app.auth.services import AuthError
from app.banking.services import (
    execute_payup_transfer,
    payup_amount_used_today,
    payup_requires_step_up,
    sgt_day_start_utc,
)
from app.extensions import db
from app.models import PayupPendingTransfer, Transaction, User


def _make_payup_pending(
    user: User,
    recipient: User,
    amount: Decimal,
    reference: str = "",
    *,
    expires_in: int = 300,
) -> str:
    token = os.urandom(32).hex()
    pending = PayupPendingTransfer(
        token=token,
        user_id=user.id,
        recipient_user_id=recipient.id,
        amount=amount,
        reference=reference,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
    )
    db.session.add(pending)
    db.session.commit()
    return token


def _make_payup_transaction(
    sender: User,
    recipient: User,
    amount: Decimal,
    *,
    created_at: datetime | None = None,
    status: str = "completed",
) -> Transaction:
    txn = Transaction(
        transaction_ref=str(uuid.uuid4()),
        transaction_hash=hashlib.sha256(os.urandom(16)).hexdigest(),
        sender_id=sender.id,
        recipient_id=recipient.id,
        payee_id=None,
        amount=amount,
        reference="",
        status=status,
        transaction_type="payup",
        created_at=created_at or datetime.now(timezone.utc),
    )
    db.session.add(txn)
    db.session.commit()
    return txn


@pytest.fixture()
def payup_context(app, client):
    bob_client = app.test_client()

    register(
        client,
        username="alice01",
        email="alice@example.com",
        full_name="Alice Sender",
        phone_number="91234567",
    )
    register(
        bob_client,
        username="bob02",
        email="bob@example.com",
        full_name="Bob Recipient",
        phone_number="81234567",
    )

    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    bob = db.session.execute(db.select(User).where(User.username == "bob02")).scalar_one()
    alice.account_number = "111111111"
    bob.account_number = "222222222"
    alice.balance = Decimal("5000.00")
    bob.balance = Decimal("1000.00")
    alice.account_type = bob.account_type = "customer"
    alice.account_status = bob.account_status = "active"
    db.session.commit()

    login(client, identifier="alice01")
    alice, alice_secret = enable_mfa_for_user("alice01")
    mark_recent_mfa(client, alice)

    return {"alice": alice, "alice_secret": alice_secret, "bob": bob}


# ── Daily-limit accounting ───────────────────────────────────────────────────────

def test_payup_amount_used_today_ignores_failed_and_other_channel_transactions(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    _make_payup_transaction(alice, bob, Decimal("50.00"))
    _make_payup_transaction(alice, bob, Decimal("30.00"), status="failed")
    db.session.add(
        Transaction(
            transaction_ref=str(uuid.uuid4()),
            transaction_hash=hashlib.sha256(os.urandom(16)).hexdigest(),
            sender_id=alice.id,
            recipient_id=bob.id,
            payee_id=None,
            amount=Decimal("999.00"),
            reference="",
            status="completed",
            transaction_type="local_transfer",
            created_at=datetime.now(timezone.utc),
        )
    )
    db.session.commit()

    assert payup_amount_used_today(alice) == Decimal("50.00")


def test_daily_limit_resets_at_midnight_sgt(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    before_midnight_sgt = sgt_day_start_utc() - timedelta(hours=1)
    _make_payup_transaction(alice, bob, Decimal("400.00"), created_at=before_midnight_sgt)

    assert payup_amount_used_today(alice) == Decimal("0")


def test_payup_requires_step_up_at_eighty_percent_threshold(app, payup_context):
    alice = payup_context["alice"]

    assert Decimal(str(alice.payup_daily_limit)) == Decimal("500.00")
    assert payup_requires_step_up(alice, Decimal("100.00")) is False
    assert payup_requires_step_up(alice, Decimal("399.99")) is False
    assert payup_requires_step_up(alice, Decimal("400.00")) is True


# ── execute_payup_transfer: correctness and fail-closed behavior ────────────────

def test_execute_payup_transfer_debits_sender_and_credits_recipient(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    alice_before = Decimal(str(alice.balance))
    bob_before = Decimal(str(bob.balance))
    amount = Decimal("100.00")
    token = _make_payup_pending(alice, bob, amount, reference="Lunch")

    with app.test_request_context("/banking/payup/confirm", method="POST"):
        txn_ref = execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    db.session.expire_all()
    alice_after = db.session.get(User, alice.id)
    bob_after = db.session.get(User, bob.id)

    assert Decimal(str(alice_after.balance)) == alice_before - amount
    assert Decimal(str(bob_after.balance)) == bob_before + amount

    txn = db.session.execute(
        db.select(Transaction).where(Transaction.transaction_ref == txn_ref)
    ).scalar_one()
    assert txn.sender_id == alice.id
    assert txn.recipient_id == bob.id
    assert Decimal(str(txn.amount)) == amount
    assert txn.reference == "Lunch"
    assert txn.status == "completed"
    assert txn.transaction_type == "payup"
    assert txn.payee_id is None


def test_execute_payup_transfer_self_transfer_blocked(app, payup_context):
    alice = payup_context["alice"]
    token = _make_payup_pending(alice, alice, Decimal("10.00"))

    with app.test_request_context("/banking/payup/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert "yourself" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


def test_execute_payup_transfer_recipient_unavailable_blocked(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]
    bob.account_status = "revoked"
    db.session.commit()

    token = _make_payup_pending(alice, bob, Decimal("10.00"))

    with app.test_request_context("/banking/payup/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert "not available" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


def test_execute_payup_transfer_exceeding_daily_limit_blocked(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    token = _make_payup_pending(alice, bob, Decimal("600.00"))

    with app.test_request_context("/banking/payup/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert "daily payup limit" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


def test_execute_payup_transfer_requires_authorization_above_threshold(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    token = _make_payup_pending(alice, bob, Decimal("450.00"))

    with app.test_request_context("/banking/payup/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert "authenticator" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


def test_execute_payup_transfer_succeeds_when_authorized_above_threshold(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    token = _make_payup_pending(alice, bob, Decimal("450.00"))

    with app.test_request_context("/banking/payup/confirm", method="POST"):
        txn_ref = execute_payup_transfer(sender=alice, confirmation_token=token, authorized=True)

    assert Transaction.query.filter_by(transaction_ref=txn_ref).count() == 1


def test_execute_payup_transfer_token_replay_blocked(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    token = _make_payup_pending(alice, bob, Decimal("50.00"))

    with app.test_request_context("/banking/payup/confirm", method="POST"):
        execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert "expired or was already used" in exc_info.value.message.lower()
    assert Transaction.query.count() == 1


def test_execute_payup_transfer_expired_token_blocked(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    token = _make_payup_pending(alice, bob, Decimal("50.00"), expires_in=-1)

    with app.test_request_context("/banking/payup/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert "expired" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


# ── Phone lookup route ───────────────────────────────────────────────────────────

def test_payup_phone_lookup_success_redirects_to_amount(client, payup_context):
    response = client.post("/banking/payup", data={"phone_number": "81234567"})

    assert response.status_code == 302
    assert "payup/amount" in response.headers["Location"]

    with client.session_transaction() as sess:
        pending = sess.get("pending_payup_recipient")
    assert pending is not None
    assert pending["recipient_name"] == "Bob Recipient"


def test_payup_phone_lookup_unknown_number_shows_error(client, payup_context):
    response = client.post("/banking/payup", data={"phone_number": "89999999"})

    assert response.status_code == 400
    assert b"Invalid phone number" in response.data


def test_payup_phone_lookup_self_number_blocked(client, payup_context):
    response = client.post("/banking/payup", data={"phone_number": "91234567"})

    assert response.status_code == 400
    assert b"own phone number" in response.data


# ── Amount step: daily limit enforcement ─────────────────────────────────────────

def test_payup_amount_rejects_amount_exceeding_daily_limit(client, payup_context):
    client.post("/banking/payup", data={"phone_number": "81234567"})

    response = client.post("/banking/payup/amount", data={"amount": "600.00"})

    assert response.status_code == 400
    assert b"exceed your daily PayUp limit" in response.data
    assert PayupPendingTransfer.query.count() == 0


def test_payup_amount_rejects_amount_exceeding_available_balance(client, payup_context):
    alice = payup_context["alice"]
    alice.balance = Decimal("50.00")
    db.session.commit()

    client.post("/banking/payup", data={"phone_number": "81234567"})

    # Under the 500 SGD daily limit, but over the 50.00 available balance.
    response = client.post("/banking/payup/amount", data={"amount": "100.00"})

    assert response.status_code == 400
    assert b"Insufficient balance" in response.data
    assert PayupPendingTransfer.query.count() == 0


def test_payup_amount_accepts_amount_under_limit(client, payup_context):
    client.post("/banking/payup", data={"phone_number": "81234567"})

    response = client.post("/banking/payup/amount", data={"amount": "100.00"})

    assert response.status_code == 302
    assert "payup/confirm" in response.headers["Location"]
    assert PayupPendingTransfer.query.count() == 1


# ── Full route flow: conditional MFA step-up ─────────────────────────────────────

def test_complete_payup_route_flow_below_threshold_no_mfa(client, payup_context):
    client.post("/banking/payup", data={"phone_number": "81234567"})
    client.post("/banking/payup/amount", data={"amount": "100.00", "reference": "Lunch"})

    confirm_page = client.get("/banking/payup/confirm")
    assert confirm_page.status_code == 200
    assert b"Authenticator code" not in confirm_page.data

    confirm_submit = client.post("/banking/payup/confirm", data={})
    assert confirm_submit.status_code == 302
    assert Transaction.query.filter_by(reference="Lunch", transaction_type="payup").count() == 1


def test_complete_payup_route_flow_crossing_threshold_requires_mfa(client, payup_context, monkeypatch):
    alice_secret = payup_context["alice_secret"]

    client.post("/banking/payup", data={"phone_number": "81234567"})
    client.post("/banking/payup/amount", data={"amount": "450.00"})

    confirm_page = client.get("/banking/payup/confirm")
    assert b"Authenticator code" in confirm_page.data

    # A missing code is rejected before touching the failed-attempt backoff
    # counter, so it does not block the subsequent valid attempt below.
    missing_mfa = client.post("/banking/payup/confirm", data={})
    assert missing_mfa.status_code == 403
    assert Transaction.query.count() == 0

    stepup_time = int(time.time())
    totp_code = pyotp.TOTP(alice_secret, digits=6, interval=30).at(stepup_time)
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)

    confirm_submit = client.post("/banking/payup/confirm", data={"totp_code": totp_code})
    assert confirm_submit.status_code == 302
    assert Transaction.query.filter_by(transaction_type="payup").count() == 1


def test_payup_confirm_rejects_wrong_totp_code(client, payup_context):
    client.post("/banking/payup", data={"phone_number": "81234567"})
    client.post("/banking/payup/amount", data={"amount": "450.00"})

    response = client.post("/banking/payup/confirm", data={"totp_code": "000000"})

    assert response.status_code == 401
    assert Transaction.query.count() == 0
