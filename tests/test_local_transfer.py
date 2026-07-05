from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import Mock

import pytest
import pyotp

from _auth_flow_helpers import enable_mfa_for_user, login, mark_recent_mfa, register
from app.auth.services import AuthError
from app.banking.services import (
    execute_local_transfer,
    local_transfer_amount_used_today,
    local_transfer_token_verifier,
    sgt_day_start_utc,
)
from app.extensions import db
from app.models import Payee, PendingTransfer, SecurityAuditEvent, Transaction, User
from app.security.passwords import hash_password
from app.security.transaction_integrity import sign_transaction_integrity


def _make_pending_transfer(
    user: User,
    payee: Payee,
    amount: Decimal,
    reference: str = "",
    *,
    expires_in: int = 300,
) -> str:
    token = os.urandom(32).hex()
    pending = PendingTransfer(
        token=local_transfer_token_verifier(token),
        user_id=user.id,
        payee_id=payee.id,
        amount=amount,
        reference=reference,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
    )
    db.session.add(pending)
    db.session.commit()
    return token


def _make_active_payee(owner: User, account_number: str, recipient_name: str) -> Payee:
    payee = Payee(
        user_id=owner.id,
        nickname="Test Payee",
        account_number=account_number,
        recipient_name=recipient_name,
        created_at=datetime.now(timezone.utc) - timedelta(days=2),
    )
    db.session.add(payee)
    db.session.commit()
    return payee


def _make_cooldown_payee(owner: User, account_number: str, recipient_name: str) -> Payee:
    payee = Payee(
        user_id=owner.id,
        nickname="Cooldown Payee",
        account_number=account_number,
        recipient_name=recipient_name,
        created_at=datetime.now(timezone.utc),
    )
    db.session.add(payee)
    db.session.commit()
    return payee


@pytest.fixture()
def transfer_context(app, client):
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
    alice.account_number = "111111111000"
    bob.account_number = "222222222000"
    alice.balance = Decimal("5000.00")
    bob.balance = Decimal("1000.00")
    alice.account_type = bob.account_type = "customer"
    alice.account_status = bob.account_status = "active"
    db.session.commit()

    login(client, identifier="alice01")
    alice, alice_secret = enable_mfa_for_user("alice01")
    mark_recent_mfa(client, alice)

    payee = _make_active_payee(alice, bob.account_number, bob.full_name)

    return {
        "alice": alice,
        "alice_secret": alice_secret,
        "bob": bob,
        "payee": payee,
    }


# ── A04: cooldown enforcement ──────────────────────────────────────────────────

def test_transfer_blocked_during_cooldown(client, transfer_context):
    alice = transfer_context["alice"]
    cooldown_payee = _make_cooldown_payee(alice, "333333333000", "Carol")

    response = client.get(f"/banking/transfer/{cooldown_payee.id}")

    # Must redirect — never show the transfer form for a payee in cooldown
    assert response.status_code == 302
    assert "payees" in response.headers["Location"]


def test_transfer_submit_blocked_during_cooldown(client, transfer_context):
    alice = transfer_context["alice"]
    cooldown_payee = _make_cooldown_payee(alice, "444444444000", "Dave")

    response = client.post(
        f"/banking/transfer/{cooldown_payee.id}",
        data={"amount": "10.00", "totp_code": "123456"},
    )

    assert response.status_code == 302
    assert Transaction.query.count() == 0


# ── A01: IDOR — cannot access another user's payee transfer page ───────────────

def test_transfer_page_returns_404_for_other_users_payee(app, client, transfer_context):
    carol = User(
        username="carol03",
        email="carol@example.com",
        full_name="Carol Other",
        phone_number="71234567",
        account_number="555555555000",
        account_status="active",
        account_type="customer",
        password_hash=hash_password("correct horse battery staple"),
        balance=Decimal("500.00"),
    )
    db.session.add(carol)
    db.session.commit()

    carol_payee = _make_active_payee(carol, "666666666000", "Eve")

    # Alice (logged in via `client`) tries to access Carol's payee
    response = client.get(f"/banking/transfer/{carol_payee.id}")

    assert response.status_code == 404
    assert b"Eve" not in response.data


def test_transfer_submit_idor_check_runs_before_mfa(app, client, transfer_context, monkeypatch):
    from app.banking import routes as banking_routes

    carol = User(
        username="carol04",
        email="carol04@example.com",
        full_name="Carol Other",
        phone_number="61234567",
        account_number="777777777000",
        account_status="active",
        account_type="customer",
        password_hash=hash_password("correct horse battery staple"),
        balance=Decimal("500.00"),
    )
    db.session.add(carol)
    db.session.commit()

    carol_payee = _make_active_payee(carol, "888888888000", "Frank")

    mfa_mock = Mock(side_effect=AssertionError("MFA reached before IDOR check"))
    monkeypatch.setattr(banking_routes, "verify_high_risk_authorization", mfa_mock)

    response = client.post(
        f"/banking/transfer/{carol_payee.id}",
        data={"amount": "10.00", "totp_code": "123456"},
    )

    assert response.status_code == 404
    mfa_mock.assert_not_called()
    assert Transaction.query.count() == 0


# ── A04: insufficient funds rejected server-side ──────────────────────────────

def test_transfer_fails_on_insufficient_funds(app, transfer_context):
    alice = transfer_context["alice"]
    payee = transfer_context["payee"]

    alice.balance = Decimal("5.00")
    db.session.commit()

    token = _make_pending_transfer(alice, payee, Decimal("100.00"))

    from app.auth.services import AuthError

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    assert "insufficient" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


def test_insufficient_funds_writes_failure_audit(app, transfer_context):
    alice = transfer_context["alice"]
    payee = transfer_context["payee"]

    alice.balance = Decimal("1.00")
    db.session.commit()

    token = _make_pending_transfer(alice, payee, Decimal("999.00"))

    from app.auth.services import AuthError

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError):
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    event = db.session.execute(
        db.select(SecurityAuditEvent).where(
            SecurityAuditEvent.event_type == "banking_outbound_transfer",
            SecurityAuditEvent.outcome == "failure",
            SecurityAuditEvent.user_id == alice.id,
        )
    ).scalars().first()
    assert event is not None
    assert event.event_metadata.get("reason") == "insufficient_funds"


# ── Core: successful transfer ──────────────────────────────────────────────────

def test_successful_transfer_debits_sender_and_credits_recipient(app, transfer_context):
    alice = transfer_context["alice"]
    bob = transfer_context["bob"]
    payee = transfer_context["payee"]

    alice_before = Decimal(str(alice.balance))
    bob_before = Decimal(str(bob.balance))
    amount = Decimal("250.00")
    token = _make_pending_transfer(alice, payee, amount, reference="Rent")

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        txn_ref = execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

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
    assert txn.reference == "Rent"
    assert txn.status == "completed"


def test_successful_transfer_writes_durable_audit_and_redacts_pii(app, transfer_context):
    alice = transfer_context["alice"]
    payee = transfer_context["payee"]

    token = _make_pending_transfer(alice, payee, Decimal("50.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        txn_ref = execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    event = db.session.execute(
        db.select(SecurityAuditEvent).where(
            SecurityAuditEvent.event_type == "banking_outbound_transfer",
            SecurityAuditEvent.outcome == "success",
            SecurityAuditEvent.user_id == alice.id,
        )
    ).scalars().first()
    assert event is not None

    serialized = str(event.event_metadata)
    # Raw account number and transaction ref must not appear — only hashed references
    assert payee.account_number not in serialized
    assert txn_ref not in serialized


# ── A04: anti-replay — pending transfer consumed on confirm ────────────────────

def test_confirm_post_without_pending_session_redirects_to_payees(client, transfer_context):
    payee_id = transfer_context["payee"].id

    response = client.post(f"/banking/transfer/{payee_id}/confirm")

    assert response.status_code == 302
    assert "payees" in response.headers["Location"]
    assert Transaction.query.count() == 0


def test_confirm_get_without_pending_session_redirects(client, transfer_context):
    payee_id = transfer_context["payee"].id

    response = client.get(f"/banking/transfer/{payee_id}/confirm")

    assert response.status_code == 302
    assert Transaction.query.count() == 0


def test_complete_transfer_route_flow(client, transfer_context, monkeypatch):
    payee = transfer_context["payee"]
    stepup_time = int(time.time())
    totp_code = pyotp.TOTP(
        transfer_context["alice_secret"],
        digits=6,
        interval=30,
    ).at(stepup_time)

    form_response = client.get(f"/banking/transfer/{payee.id}")
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)
    submit_response = client.post(
        f"/banking/transfer/{payee.id}",
        data={"amount": "25.00", "reference": "Coverage", "totp_code": totp_code},
    )
    confirm_response = client.get(f"/banking/transfer/{payee.id}/confirm")
    complete_response = client.post(f"/banking/transfer/{payee.id}/confirm")

    assert form_response.status_code == 200
    assert submit_response.status_code == 302
    assert confirm_response.status_code == 200
    assert complete_response.status_code == 302
    assert Transaction.query.filter_by(reference="Coverage").count() == 1


def test_transfer_stepup_accepts_matching_legacy_session_context(
    client,
    transfer_context,
    monkeypatch,
):
    from app.security.sessions import SESSION_RISK_CONTEXT_KEY, SESSION_RISK_FINGERPRINT_KEY

    payee = transfer_context["payee"]
    secret = transfer_context["alice_secret"]
    client.post("/logout")
    password_response = login(client, identifier="alice01")
    login_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: login_time)
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(login_time)},
    )
    with client.session_transaction() as sess:
        assert sess.get(SESSION_RISK_FINGERPRINT_KEY)
        sess.pop(SESSION_RISK_CONTEXT_KEY)

    stepup_time = login_time + 1
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)
    submit_response = client.post(
        f"/banking/transfer/{payee.id}",
        data={
            "amount": "25.00",
            "reference": "Legacy context",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(stepup_time),
        },
    )
    with client.session_transaction() as sess:
        assert sess.get("pending_transfer_token")

    confirm_response = client.get(f"/banking/transfer/{payee.id}/confirm")
    complete_response = client.post(f"/banking/transfer/{payee.id}/confirm")

    assert password_response.status_code == 302
    assert mfa_response.status_code == 200
    assert submit_response.status_code == 302
    assert confirm_response.status_code == 200
    assert complete_response.status_code == 302
    assert Transaction.query.filter_by(reference="Legacy context").count() == 1
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk",
        outcome="reauth_required",
    ).count() == 0


def test_transfer_route_handles_invalid_form_and_mfa_error(
    client,
    transfer_context,
):
    payee = transfer_context["payee"]

    invalid_form = client.post(f"/banking/transfer/{payee.id}", data={})
    invalid_mfa = client.post(
        f"/banking/transfer/{payee.id}",
        data={"amount": "25.00", "totp_code": "000000"},
    )

    assert invalid_form.status_code == 400
    assert invalid_mfa.status_code == 401


def test_transfer_confirmation_rejects_missing_and_expired_records(
    client,
    transfer_context,
):
    alice = transfer_context["alice"]
    payee = transfer_context["payee"]

    with client.session_transaction() as session_state:
        session_state["pending_transfer_token"] = "missing-token"
    missing = client.get(f"/banking/transfer/{payee.id}/confirm")

    expired_token = _make_pending_transfer(
        alice,
        payee,
        Decimal("10.00"),
        expires_in=-1,
    )
    with client.session_transaction() as session_state:
        session_state["pending_transfer_token"] = expired_token
    expired = client.get(f"/banking/transfer/{payee.id}/confirm")

    assert missing.status_code == 302
    assert expired.status_code == 302


def test_transfer_confirmation_handles_validation_and_service_errors(
    client,
    transfer_context,
    monkeypatch,
):
    from app.banking import routes as banking_routes

    class InvalidForm:
        def validate_on_submit(self):
            return False

    alice = transfer_context["alice"]
    payee = transfer_context["payee"]
    invalid_token = _make_pending_transfer(alice, payee, Decimal("10.00"))
    with client.session_transaction() as session_state:
        session_state["pending_transfer_token"] = invalid_token
    monkeypatch.setattr(banking_routes, "CsrfOnlyForm", InvalidForm)
    invalid = client.post(f"/banking/transfer/{payee.id}/confirm")

    error_token = _make_pending_transfer(alice, payee, Decimal("10.00"))
    with client.session_transaction() as session_state:
        session_state["pending_transfer_token"] = error_token
    monkeypatch.setattr(
        banking_routes,
        "CsrfOnlyForm",
        lambda: type("ValidForm", (), {"validate_on_submit": lambda self: True})(),
    )
    monkeypatch.setattr(
        banking_routes,
        "execute_local_transfer",
        lambda **_kwargs: (_ for _ in ()).throw(AuthError("Transfer denied", 403)),
    )
    denied = client.post(f"/banking/transfer/{payee.id}/confirm")

    assert invalid.status_code == 302
    assert denied.status_code == 302


# ── A03: server-side amount range validation ───────────────────────────────────

def test_transfer_form_rejects_zero_amount(client, transfer_context):
    payee_id = transfer_context["payee"].id

    response = client.post(
        f"/banking/transfer/{payee_id}",
        data={"amount": "0.00", "totp_code": "123456"},
    )

    assert response.status_code == 400
    assert Transaction.query.count() == 0


def test_transfer_form_rejects_amount_above_limit(client, transfer_context):
    payee_id = transfer_context["payee"].id

    response = client.post(
        f"/banking/transfer/{payee_id}",
        data={"amount": "99999999.00", "totp_code": "123456"},
    )

    assert response.status_code == 400
    assert Transaction.query.count() == 0


# ── Route inventory ────────────────────────────────────────────────────────────

def test_transfer_routes_are_registered(app):
    rules = {rule.endpoint for rule in app.url_map.iter_rules()}
    assert "banking.transfer" in rules
    assert "banking.transfer_submit" in rules
    assert "banking.transfer_confirm" in rules
    assert "banking.transfer_confirm_submit" in rules


# ── Daily-limit accounting ───────────────────────────────────────────────────────

def _make_local_transfer_transaction(
    sender: User,
    recipient: User,
    amount: Decimal,
    *,
    created_at: datetime | None = None,
    status: str = "completed",
) -> Transaction:
    created = created_at or datetime.now(timezone.utc)
    transaction_ref = str(uuid.uuid4())
    digest, key_id, algorithm, version = sign_transaction_integrity(
        transaction_ref=transaction_ref,
        sender_id=sender.id,
        recipient_id=recipient.id,
        payee_id=None,
        amount=amount,
        reference="",
        status=status,
        transaction_type="local_transfer",
        created_at=created,
    )
    txn = Transaction(
        transaction_ref=transaction_ref,
        transaction_hash=digest,
        transaction_integrity_key_id=key_id,
        transaction_integrity_algorithm=algorithm,
        transaction_integrity_version=version,
        sender_id=sender.id,
        recipient_id=recipient.id,
        payee_id=None,
        amount=amount,
        reference="",
        status=status,
        transaction_type="local_transfer",
        created_at=created,
    )
    db.session.add(txn)
    db.session.commit()
    return txn


def test_local_transfer_amount_used_today_ignores_failed_and_other_channel_transactions(
    app, transfer_context
):
    alice = transfer_context["alice"]
    bob = transfer_context["bob"]

    _make_local_transfer_transaction(alice, bob, Decimal("50.00"))
    _make_local_transfer_transaction(alice, bob, Decimal("30.00"), status="failed")

    created = datetime.now(timezone.utc)
    transaction_ref = str(uuid.uuid4())
    digest, key_id, algorithm, version = sign_transaction_integrity(
        transaction_ref=transaction_ref,
        sender_id=alice.id,
        recipient_id=bob.id,
        payee_id=None,
        amount=Decimal("999.00"),
        reference="",
        status="completed",
        transaction_type="payup",
        created_at=created,
    )
    db.session.add(
        Transaction(
            transaction_ref=transaction_ref,
            transaction_hash=digest,
            transaction_integrity_key_id=key_id,
            transaction_integrity_algorithm=algorithm,
            transaction_integrity_version=version,
            sender_id=alice.id,
            recipient_id=bob.id,
            payee_id=None,
            amount=Decimal("999.00"),
            reference="",
            status="completed",
            transaction_type="payup",
            created_at=created,
        )
    )
    db.session.commit()

    assert local_transfer_amount_used_today(alice) == Decimal("50.00")


def test_local_transfer_daily_limit_resets_at_midnight_sgt(app, transfer_context):
    alice = transfer_context["alice"]
    bob = transfer_context["bob"]

    before_midnight_sgt = sgt_day_start_utc() - timedelta(hours=1)
    _make_local_transfer_transaction(alice, bob, Decimal("400.00"), created_at=before_midnight_sgt)

    assert local_transfer_amount_used_today(alice) == Decimal("0")


def test_transfer_blocked_when_exceeding_daily_limit(app, transfer_context):
    alice = transfer_context["alice"]
    bob = transfer_context["bob"]
    payee = transfer_context["payee"]

    assert Decimal(str(alice.local_transfer_daily_limit)) == Decimal("500.00")
    _make_local_transfer_transaction(alice, bob, Decimal("450.00"))

    token = _make_pending_transfer(alice, payee, Decimal("100.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    assert "daily local transfer limit" in exc_info.value.message.lower()
    assert Transaction.query.count() == 1  # only the seeded transaction, no new one created


def test_daily_limit_exceeded_writes_failure_audit_and_leaves_balance_unchanged(app, transfer_context):
    alice = transfer_context["alice"]
    bob = transfer_context["bob"]
    payee = transfer_context["payee"]

    _make_local_transfer_transaction(alice, bob, Decimal("450.00"))
    alice_before = Decimal(str(alice.balance))

    token = _make_pending_transfer(alice, payee, Decimal("100.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError):
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    db.session.expire_all()
    alice_after = db.session.get(User, alice.id)
    assert Decimal(str(alice_after.balance)) == alice_before

    event = db.session.execute(
        db.select(SecurityAuditEvent).where(
            SecurityAuditEvent.event_type == "banking_outbound_transfer",
            SecurityAuditEvent.outcome == "failure",
            SecurityAuditEvent.user_id == alice.id,
        )
    ).scalars().first()
    assert event is not None
    assert event.event_metadata.get("reason") == "daily_limit_exceeded"


def test_transfer_within_daily_limit_after_prior_transfers_succeeds(app, transfer_context):
    alice = transfer_context["alice"]
    bob = transfer_context["bob"]
    payee = transfer_context["payee"]

    _make_local_transfer_transaction(alice, bob, Decimal("400.00"))

    token = _make_pending_transfer(alice, payee, Decimal("100.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        txn_ref = execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    assert Transaction.query.filter_by(transaction_ref=txn_ref).count() == 1


def test_transfer_submit_route_blocks_when_exceeding_daily_limit(client, transfer_context):
    alice = transfer_context["alice"]
    bob = transfer_context["bob"]
    payee = transfer_context["payee"]

    _make_local_transfer_transaction(alice, bob, Decimal("450.00"))

    response = client.post(
        f"/banking/transfer/{payee.id}",
        data={"amount": "100.00", "totp_code": "123456"},
    )

    assert response.status_code == 400
    assert b"daily Local Transfer limit" in response.data
    assert PendingTransfer.query.count() == 0
