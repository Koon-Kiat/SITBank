"""Security-focused tests for the local transfer service (issue #248).

Covers: payee ownership, self-transfer, decimal precision, DB-backed anti-replay,
token binding, deadlock-safe locking order, and audit redaction.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from app.auth.services import AuthError
from app.banking.services import execute_local_transfer
from app.extensions import db
from app.models import Payee, PendingTransfer, SecurityAuditEvent, Transaction, User
from app.security.passwords import hash_password


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_user(
    username: str,
    account_number: str,
    *,
    balance: Decimal = Decimal("1000.00"),
    account_status: str = "active",
) -> User:
    user = User(
        username=username,
        email=f"{username}@sit.singaporetech.edu.sg",
        full_name=username.capitalize(),
        phone_number="91234567",
        account_number=account_number,
        account_type="customer",
        account_status=account_status,
        password_hash=hash_password("S3cur3P@ss!"),
        balance=balance,
    )
    db.session.add(user)
    db.session.commit()
    return user


def _make_active_payee(owner: User, account_number: str, name: str = "Payee") -> Payee:
    payee = Payee(
        user_id=owner.id,
        nickname=name,
        account_number=account_number,
        recipient_name=name,
        created_at=datetime.now(timezone.utc) - timedelta(days=2),
    )
    db.session.add(payee)
    db.session.commit()
    return payee


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
        token=token,
        user_id=user.id,
        payee_id=payee.id,
        amount=amount,
        reference=reference,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
    )
    db.session.add(pending)
    db.session.commit()
    return token


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture()
def sec_ctx(app):
    """Two users (alice, bob) with a registered payee in cooldown-free state."""
    alice = _make_user("sec_alice", "901000001", balance=Decimal("5000.00"))
    bob = _make_user("sec_bob", "901000002", balance=Decimal("1000.00"))
    payee = _make_active_payee(alice, bob.account_number, "Bob")
    return {"alice": alice, "bob": bob, "payee": payee}


# ── Payee ownership enforcement (service layer) ────────────────────────────────

def test_service_rejects_payee_not_owned_by_sender(app, sec_ctx):
    alice = sec_ctx["alice"]
    bob = sec_ctx["bob"]

    # Create a payee that belongs to bob, not alice
    stranger_payee = Payee(
        user_id=bob.id,
        nickname="Eve",
        account_number="901000003",
        recipient_name="Eve",
        created_at=datetime.now(timezone.utc) - timedelta(days=2),
    )
    db.session.add(stranger_payee)
    db.session.commit()

    token = _make_pending_transfer(alice, stranger_payee, Decimal("10.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_local_transfer(
                sender=alice,
                payee=stranger_payee,
                confirmation_token=token,
            )

    assert exc_info.value.status_code == 403
    assert Transaction.query.count() == 0


# ── Self-transfer ──────────────────────────────────────────────────────────────

def test_service_rejects_self_transfer(app, sec_ctx):
    alice = sec_ctx["alice"]

    self_payee = Payee(
        user_id=alice.id,
        nickname="Myself",
        account_number=alice.account_number,
        recipient_name="Alice",
        created_at=datetime.now(timezone.utc) - timedelta(days=2),
    )
    db.session.add(self_payee)
    db.session.commit()

    token = _make_pending_transfer(alice, self_payee, Decimal("10.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_local_transfer(
                sender=alice,
                payee=self_payee,
                confirmation_token=token,
            )

    assert exc_info.value.status_code == 400
    assert "yourself" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


# ── Recipient account state policy ────────────────────────────────────────────

def test_service_rejects_transfer_to_revoked_account(app, sec_ctx):
    alice = sec_ctx["alice"]
    revoked = _make_user("sec_revoked", "901000010", account_status="revoked")
    payee = _make_active_payee(alice, revoked.account_number, "Revoked")
    token = _make_pending_transfer(alice, payee, Decimal("10.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    assert exc_info.value.status_code == 400
    assert Transaction.query.count() == 0


def test_service_rejects_transfer_to_setup_pending_account(app, sec_ctx):
    alice = sec_ctx["alice"]
    pending_user = _make_user("sec_pend", "901000011", account_status="setup_pending")
    payee = _make_active_payee(alice, pending_user.account_number, "Pending")
    token = _make_pending_transfer(alice, payee, Decimal("10.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError):
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    assert Transaction.query.count() == 0


def test_service_allows_transfer_to_locked_account(app, sec_ctx):
    alice = sec_ctx["alice"]
    locked_user = _make_user("sec_locked", "901000012", account_status="locked")
    payee = _make_active_payee(alice, locked_user.account_number, "Locked")
    token = _make_pending_transfer(alice, payee, Decimal("10.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        txn_ref = execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    assert txn_ref
    assert Transaction.query.count() == 1


# ── Decimal precision enforcement ─────────────────────────────────────────────

def test_service_rejects_amount_with_three_decimal_places(app, sec_ctx):
    alice = sec_ctx["alice"]
    payee = sec_ctx["payee"]
    # Store an over-precision amount directly in the DB (bypasses route validation)
    token = _make_pending_transfer(alice, payee, Decimal("10.001"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    assert exc_info.value.status_code == 400
    assert "decimal" in exc_info.value.message.lower() or "precision" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


def test_service_rejects_amount_with_sub_cent_precision(app, sec_ctx):
    alice = sec_ctx["alice"]
    payee = sec_ctx["payee"]
    token = _make_pending_transfer(alice, payee, Decimal("0.001"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError):
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    assert Transaction.query.count() == 0


def test_service_normalizes_one_decimal_place_to_two(app, sec_ctx):
    alice = sec_ctx["alice"]
    bob = sec_ctx["bob"]
    payee = sec_ctx["payee"]
    token = _make_pending_transfer(alice, payee, Decimal("10.1"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        txn_ref = execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    txn = Transaction.query.filter_by(transaction_ref=txn_ref).one()
    assert Decimal(str(txn.amount)) == Decimal("10.10")


def test_service_accepts_whole_number_amount(app, sec_ctx):
    alice = sec_ctx["alice"]
    payee = sec_ctx["payee"]
    token = _make_pending_transfer(alice, payee, Decimal("10"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        txn_ref = execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    assert txn_ref
    txn = Transaction.query.filter_by(transaction_ref=txn_ref).one()
    assert Decimal(str(txn.amount)) == Decimal("10.00")


# ── DB-backed anti-replay token ────────────────────────────────────────────────

def test_replay_attack_second_consume_fails(app, sec_ctx):
    alice = sec_ctx["alice"]
    payee = sec_ctx["payee"]
    token = _make_pending_transfer(alice, payee, Decimal("10.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        txn_ref = execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)
    assert txn_ref

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    assert exc_info.value.status_code == 409
    assert Transaction.query.count() == 1


def test_sequential_double_submit_results_in_one_transaction(app, sec_ctx):
    """Simulate the concurrent double-submit scenario sequentially."""
    alice = sec_ctx["alice"]
    payee = sec_ctx["payee"]
    token = _make_pending_transfer(alice, payee, Decimal("10.00"))

    results = []
    errors = []

    for _ in range(2):
        try:
            with app.test_request_context("/banking/transfer/confirm", method="POST"):
                ref = execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)
            results.append(ref)
        except AuthError as exc:
            errors.append(exc)

    assert len(results) == 1, "Exactly one transfer should succeed"
    assert len(errors) == 1, "Second attempt must fail"
    assert Transaction.query.count() == 1


def test_expired_token_is_rejected(app, sec_ctx):
    alice = sec_ctx["alice"]
    payee = sec_ctx["payee"]
    token = _make_pending_transfer(alice, payee, Decimal("10.00"), expires_in=-1)

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    assert exc_info.value.status_code == 409
    assert Transaction.query.count() == 0


# ── Token binding ──────────────────────────────────────────────────────────────

def test_token_bound_to_sender_cannot_be_used_by_another_user(app, sec_ctx):
    alice = sec_ctx["alice"]
    bob = sec_ctx["bob"]
    payee = sec_ctx["payee"]

    # Token is minted for alice
    token = _make_pending_transfer(alice, payee, Decimal("10.00"))

    # bob tries to use alice's token (payee belongs to alice, bob has no payee here)
    bob_payee = _make_active_payee(bob, alice.account_number, "Alice")
    token_for_bob = _make_pending_transfer(bob, bob_payee, Decimal("10.00"))

    # Swap: try to pass alice's token but claim it's for bob
    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError):
            execute_local_transfer(sender=bob, payee=bob_payee, confirmation_token=token)

    assert Transaction.query.count() == 0


def test_token_bound_to_payee_rejects_different_payee(app, sec_ctx):
    alice = sec_ctx["alice"]
    bob = sec_ctx["bob"]
    payee = sec_ctx["payee"]

    other_recipient = _make_user("sec_eve", "901000020")
    other_payee = _make_active_payee(alice, other_recipient.account_number, "Eve")

    # Token is minted for original payee
    token = _make_pending_transfer(alice, payee, Decimal("10.00"))

    # Pass a different payee to the service
    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError):
            execute_local_transfer(sender=alice, payee=other_payee, confirmation_token=token)

    assert Transaction.query.count() == 0


def test_unknown_token_is_rejected(app, sec_ctx):
    alice = sec_ctx["alice"]
    payee = sec_ctx["payee"]
    bogus_token = os.urandom(32).hex()

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=bogus_token)

    assert exc_info.value.status_code == 409
    assert Transaction.query.count() == 0


# ── Locking query uses deterministic ORDER BY ─────────────────────────────────

def test_locking_query_uses_ascending_id_order(app, sec_ctx):
    """Verify SELECT FOR UPDATE issues ORDER BY id ASC to prevent deadlocks."""
    from sqlalchemy import event
    from app.extensions import db as ext_db

    alice = sec_ctx["alice"]
    payee = sec_ctx["payee"]
    token = _make_pending_transfer(alice, payee, Decimal("10.00"))

    executed_stmts: list[str] = []

    def _capture(conn, cursor, statement, parameters, context, executemany):
        executed_stmts.append(statement.upper())

    event.listen(ext_db.engine, "before_cursor_execute", _capture)
    try:
        with app.test_request_context("/banking/transfer/confirm", method="POST"):
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)
    finally:
        event.remove(ext_db.engine, "before_cursor_execute", _capture)

    user_selects = [s for s in executed_stmts if "FROM USERS" in s and "ORDER BY" in s]
    assert user_selects, "Expected at least one SELECT FROM users with ORDER BY"
    assert any("ID ASC" in s or "USERS.ID ASC" in s for s in user_selects), (
        "Expected ORDER BY id ASC in the user locking query"
    )


# ── Audit log does not contain raw reference ──────────────────────────────────

def test_raw_reference_not_in_success_audit_metadata(app, sec_ctx):
    alice = sec_ctx["alice"]
    payee = sec_ctx["payee"]
    secret_ref = "PRIVATE-REF-XYZ"
    token = _make_pending_transfer(alice, payee, Decimal("10.00"), reference=secret_ref)

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    event = db.session.execute(
        db.select(SecurityAuditEvent).where(
            SecurityAuditEvent.event_type == "banking_outbound_transfer",
            SecurityAuditEvent.outcome == "success",
            SecurityAuditEvent.user_id == alice.id,
        )
    ).scalars().first()
    assert event is not None
    serialized = str(event.event_metadata)
    assert secret_ref not in serialized, "Raw reference must not appear in audit metadata"


def test_success_audit_metadata_contains_safe_reference_fields(app, sec_ctx):
    alice = sec_ctx["alice"]
    payee = sec_ctx["payee"]
    token = _make_pending_transfer(alice, payee, Decimal("10.00"), reference="Rent")

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    event = db.session.execute(
        db.select(SecurityAuditEvent).where(
            SecurityAuditEvent.event_type == "banking_outbound_transfer",
            SecurityAuditEvent.outcome == "success",
            SecurityAuditEvent.user_id == alice.id,
        )
    ).scalars().first()
    assert event is not None
    meta = event.event_metadata
    assert "reference_present" in meta
    assert "reference_length" in meta
    assert meta["reference_present"] is True
    assert meta["reference_length"] == len("Rent")


def test_empty_reference_reflected_in_audit_metadata(app, sec_ctx):
    alice = sec_ctx["alice"]
    payee = sec_ctx["payee"]
    token = _make_pending_transfer(alice, payee, Decimal("10.00"), reference="")

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    event = db.session.execute(
        db.select(SecurityAuditEvent).where(
            SecurityAuditEvent.event_type == "banking_outbound_transfer",
            SecurityAuditEvent.outcome == "success",
            SecurityAuditEvent.user_id == alice.id,
        )
    ).scalars().first()
    assert event is not None
    meta = event.event_metadata
    assert meta["reference_present"] is False
    assert meta["reference_length"] == 0


# ── Payee cooldown enforcement (service layer) ─────────────────────────────────

def test_service_rejects_payee_in_cooldown(app, sec_ctx):
    alice = sec_ctx["alice"]
    bob = sec_ctx["bob"]

    cooldown_payee = Payee(
        user_id=alice.id,
        nickname="New Payee",
        account_number=bob.account_number,
        recipient_name="Bob",
        created_at=datetime.now(timezone.utc),
    )
    db.session.add(cooldown_payee)
    db.session.commit()

    token = _make_pending_transfer(alice, cooldown_payee, Decimal("10.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError) as exc_info:
            execute_local_transfer(sender=alice, payee=cooldown_payee, confirmation_token=token)

    assert exc_info.value.status_code == 400
    assert "cooldown" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


# ── Atomicity: no partial debit on failure ────────────────────────────────────

def test_failed_transfer_leaves_balances_unchanged(app, sec_ctx):
    alice = sec_ctx["alice"]
    bob = sec_ctx["bob"]
    payee = sec_ctx["payee"]

    alice.balance = Decimal("5.00")
    db.session.commit()

    alice_before = Decimal(str(alice.balance))
    bob_before = Decimal(str(bob.balance))
    token = _make_pending_transfer(alice, payee, Decimal("100.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        with pytest.raises(AuthError):
            execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    db.session.expire_all()
    assert Decimal(str(db.session.get(User, alice.id).balance)) == alice_before
    assert Decimal(str(db.session.get(User, bob.id).balance)) == bob_before
    assert Transaction.query.count() == 0


# ── Consumed token stores transaction reference ────────────────────────────────

def test_consumed_token_stores_transaction_ref(app, sec_ctx):
    alice = sec_ctx["alice"]
    payee = sec_ctx["payee"]
    token = _make_pending_transfer(alice, payee, Decimal("10.00"))

    with app.test_request_context("/banking/transfer/confirm", method="POST"):
        txn_ref = execute_local_transfer(sender=alice, payee=payee, confirmation_token=token)

    db.session.expire_all()
    pending = PendingTransfer.query.filter_by(token=token).one()
    assert pending.consumed_at is not None
    assert pending.consumed_transaction_ref == txn_ref
