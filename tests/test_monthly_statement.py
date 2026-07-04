from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from app.auth.services import AuthError
from app.banking.services import sgt_month_bounds_utc, statement_for_period
from app.extensions import db
from app.models import Transaction, User
from app.security.passwords import hash_password
from app.security.transaction_integrity import sign_transaction_integrity


def _create_user(username: str, account_number: str, *, created_at: datetime, balance: Decimal) -> User:
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        account_type="customer",
        account_status="active",
        full_name=username.title(),
        phone_number=None,
        account_number=account_number,
        created_at=created_at,
        balance=balance,
    )
    db.session.add(user)
    db.session.commit()
    return user


def _create_transaction(
    sender: User,
    recipient: User,
    amount: Decimal,
    created_at: datetime,
    *,
    status: str = "completed",
) -> Transaction:
    txn_ref = str(uuid.uuid4())
    digest, key_id, algorithm, version = sign_transaction_integrity(
        transaction_ref=txn_ref,
        sender_id=sender.id,
        recipient_id=recipient.id,
        payee_id=None,
        amount=amount,
        reference="Statement test",
        status=status,
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
        reference="Statement test",
        status=status,
        transaction_type="local_transfer",
        created_at=created_at,
    )
    db.session.add(txn)
    db.session.commit()
    return txn


def test_sgt_month_bounds_utc_covers_whole_sgt_month():
    start, end = sgt_month_bounds_utc(2026, 6)
    assert start.isoformat() == "2026-05-31T16:00:00+00:00"
    assert end.isoformat() == "2026-06-30T16:00:00+00:00"


def test_statement_balance_derivation_across_month_boundary(app):
    with app.app_context():
        account_created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        alice = _create_user("stmt-alice", "100000004000", created_at=account_created_at, balance=Decimal("0"))
        bob = _create_user("stmt-bob", "100000005000", created_at=account_created_at, balance=Decimal("0"))

        # May: alice sends 100 to bob (before the statement period).
        _create_transaction(alice, bob, Decimal("100.00"), datetime(2026, 5, 15, tzinfo=timezone.utc))
        # June (the statement period): bob sends 50 to alice, alice sends 30 to bob.
        _create_transaction(bob, alice, Decimal("50.00"), datetime(2026, 6, 10, tzinfo=timezone.utc))
        _create_transaction(alice, bob, Decimal("30.00"), datetime(2026, 6, 20, tzinfo=timezone.utc))
        # A failed June transaction must be excluded from balance math but still listed.
        failed_txn = _create_transaction(
            bob, alice, Decimal("999.00"), datetime(2026, 6, 21, tzinfo=timezone.utc), status="failed"
        )
        # July: bob sends 20 to alice (after the statement period).
        _create_transaction(bob, alice, Decimal("20.00"), datetime(2026, 7, 5, tzinfo=timezone.utc))

        # Net effect on alice across all of the above: -100 + 50 - 30 + 20 = -60.
        alice.balance = Decimal("940.00")
        db.session.commit()

        statement = statement_for_period(alice, 2026, 6)

        assert statement["opening_balance"] == Decimal("900.00")
        assert statement["closing_balance"] == Decimal("920.00")
        txn_ids = {txn.id for txn in statement["transactions"]}
        assert failed_txn.id in txn_ids
        assert len(statement["transactions"]) == 3


def test_statement_rejects_future_period(app):
    with app.app_context():
        alice = _create_user(
            "stmt-future",
            "100000006000",
            created_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
            balance=Decimal("0"),
        )
        with pytest.raises(AuthError):
            statement_for_period(alice, 2099, 1)


def test_statement_rejects_period_entirely_before_account_creation(app):
    with app.app_context():
        alice = _create_user(
            "stmt-precreate",
            "100000007000",
            created_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
            balance=Decimal("0"),
        )
        with pytest.raises(AuthError):
            statement_for_period(alice, 2026, 3)


def test_statement_allows_period_straddling_account_creation(app):
    with app.app_context():
        alice = _create_user(
            "stmt-straddle",
            "100000008000",
            created_at=datetime(2026, 6, 15, tzinfo=timezone.utc),
            balance=Decimal("500.00"),
        )
        statement = statement_for_period(alice, 2026, 6)
        assert statement["opening_balance"] == Decimal("500.00")
        assert statement["closing_balance"] == Decimal("500.00")
