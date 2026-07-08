from __future__ import annotations

import os
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
import pyotp
from flask import session

from _auth_flow_helpers import enable_mfa_for_user, login, mark_recent_mfa, register
from app.auth.services import AuthError
from app.banking.services import (
    evaluate_payup_risk,
    execute_payup_transfer,
    payup_amount_used_today,
    payup_requires_step_up,
    payup_transfer_token_verifier,
    sgt_day_start_utc,
    transaction_hash_matches,
)
from app.extensions import db
from app.models import AuthAttemptCounter, PayupPendingTransfer, SecurityAuditEvent, Transaction, User
from app.security.audit import audit_event
from app.security.transaction_integrity import sign_transaction_integrity
from app.security.sessions import establish_authenticated_session


@contextmanager
def _payup_service_context(app, user: User):
    with app.test_request_context(
        "/banking/payup/confirm",
        method="POST",
        headers={"User-Agent": "SITBank-PayUp-Test/1.0"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        establish_authenticated_session(
            user_id=user.id,
            mfa_verified=True,
            auth_context="password+totp",
        )
        yield


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
        token=payup_transfer_token_verifier(token),
        user_id=user.id,
        recipient_user_id=recipient.id,
        amount=amount,
        reference=reference,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
    )
    db.session.add(pending)
    db.session.commit()
    return token


def _totp_code(secret: str, timestamp: int | None = None) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).at(timestamp or int(time.time()))


def _complete_clean_mfa_login(client, secret: str, monkeypatch) -> int:
    client.post("/logout")
    password_response = login(client, identifier="alice01")
    login_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: login_time)
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": _totp_code(secret, login_time)},
    )
    assert password_response.status_code == 302
    assert mfa_response.status_code == 200
    return login_time


def _payup_lookup_data(
    payup_context: dict,
    phone_number: str = "81234567",
    timestamp: int | None = None,
    totp_code: str | None = None,
) -> dict[str, str]:
    del payup_context, timestamp, totp_code
    return {"phone_number": phone_number}


def _make_payup_transaction(
    sender: User,
    recipient: User,
    amount: Decimal,
    *,
    created_at: datetime | None = None,
    reference: str = "",
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
        reference=reference,
        status=status,
        transaction_type="payup",
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
        reference=reference,
        status=status,
        transaction_type="payup",
        created_at=created,
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
    alice.account_number = "111111111000"
    bob.account_number = "222222222000"
    alice.payup_nickname = "Alice PayUp"
    bob.payup_nickname = "Bob PayUp"
    alice.balance = Decimal("5000.00")
    bob.balance = Decimal("1000.00")
    alice.account_type = bob.account_type = "customer"
    alice.account_status = bob.account_status = "active"
    db.session.commit()

    login(client, identifier="alice01")
    alice, alice_secret = enable_mfa_for_user("alice01")
    mark_recent_mfa(client, alice)

    return {"alice": alice, "alice_secret": alice_secret, "bob": bob, "bob_client": bob_client}


# ── Daily-limit accounting ───────────────────────────────────────────────────────

def test_payup_amount_used_today_ignores_failed_and_other_channel_transactions(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    _make_payup_transaction(alice, bob, Decimal("50.00"))
    _make_payup_transaction(alice, bob, Decimal("30.00"), status="failed")
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
        transaction_type="local_transfer",
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
            transaction_type="local_transfer",
            created_at=created,
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


def test_payup_quick_payment_ignores_daily_limit_percentage_threshold(app, payup_context):
    alice = payup_context["alice"]

    with _payup_service_context(app, alice):
        app.config["PAYUP_QUICK_TRANSFER_CAP"] = 500.0
        app.config["PAYUP_QUICK_DAILY_CAP"] = 1000.0
        assert Decimal(str(alice.payup_daily_limit)) == Decimal("500.00")
        assert payup_requires_step_up(alice, Decimal("100.00")) is False
        assert payup_requires_step_up(alice, Decimal("399.99")) is False
        assert payup_requires_step_up(alice, Decimal("400.00")) is False
        alice.payup_daily_limit = Decimal("100.00")
        db.session.commit()
        assert payup_requires_step_up(alice, Decimal("5.00")) is False
        alice.payup_daily_limit = Decimal("500.00")
        db.session.commit()

        app.config["PAYUP_QUICK_TRANSFER_CAP"] = 200.0
        transfer_cap = evaluate_payup_risk(alice, Decimal("250.00"))
        assert transfer_cap.decision == "step_up"
        assert transfer_cap.reasons == ("quick_transfer_cap",)


def test_payup_risk_policy_covers_caps_stale_sessions_sensitive_events_and_blocks(
    app,
    payup_context,
):
    alice = payup_context["alice"]

    with _payup_service_context(app, alice):
        low_risk = evaluate_payup_risk(alice, Decimal("100.00"))
        assert low_risk.decision == "allow"

        app.config["PAYUP_QUICK_TRANSFER_CAP"] = 50.0
        transfer_cap = evaluate_payup_risk(alice, Decimal("100.00"))
        assert transfer_cap.decision == "step_up"
        assert "quick_transfer_cap" in transfer_cap.reasons

        app.config["PAYUP_QUICK_TRANSFER_CAP"] = 200.0
        session["auth_created_at"] -= (
            app.config["PAYUP_QUICK_SESSION_MAX_AGE_SECONDS"] + 1
        )
        stale = evaluate_payup_risk(alice, Decimal("100.00"))
        assert stale.decision == "block"
        assert "stale_session" in stale.reasons

        session["auth_created_at"] = int(time.time())
        audit_event(
            "profile_update",
            "success",
            user=alice,
            metadata={"updated_fields": "profile_email"},
        )
        sensitive = evaluate_payup_risk(alice, Decimal("100.00"))
        assert sensitive.decision == "block"
        assert "recent_sensitive_event" in sensitive.reasons

        session["risk_reauth_required"] = True
        risky_session = evaluate_payup_risk(alice, Decimal("100.00"))
        assert risky_session.decision == "block"
        assert risky_session.reasons == ("session_risk",)

        session.pop("risk_reauth_required")
        alice.payup_enabled = False
        disabled = evaluate_payup_risk(alice, Decimal("100.00"))
        assert disabled.decision == "block"
        assert disabled.reasons == ("payup_disabled",)

        alice.payup_enabled = True
        app.config.pop("PAYUP_QUICK_DAILY_CAP")
        unavailable = evaluate_payup_risk(alice, Decimal("100.00"))
        assert unavailable.decision == "block"
        assert unavailable.reasons == ("risk_state_unavailable",)


# ── execute_payup_transfer: correctness and fail-closed behavior ────────────────

def test_payup_sensitive_event_cannot_be_hidden_by_later_benign_audit_volume(
    app,
    payup_context,
):
    alice = payup_context["alice"]
    with _payup_service_context(app, alice):
        audit_event(
            "profile_update",
            "success",
            user=alice,
            metadata={"updated_fields": "profile_email"},
        )
        for _index in range(101):
            audit_event(
                "profile_update",
                "success",
                user=alice,
                metadata={"updated_fields": "profile_details"},
            )

        decision = evaluate_payup_risk(alice, Decimal("100.00"))

    assert decision.decision == "block"
    assert "recent_sensitive_event" in decision.reasons


def test_execute_payup_transfer_debits_sender_and_credits_recipient(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    alice_before = Decimal(str(alice.balance))
    bob_before = Decimal(str(bob.balance))
    amount = Decimal("100.00")
    token = _make_payup_pending(alice, bob, amount, reference="Lunch")
    pending = PayupPendingTransfer.query.filter_by(token=payup_transfer_token_verifier(token)).one()
    assert pending.token != token

    with _payup_service_context(app, alice):
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
    assert txn.transaction_integrity_key_id
    assert txn.transaction_integrity_algorithm == "hmac-sha256"
    assert txn.transaction_integrity_version == 1
    assert transaction_hash_matches(txn)


def test_successful_payup_sends_withdrawal_deposit_and_limit_warning(app, payup_context):
    from app.security.email import password_reset_outbox

    alice = payup_context["alice"]
    bob = payup_context["bob"]
    _make_payup_transaction(alice, bob, Decimal("350.00"))
    token = _make_payup_pending(alice, bob, Decimal("50.00"))

    with _payup_service_context(app, alice):
        execute_payup_transfer(sender=alice, confirmation_token=token, authorized=True)

    deliveries = password_reset_outbox()
    assert [item["subject"] for item in deliveries[-3:]] == [
        "SITBank Withdrawal successful",
        "SITBank Deposit successful",
        "SITBank PayUp daily limit 80% alert",
    ]
    assert deliveries[-3]["to"] == "alice@example.com"
    assert "withdrawal PayUp transaction was successful" in deliveries[-3]["body"]
    assert deliveries[-2]["to"] == "bob@example.com"
    assert "deposit PayUp transaction was successful" in deliveries[-2]["body"]
    assert deliveries[-1]["to"] == "alice@example.com"
    assert "80.00% of your limit" in deliveries[-1]["body"]


def test_execute_payup_transfer_self_transfer_blocked(app, payup_context):
    alice = payup_context["alice"]
    token = _make_payup_pending(alice, alice, Decimal("10.00"))

    with _payup_service_context(app, alice):
        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert "yourself" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


@pytest.mark.parametrize(
    ("account_status", "is_frozen", "has_phone"),
    [
        ("revoked", False, True),
        ("locked", False, True),
        ("active", True, True),
        ("active", False, False),
    ],
)
def test_execute_payup_transfer_recipient_unavailable_blocked(
    app,
    payup_context,
    account_status,
    is_frozen,
    has_phone,
):
    alice = payup_context["alice"]
    bob = payup_context["bob"]
    bob.account_status = account_status
    bob.is_frozen = is_frozen
    if not has_phone:
        bob.phone_number = None
    db.session.commit()

    token = _make_payup_pending(alice, bob, Decimal("10.00"))

    with _payup_service_context(app, alice):
        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert "not available" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


def test_execute_payup_transfer_exceeding_daily_limit_blocked(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    token = _make_payup_pending(alice, bob, Decimal("600.00"))

    with _payup_service_context(app, alice):
        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert "could not authorize" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


def test_execute_payup_transfer_requires_authorization_above_threshold(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    token = _make_payup_pending(alice, bob, Decimal("450.00"))

    with _payup_service_context(app, alice):
        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert "authenticator" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


def test_execute_payup_transfer_succeeds_when_authorized_above_threshold(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    token = _make_payup_pending(alice, bob, Decimal("450.00"))

    with _payup_service_context(app, alice):
        txn_ref = execute_payup_transfer(sender=alice, confirmation_token=token, authorized=True)

    assert Transaction.query.filter_by(transaction_ref=txn_ref).count() == 1


def test_execute_payup_transfer_token_replay_blocked(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    token = _make_payup_pending(alice, bob, Decimal("50.00"))

    with _payup_service_context(app, alice):
        execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert "expired or was already used" in exc_info.value.message.lower()
    assert Transaction.query.count() == 1


def test_execute_payup_transfer_expired_token_blocked(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    token = _make_payup_pending(alice, bob, Decimal("50.00"), expires_in=-1)

    with _payup_service_context(app, alice):
        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert "expired" in exc_info.value.message.lower()
    assert Transaction.query.count() == 0


# ── Phone lookup route ───────────────────────────────────────────────────────────

def test_execute_payup_transfer_requires_sender_nickname(app, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]
    alice.payup_nickname = None
    db.session.commit()
    token = _make_payup_pending(alice, bob, Decimal("50.00"))

    with _payup_service_context(app, alice):
        with pytest.raises(AuthError) as exc_info:
            execute_payup_transfer(sender=alice, confirmation_token=token, authorized=False)

    assert exc_info.value.status_code == 403
    assert "display nickname" in exc_info.value.message
    assert Transaction.query.count() == 0


def test_payup_nickname_setup_saves_trimmed_display_name_without_raw_audit(client, payup_context):
    alice = payup_context["alice"]
    alice.payup_nickname = None
    db.session.commit()

    response = client.post("/banking/payup/nickname", data={"nickname": "  Alice New  "})
    db.session.refresh(alice)
    event = db.session.query(SecurityAuditEvent).filter_by(event_type="payup_nickname_update").one()

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/banking/payup")
    assert alice.payup_nickname == "Alice New"
    assert event.event_metadata == {"nickname_present": True, "nickname_length": 9}
    assert "Alice New" not in str(event.event_metadata)


def test_payup_requires_sender_nickname_before_lookup(client, payup_context):
    alice = payup_context["alice"]
    alice.payup_nickname = None
    db.session.commit()

    response = client.post("/banking/payup", data=_payup_lookup_data(payup_context))

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/banking/payup/nickname")
    with client.session_transaction() as sess:
        assert "pending_payup_recipient" not in sess
        assert "pending_payup_token" not in sess


def test_payup_phone_lookup_success_redirects_to_amount(client, payup_context):
    response = client.post("/banking/payup", data=_payup_lookup_data(payup_context))

    assert response.status_code == 302
    assert "payup/amount" in response.headers["Location"]

    with client.session_transaction() as sess:
        pending = sess.get("pending_payup_recipient")
    assert pending is not None
    assert pending["recipient_user_id"] == payup_context["bob"].id
    assert "recipient_name" not in pending
    assert "recipient_phone" not in pending


def test_payup_lookup_uses_committed_profile_phone_changes(client, payup_context):
    bob = payup_context["bob"]
    bob.phone_number = "82345678"
    db.session.commit()

    old_phone = client.post("/banking/payup", data=_payup_lookup_data(payup_context, phone_number="81234567"))
    new_phone = client.post("/banking/payup", data=_payup_lookup_data(payup_context, phone_number="82345678"))

    assert old_phone.status_code == 400
    assert b"Invalid phone number" in old_phone.data
    assert new_phone.status_code == 302
    assert "payup/amount" in new_phone.headers["Location"]


def test_payup_phone_lookup_unknown_number_shows_error(client, payup_context):
    response = client.post(
        "/banking/payup",
        data=_payup_lookup_data(payup_context, phone_number="89999999"),
    )
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="payup_lookup",
        outcome="failure",
    ).one()

    assert response.status_code == 400
    assert b"Invalid phone number" in response.data
    assert response.data.count(b"Bob Recipient") == 0
    assert "89999999" not in str(event.event_metadata)
    assert event.event_metadata["failure_count"] == 1


def test_payup_phone_lookup_allows_low_risk_session_without_fresh_totp(
    client,
    payup_context,
):
    response = client.post("/banking/payup", data={"phone_number": "81234567"})

    assert response.status_code == 302
    assert b"Bob Recipient" not in response.data
    with client.session_transaction() as sess:
        assert sess["pending_payup_recipient"]["recipient_user_id"] == payup_context["bob"].id


def test_payup_phone_lookup_does_not_store_client_totp_or_raw_recipient_identity(
    client,
    payup_context,
):
    response = client.post(
        "/banking/payup",
        data=_payup_lookup_data(payup_context, totp_code="000000"),
    )

    assert response.status_code == 302
    assert b"Bob Recipient" not in response.data
    with client.session_transaction() as sess:
        pending = sess["pending_payup_recipient"]
        assert "totp_code" not in pending
        assert "recipient_name" not in pending
        assert "recipient_phone" not in pending


@pytest.mark.parametrize(
    ("status", "frozen"),
    [
        ("revoked", False),
        ("locked", False),
        ("setup_pending", False),
        ("active", True),
    ],
)
def test_payup_unavailable_recipient_matches_unknown_number_response(
    client,
    payup_context,
    monkeypatch,
    status,
    frozen,
):
    bob = payup_context["bob"]
    bob.account_status = status
    bob.is_frozen = frozen
    db.session.commit()
    first_step = int(time.time())
    second_step = first_step + 31

    monkeypatch.setattr("app.auth.services.time.time", lambda: first_step)
    unavailable = client.post(
        "/banking/payup",
        data=_payup_lookup_data(payup_context, timestamp=first_step),
    )
    monkeypatch.setattr("app.auth.services.time.time", lambda: second_step)
    unknown = client.post(
        "/banking/payup",
        data=_payup_lookup_data(
            payup_context,
            phone_number="89999999",
            timestamp=second_step,
        ),
    )

    assert unavailable.status_code == 400
    assert unknown.status_code == 400
    assert b"Invalid phone number" in unavailable.data
    assert b"Invalid phone number" in unknown.data
    assert b"Bob Recipient" not in unavailable.data


def test_payup_phone_lookup_self_number_blocked(client, payup_context):
    response = client.post(
        "/banking/payup",
        data=_payup_lookup_data(payup_context, phone_number="91234567"),
    )

    assert response.status_code == 400
    assert b"Invalid phone number" in response.data
    assert b"own phone number" not in response.data


def test_payup_phone_lookup_failures_use_durable_user_scoped_limit(client, payup_context, monkeypatch):
    base_time = int(time.time())
    statuses = []

    for index in range(6):
        timestamp = base_time + (31 * index)
        monkeypatch.setattr("app.auth.services.time.time", lambda timestamp=timestamp: timestamp)
        response = client.post(
            "/banking/payup",
            data=_payup_lookup_data(
                payup_context,
                phone_number="89999999",
                timestamp=timestamp,
            ),
        )
        statuses.append(response.status_code)

    counter = db.session.query(AuthAttemptCounter).filter_by(scope="payup_lookup_failure").one()
    blocked = db.session.query(SecurityAuditEvent).filter_by(
        event_type="payup_lookup",
        outcome="blocked",
    ).one()

    assert statuses == [400, 400, 400, 400, 400, 429]
    assert counter.failure_count == 5
    assert blocked.event_metadata["reason"] == "durable_rate_limit"
    assert "89999999" not in str(blocked.event_metadata)


# ── Amount step: daily limit enforcement ─────────────────────────────────────────

@pytest.mark.parametrize(
    ("dimension", "config_name"),
    [
        ("account", "PAYUP_RATE_LIMIT_ACCOUNT"),
        ("session", "PAYUP_RATE_LIMIT_SESSION"),
        ("ip", "PAYUP_RATE_LIMIT_IP"),
        ("recipient", "PAYUP_RATE_LIMIT_RECIPIENT"),
    ],
)
def test_payup_lookup_has_durable_limits_for_each_abuse_dimension(
    app,
    client,
    payup_context,
    dimension,
    config_name,
):
    for name in (
        "PAYUP_RATE_LIMIT_ACCOUNT",
        "PAYUP_RATE_LIMIT_SESSION",
        "PAYUP_RATE_LIMIT_IP",
        "PAYUP_RATE_LIMIT_RECIPIENT",
    ):
        app.config[name] = 100
    app.config[config_name] = 1

    first = client.post(
        "/banking/payup",
        data=_payup_lookup_data(payup_context),
    )
    second = client.post(
        "/banking/payup",
        data=_payup_lookup_data(payup_context),
    )

    assert first.status_code == 302
    assert second.status_code == 429
    counter = db.session.query(AuthAttemptCounter).filter_by(
        scope=f"payup_lookup_{dimension}"
    ).one()
    assert counter.failure_count == 1
    blocked = (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="payup_rate_limit", outcome="blocked")
        .one()
    )
    assert "81234567" not in str(blocked.event_metadata)


def test_payup_amount_rejects_amount_exceeding_daily_limit(client, payup_context):
    client.post("/banking/payup", data=_payup_lookup_data(payup_context))

    response = client.post("/banking/payup/amount", data={"amount": "600.00"})

    assert response.status_code == 400
    assert b"exceed your daily PayUp limit" in response.data
    assert PayupPendingTransfer.query.count() == 0


def test_payup_amount_rejects_amount_exceeding_available_balance(client, payup_context):
    alice = payup_context["alice"]
    alice.balance = Decimal("50.00")
    db.session.commit()

    client.post("/banking/payup", data=_payup_lookup_data(payup_context))

    # Under the 500 SGD daily limit, but over the 50.00 available balance.
    response = client.post("/banking/payup/amount", data={"amount": "100.00"})

    assert response.status_code == 400
    assert b"Insufficient balance" in response.data
    assert PayupPendingTransfer.query.count() == 0


def test_payup_amount_accepts_amount_under_limit(client, payup_context):
    client.post("/banking/payup", data=_payup_lookup_data(payup_context))

    response = client.post("/banking/payup/amount", data={"amount": "100.00"})

    assert response.status_code == 302
    assert "payup/confirm" in response.headers["Location"]
    assert PayupPendingTransfer.query.count() == 1
    pending = PayupPendingTransfer.query.one()
    with client.session_transaction() as sess:
        raw_token = sess["pending_payup_token"]
    assert pending.token == payup_transfer_token_verifier(raw_token)
    assert pending.token != raw_token


# ── Full route flow: conditional MFA step-up ─────────────────────────────────────

def test_payup_confirmation_revalidates_recipient_before_identity_display(
    client,
    payup_context,
):
    bob = payup_context["bob"]
    client.post("/banking/payup", data=_payup_lookup_data(payup_context))
    client.post("/banking/payup/amount", data={"amount": "100.00"})
    bob.account_status = "locked"
    db.session.commit()

    response = client.get("/banking/payup/confirm")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/banking/payup")
    assert b"Bob Recipient" not in response.data
    assert Transaction.query.count() == 0
    event = (
        db.session.query(SecurityAuditEvent)
        .filter_by(
            event_type="payup_transfer",
            outcome="blocked",
        )
        .one()
    )
    assert event.event_metadata["reason"] == "recipient_unavailable"


def test_complete_payup_route_flow_below_threshold_no_mfa(client, payup_context):
    client.post("/banking/payup", data=_payup_lookup_data(payup_context))
    client.post("/banking/payup/amount", data={"amount": "100.00", "reference": "Lunch"})

    confirm_page = client.get("/banking/payup/confirm")
    assert confirm_page.status_code == 200
    assert b"Authenticator code" not in confirm_page.data
    assert b"From: Alice PayUp" in confirm_page.data
    assert b"Source account ending in 1000" in confirm_page.data
    assert b"To: 81234567" in confirm_page.data
    assert b"Recipient nickname: Bob PayUp" in confirm_page.data
    assert b"Bob Recipient" not in confirm_page.data

    confirm_submit = client.post("/banking/payup/confirm", data={})
    assert confirm_submit.status_code == 302
    assert Transaction.query.filter_by(reference="Lunch", transaction_type="payup").count() == 1

    history = client.get("/transactions")
    assert b"To: Bob PayUp" in history.data
    assert b"Phone: 81234567" in history.data
    assert b"Bob Recipient" not in history.data


def test_low_risk_confirmations_use_payup_limits_not_legacy_mfa_limiter(
    app,
    client,
    payup_context,
):
    for config_name in (
        "PAYUP_RATE_LIMIT_ACCOUNT",
        "PAYUP_RATE_LIMIT_SESSION",
        "PAYUP_RATE_LIMIT_IP",
        "PAYUP_RATE_LIMIT_RECIPIENT",
    ):
        app.config[config_name] = 20

    for index in range(6):
        lookup = client.post(
            "/banking/payup",
            data=_payup_lookup_data(payup_context),
        )
        amount = client.post(
            "/banking/payup/amount",
            data={"amount": "1.00", "reference": f"Low risk {index}"},
        )
        confirmation = client.post("/banking/payup/confirm", data={})

        assert lookup.status_code == 302
        assert amount.status_code == 302
        assert confirmation.status_code == 302

    assert Transaction.query.filter_by(transaction_type="payup").count() == 6


def test_complete_payup_route_flow_crossing_threshold_requires_mfa(client, payup_context, monkeypatch):
    alice_secret = payup_context["alice_secret"]

    client.post("/banking/payup", data=_payup_lookup_data(payup_context))
    client.post("/banking/payup/amount", data={"amount": "450.00"})

    confirm_page = client.get("/banking/payup/confirm")
    assert b"Authenticator code" in confirm_page.data

    # A missing code is rejected before touching the failed-attempt backoff
    # counter, so it does not block the subsequent valid attempt below.
    missing_mfa = client.post("/banking/payup/confirm", data={})
    assert missing_mfa.status_code == 403
    assert Transaction.query.count() == 0

    stepup_time = int(time.time())
    totp_code = _totp_code(alice_secret, stepup_time)
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)

    confirm_submit = client.post("/banking/payup/confirm", data={"totp_code": totp_code})
    assert confirm_submit.status_code == 302
    assert Transaction.query.filter_by(transaction_type="payup").count() == 1


def test_payup_low_risk_succeeds_after_clean_password_totp_login(
    client,
    payup_context,
    monkeypatch,
):
    _complete_clean_mfa_login(client, payup_context["alice_secret"], monkeypatch)

    lookup = client.post("/banking/payup", data=_payup_lookup_data(payup_context))
    amount = client.post(
        "/banking/payup/amount",
        data={"amount": "100.00", "reference": "Clean low risk"},
    )
    confirm_page = client.get("/banking/payup/confirm")
    confirm_submit = client.post("/banking/payup/confirm", data={})

    assert lookup.status_code == 302
    assert amount.status_code == 302
    assert confirm_page.status_code == 200
    assert b"Authenticator code" not in confirm_page.data
    assert confirm_submit.status_code == 302
    assert Transaction.query.filter_by(reference="Clean low risk", transaction_type="payup").count() == 1
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk",
        outcome="reauth_required",
    ).count() == 0


def test_payup_stepup_succeeds_after_clean_password_totp_login(
    client,
    payup_context,
    monkeypatch,
):
    alice_secret = payup_context["alice_secret"]
    login_time = _complete_clean_mfa_login(client, alice_secret, monkeypatch)

    lookup = client.post("/banking/payup", data=_payup_lookup_data(payup_context))
    amount = client.post(
        "/banking/payup/amount",
        data={"amount": "450.00", "reference": "Clean stepup"},
    )
    confirm_page = client.get("/banking/payup/confirm")
    stepup_time = login_time + 31
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)
    confirm_submit = client.post(
        "/banking/payup/confirm",
        data={"totp_code": _totp_code(alice_secret, stepup_time)},
    )

    assert lookup.status_code == 302
    assert amount.status_code == 302
    assert confirm_page.status_code == 200
    assert b"Authenticator code" in confirm_page.data
    assert confirm_submit.status_code == 302
    assert Transaction.query.filter_by(reference="Clean stepup", transaction_type="payup").count() == 1
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk",
        outcome="reauth_required",
    ).count() == 0


def test_payup_confirm_rejects_missing_context_with_matching_legacy_fingerprint(
    client,
    payup_context,
    monkeypatch,
):
    from app.security.sessions import SESSION_RISK_CONTEXT_KEY, SESSION_RISK_FINGERPRINT_KEY

    alice_secret = payup_context["alice_secret"]
    client.post("/logout")
    password_response = login(client, identifier="alice01")
    login_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: login_time)
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": _totp_code(alice_secret, login_time)},
    )

    lookup = client.post("/banking/payup", data=_payup_lookup_data(payup_context))
    amount = client.post("/banking/payup/amount", data={"amount": "450.00"})
    with client.session_transaction() as sess:
        assert sess.get(SESSION_RISK_FINGERPRINT_KEY)
        assert sess.get("pending_payup_token")
        sess.pop(SESSION_RISK_CONTEXT_KEY)

    confirm_page = client.get("/banking/payup/confirm")
    stepup_time = login_time + 1
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)
    confirm_submit = client.post(
        "/banking/payup/confirm",
        data={"totp_code": _totp_code(alice_secret, stepup_time)},
    )

    assert password_response.status_code == 302
    assert mfa_response.status_code == 200
    assert lookup.status_code == 302
    assert amount.status_code == 302
    assert confirm_page.status_code == 302
    assert confirm_page.headers["Location"].endswith("/banking/payup")
    assert confirm_submit.status_code == 302
    assert Transaction.query.filter_by(transaction_type="payup").count() == 0
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk",
        outcome="reauth_required",
    ).count() == 1


def test_payup_confirm_recomputes_policy_and_ignores_forged_client_state(client, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]

    client.post("/banking/payup", data=_payup_lookup_data(payup_context))
    client.post("/banking/payup/amount", data={"amount": "100.00", "reference": "Late policy block"})
    _make_payup_transaction(alice, bob, Decimal("450.00"), reference="Earlier PayUp")

    response = client.post(
        "/banking/payup/confirm",
        data={
            "requires_step_up": "false",
            "risk_decision": "allow",
            "totp_code": "",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/banking/payup")
    assert Transaction.query.filter_by(reference="Late policy block", transaction_type="payup").count() == 0


def test_payup_over_quick_cap_ignores_forged_no_stepup_fields(client, payup_context):
    client.post("/banking/payup", data=_payup_lookup_data(payup_context))
    client.post("/banking/payup/amount", data={"amount": "450.00", "reference": "Forged quick"})

    response = client.post(
        "/banking/payup/confirm",
        data={"requires_step_up": "false", "risk_decision": "allow"},
    )

    assert response.status_code == 403
    assert b"Authenticator code" in response.data
    assert Transaction.query.filter_by(reference="Forged quick", transaction_type="payup").count() == 0


def test_payup_confirm_rejects_wrong_totp_code(client, payup_context):
    client.post("/banking/payup", data=_payup_lookup_data(payup_context))
    client.post("/banking/payup/amount", data={"amount": "450.00"})

    response = client.post("/banking/payup/confirm", data={"totp_code": "000000"})

    assert response.status_code == 401
    assert Transaction.query.count() == 0


def test_payup_and_transfer_limit_posts_require_csrf_when_enabled(app, client, payup_context):
    alice = payup_context["alice"]
    bob = payup_context["bob"]
    token = _make_payup_pending(alice, bob, Decimal("10.00"))
    original = app.config["WTF_CSRF_ENABLED"]
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        with client.session_transaction() as sess:
            sess["pending_payup_recipient"] = {
                "recipient_user_id": bob.id,
                "recipient_name": bob.full_name,
                "recipient_phone": bob.phone_number,
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            }
        lookup = client.post("/banking/payup", data=_payup_lookup_data(payup_context))
        amount = client.post("/banking/payup/amount", data={"amount": "10.00"})
        with client.session_transaction() as sess:
            sess["pending_payup_token"] = token
        confirm = client.post("/banking/payup/confirm", data={})
        limit_update = client.post(
            "/banking/settings/transfer-limits",
            data={
                "payup_limit": "1000",
                "totp_code": _totp_code(payup_context["alice_secret"]),
            },
        )
    finally:
        app.config["WTF_CSRF_ENABLED"] = original

    assert lookup.status_code == 400
    assert amount.status_code == 400
    assert confirm.status_code == 400
    assert limit_update.status_code == 400
