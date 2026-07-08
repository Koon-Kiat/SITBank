from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pyotp

from _auth_flow_helpers import enable_mfa_for_user, login, mark_recent_mfa, register
from app.extensions import db
from app.models import Payee, SecurityAuditEvent, User
from app.security.email import password_reset_outbox


def _user(username: str) -> User:
    return db.session.execute(db.select(User).where(User.username == username)).scalar_one()


def _set_account(username: str, account_number: str) -> User:
    user = _user(username)
    user.account_number = account_number
    db.session.commit()
    return user


def _register_customer(client, *, username: str, email: str, phone: str, account: str) -> User:
    register(
        client,
        username=username,
        email=email,
        full_name=f"{''.join(c for c in username if c.isalpha()).title()} Test",
        phone_number=phone,
    )
    return _set_account(username, account)


def _login_mfa_customer(client, *, username: str = "alice01") -> tuple[User, str]:
    login(client, identifier=username)
    user, secret = enable_mfa_for_user(username)
    mark_recent_mfa(client, user)
    return user, secret


def _current_totp(secret: str) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).now()


def _submit_add_payee(client, secret: str, *, nickname: str, account_number: str):
    return client.post(
        "/banking/payees/add",
        data={
            "nickname": nickname,
            "account_number": account_number,
            "totp_code": _current_totp(secret),
        },
    )


def _stage_pending_payee(client, *, nickname: str, account_number: str, recipient_name: str, expires_in_seconds: int = 300):
    with client.session_transaction() as sess:
        sess["pending_payee"] = {
            "nickname": nickname,
            "account_number": account_number,
            "recipient_name": recipient_name,
            "authorization_action": "payee_add",
            "authorized_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
            ).isoformat(),
        }


def _setup_alice_and_bob(client):
    bob_client = client.application.test_client()
    _register_customer(
        client,
        username="alice01",
        email="alice@example.com",
        phone="91234567",
        account="012345678000",
    )
    bob = _register_customer(
        bob_client,
        username="bob02",
        email="bob@example.com",
        phone="81234567",
        account="012555999000",
    )
    alice, secret = _login_mfa_customer(client)
    return alice, secret, bob


def test_submitting_add_payee_sends_processing_email(client):
    alice, secret, bob = _setup_alice_and_bob(client)

    before_count = len(password_reset_outbox())
    response = _submit_add_payee(client, secret, nickname="Bob", account_number=bob.account_number)

    assert response.status_code == 302
    deliveries = password_reset_outbox()
    assert len(deliveries) == before_count + 1
    assert deliveries[-1]["to"] == alice.email
    assert deliveries[-1]["subject"] == "SITBank payee request received"
    assert "Bob" in deliveries[-1]["body"]
    assert bob.account_number not in deliveries[-1]["body"]
    assert (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="payee_add_processing_notification", outcome="queued", user_id=alice.id)
        .count()
        == 1
    )


def test_confirming_add_payee_sends_success_email(client):
    alice, secret, bob = _setup_alice_and_bob(client)
    _submit_add_payee(client, secret, nickname="Bob", account_number=bob.account_number)

    before_count = len(password_reset_outbox())
    response = client.post("/banking/payees/confirm")

    assert response.status_code == 302
    assert db.session.query(Payee).filter_by(user_id=alice.id).count() == 1
    deliveries = password_reset_outbox()
    assert len(deliveries) == before_count + 1
    assert deliveries[-1]["subject"] == "SITBank payee added successfully"
    assert "Bob" in deliveries[-1]["body"]
    assert (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="payee_add_result_notification", outcome="queued", user_id=alice.id)
        .count()
        == 1
    )


def test_canceling_add_payee_sends_canceled_email_and_no_payee_created(client):
    alice, secret, bob = _setup_alice_and_bob(client)
    _submit_add_payee(client, secret, nickname="Bob", account_number=bob.account_number)

    before_count = len(password_reset_outbox())
    response = client.post("/banking/payees/cancel")

    assert response.status_code == 302
    assert db.session.query(Payee).filter_by(user_id=alice.id).count() == 0
    deliveries = password_reset_outbox()
    assert len(deliveries) == before_count + 1
    assert deliveries[-1]["subject"] == "SITBank payee request canceled"
    assert "You have canceled" in deliveries[-1]["body"]

    with client.session_transaction() as sess:
        assert "pending_payee" not in sess

    confirm_after_cancel = client.get("/banking/payees/confirm")
    assert confirm_after_cancel.status_code == 302
    assert confirm_after_cancel.headers["Location"].endswith("/banking/payees/add")


def test_canceling_without_pending_payee_sends_no_email(client):
    alice, secret, bob = _setup_alice_and_bob(client)

    before_count = len(password_reset_outbox())
    response = client.post("/banking/payees/cancel")

    assert response.status_code == 302
    assert len(password_reset_outbox()) == before_count


def test_expired_confirmation_get_sends_expired_email(client):
    alice, secret, bob = _setup_alice_and_bob(client)
    _stage_pending_payee(
        client,
        nickname="Bob",
        account_number=bob.account_number,
        recipient_name=bob.full_name,
        expires_in_seconds=-1,
    )

    before_count = len(password_reset_outbox())
    response = client.get("/banking/payees/confirm")

    assert response.status_code == 302
    deliveries = password_reset_outbox()
    assert len(deliveries) == before_count + 1
    assert deliveries[-1]["subject"] == "SITBank payee request not completed"
    assert db.session.query(Payee).filter_by(user_id=alice.id).count() == 0


def test_expired_confirmation_post_sends_expired_email(client):
    alice, secret, bob = _setup_alice_and_bob(client)
    _stage_pending_payee(
        client,
        nickname="Bob",
        account_number=bob.account_number,
        recipient_name=bob.full_name,
        expires_in_seconds=-1,
    )

    before_count = len(password_reset_outbox())
    response = client.post("/banking/payees/confirm")

    assert response.status_code == 302
    deliveries = password_reset_outbox()
    assert len(deliveries) == before_count + 1
    assert deliveries[-1]["subject"] == "SITBank payee request not completed"
    assert db.session.query(Payee).filter_by(user_id=alice.id).count() == 0


def test_payee_add_emails_are_not_suppressed_by_transfer_activity_preference(client):
    alice, secret, bob = _setup_alice_and_bob(client)
    alice.transfer_activity_email_enabled = False
    db.session.commit()

    before_count = len(password_reset_outbox())
    _submit_add_payee(client, secret, nickname="Bob", account_number=bob.account_number)
    client.post("/banking/payees/confirm")

    deliveries = password_reset_outbox()
    assert len(deliveries) == before_count + 2
    subjects = {deliveries[-2]["subject"], deliveries[-1]["subject"]}
    assert subjects == {"SITBank payee request received", "SITBank payee added successfully"}


def test_processing_email_failure_does_not_block_add_payee_flow(client, monkeypatch):
    alice, secret, bob = _setup_alice_and_bob(client)

    def _raise(*args, **kwargs):
        raise RuntimeError("smtp unavailable")

    monkeypatch.setattr("app.banking.services.send_security_email", _raise)

    response = _submit_add_payee(client, secret, nickname="Bob", account_number=bob.account_number)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/banking/payees/confirm")
    assert (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="payee_add_processing_notification", outcome="failure", user_id=alice.id)
        .count()
        == 1
    )
