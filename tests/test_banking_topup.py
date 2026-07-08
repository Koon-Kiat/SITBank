from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pyotp

from _auth_flow_helpers import enable_mfa_for_user, login, register
from app.banking.topup_tokens import generate_topup_token
from app.extensions import db
from app.models import SecurityAuditEvent, Transaction, TopUpApprovalRequest, TopUpCredit, User


def _topup_approve_url(raw_token: str) -> str:
    selector, _, verifier = raw_token.partition(".")
    return f"/banking/topup/approve/{selector}.{verifier}"


def test_topup_step_one_creates_pending_request_with_parsed_amount(client):
    register(client)
    login(client)
    user, _ = enable_mfa_for_user()

    submit_response = client.post("/banking/topup", data={"amount": "50.00"})
    assert submit_response.status_code == 200

    request_row = db.session.execute(
        db.select(TopUpApprovalRequest).where(TopUpApprovalRequest.user_id == user.id)
    ).scalar_one()
    assert request_row.status == "pending"
    assert Decimal(str(request_row.amount)) == Decimal("50.00")

    status_response = client.get(f"/banking/topup/status/{request_row.selector}")
    assert status_response.status_code == 200
    assert status_response.get_json()["status"] == "pending"


def test_topup_happy_path_credits_balance_and_records_ledger(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    starting_balance = Decimal(str(user.balance))

    raw_token, _ = generate_topup_token(user.id, Decimal("50.00"))
    approve_url = _topup_approve_url(raw_token)

    get_response = client.get(approve_url)
    assert get_response.status_code == 200

    code = pyotp.TOTP(secret, digits=6, interval=30).now()
    approve_response = client.post(approve_url, data={"totp_code": code})
    assert approve_response.status_code == 200

    db.session.refresh(user)
    assert Decimal(str(user.balance)) == starting_balance + Decimal("50.00")

    credit = db.session.execute(
        db.select(TopUpCredit).where(TopUpCredit.user_id == user.id)
    ).scalar_one()
    assert Decimal(str(credit.amount)) == Decimal("50.00")
    assert credit.status == "completed"

    selector, _, _ = raw_token.partition(".")
    updated_request = db.session.execute(
        db.select(TopUpApprovalRequest).where(TopUpApprovalRequest.selector == selector)
    ).scalar_one()
    assert updated_request.status == "completed"
    assert updated_request.credit_ref == credit.credit_ref

    status_after = client.get(f"/banking/topup/status/{selector}")
    assert status_after.get_json()["status"] == "completed"

    assert (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="account_topup", outcome="success", user_id=user.id)
        .count()
        == 1
    )

    txn = db.session.execute(
        db.select(Transaction).where(Transaction.transaction_type == "topup", Transaction.sender_id == user.id)
    ).scalar_one()
    assert txn.recipient_id == user.id
    assert Decimal(str(txn.amount)) == Decimal("50.00")
    assert txn.status == "completed"
    assert txn.transaction_ref == credit.credit_ref

    history_response = client.get("/transactions")
    assert history_response.status_code == 200
    history_html = history_response.data.decode("utf-8")
    assert "Top Up" in history_html
    assert "+50.00" in history_html

    from app.security.email import password_reset_outbox

    deliveries = [item for item in password_reset_outbox() if item["to"] == user.email]
    assert deliveries[-1]["subject"] == "SITBank Deposit successful"
    assert "Top Up" in deliveries[-1]["body"]
    assert "50.00" in deliveries[-1]["body"]


def test_topup_email_suppressed_when_transfer_activity_email_disabled(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    user.transfer_activity_email_enabled = False
    db.session.commit()

    from app.security.email import password_reset_outbox

    before_count = len(password_reset_outbox())

    raw_token, _ = generate_topup_token(user.id, Decimal("25.00"))
    approve_url = _topup_approve_url(raw_token)
    code = pyotp.TOTP(secret, digits=6, interval=30).now()
    approve_response = client.post(approve_url, data={"totp_code": code})
    assert approve_response.status_code == 200

    assert len(password_reset_outbox()) == before_count


def test_topup_wrong_totp_rejected_without_crediting(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()

    raw_token, _ = generate_topup_token(user.id, Decimal("20.00"))
    approve_url = _topup_approve_url(raw_token)

    response = client.post(approve_url, data={"totp_code": "000000"})
    assert response.status_code == 401

    selector = raw_token.partition(".")[0]
    request_row = db.session.execute(
        db.select(TopUpApprovalRequest).where(TopUpApprovalRequest.selector == selector)
    ).scalar_one()
    assert request_row.failure_count == 1
    assert request_row.status == "pending"
    assert db.session.query(TopUpCredit).filter_by(user_id=user.id).count() == 0
    assert db.session.query(Transaction).filter_by(sender_id=user.id, transaction_type="topup").count() == 0


def test_topup_success_flash_shown_on_dashboard(client):
    register(client)
    login(client)
    enable_mfa_for_user()

    response = client.get("/dashboard?topup=success", follow_redirects=True)
    assert response.status_code == 200
    html = response.data.decode("utf-8")
    assert "Your top-up was added to your account." in html
    assert 'id="topup-success-overlay"' in html
    assert "alert-success" not in html


def test_topup_approval_locks_after_max_failures(client):
    # The generic per-user MFA backoff (app/security/rate_limits.py) starts
    # throttling after just one failure, so a patient attacker spacing
    # attempts out over time would still eventually reach the request's own
    # failure_count lockout. clear_failures simulates that spacing without
    # a real sleep, isolating the request-level lockout being tested here.
    from app.security.rate_limits import clear_failures

    register(client)
    login(client)
    user, secret = enable_mfa_for_user()

    raw_token, _ = generate_topup_token(user.id, Decimal("20.00"))
    approve_url = _topup_approve_url(raw_token)
    selector = raw_token.partition(".")[0]

    for attempt in range(1, 5):
        clear_failures("account_topup_approval", str(user.id))
        response = client.post(approve_url, data={"totp_code": "000000"})
        assert response.status_code == 401
        request_row = db.session.execute(
            db.select(TopUpApprovalRequest).where(TopUpApprovalRequest.selector == selector)
        ).scalar_one()
        assert request_row.failure_count == attempt
        assert request_row.status == "pending"

    clear_failures("account_topup_approval", str(user.id))
    locking_response = client.post(approve_url, data={"totp_code": "000000"})
    assert locking_response.status_code == 401

    request_row = db.session.execute(
        db.select(TopUpApprovalRequest).where(TopUpApprovalRequest.selector == selector)
    ).scalar_one()
    assert request_row.status == "failed"

    clear_failures("account_topup_approval", str(user.id))
    correct_code = pyotp.TOTP(secret, digits=6, interval=30).now()
    still_locked_response = client.post(approve_url, data={"totp_code": correct_code})
    assert still_locked_response.status_code == 404

    assert db.session.query(TopUpCredit).filter_by(user_id=user.id).count() == 0


def test_topup_expired_request_rejected(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()

    raw_token, request_row = generate_topup_token(user.id, Decimal("30.00"))
    request_row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.session.commit()

    approve_url = _topup_approve_url(raw_token)
    get_response = client.get(approve_url)
    assert get_response.status_code == 404

    code = pyotp.TOTP(secret, digits=6, interval=30).now()
    post_response = client.post(approve_url, data={"totp_code": code})
    assert post_response.status_code == 404

    status_response = client.get(f"/banking/topup/status/{request_row.selector}")
    assert status_response.get_json()["status"] == "expired"

    assert db.session.query(TopUpCredit).filter_by(user_id=user.id).count() == 0


def test_topup_tampered_verifier_rejected(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()

    raw_token, _ = generate_topup_token(user.id, Decimal("15.00"))
    selector = raw_token.partition(".")[0]
    tampered_token = f"{selector}.not-the-real-verifier"

    response = client.get(f"/banking/topup/approve/{tampered_token}")
    assert response.status_code == 404


def test_topup_status_endpoint_hides_other_users_requests(client):
    register(client, username="alice01", email="alice@example.com", phone_number="91234567")
    login(client, identifier="alice01")
    alice, _ = enable_mfa_for_user(username="alice01")
    client.post("/auth/logout")

    register(client, username="bob02", email="bob@example.com", phone_number="98765432")
    login(client, identifier="bob02")
    enable_mfa_for_user(username="bob02")

    raw_token, alice_request = generate_topup_token(alice.id, Decimal("40.00"))

    response = client.get(f"/banking/topup/status/{alice_request.selector}")
    assert response.status_code == 404


def test_topup_amount_out_of_bounds_rejected(client):
    register(client)
    login(client)
    user, _ = enable_mfa_for_user()

    too_small = client.post("/banking/topup", data={"amount": "0.00"})
    assert too_small.status_code == 400

    too_large = client.post("/banking/topup", data={"amount": "999999999.00"})
    assert too_large.status_code == 400

    assert db.session.query(TopUpApprovalRequest).filter_by(user_id=user.id).count() == 0


def test_frozen_account_cannot_start_topup(client):
    register(client)
    login(client)
    user, _ = enable_mfa_for_user()
    user.is_frozen = True
    db.session.commit()

    response = client.post("/banking/topup", data={"amount": "20.00"})
    assert response.status_code == 302

    assert db.session.query(TopUpApprovalRequest).filter_by(user_id=user.id).count() == 0


def test_topup_approval_rechecks_frozen_status_at_completion(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()

    raw_token, _ = generate_topup_token(user.id, Decimal("25.00"))
    user.is_frozen = True
    db.session.commit()

    approve_url = _topup_approve_url(raw_token)
    code = pyotp.TOTP(secret, digits=6, interval=30).now()
    response = client.post(approve_url, data={"totp_code": code})
    assert response.status_code == 403

    assert db.session.query(TopUpCredit).filter_by(user_id=user.id).count() == 0
    selector = raw_token.partition(".")[0]
    request_row = db.session.execute(
        db.select(TopUpApprovalRequest).where(TopUpApprovalRequest.selector == selector)
    ).scalar_one()
    assert request_row.status == "failed"
