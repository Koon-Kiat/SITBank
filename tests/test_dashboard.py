from __future__ import annotations

import time

import pyotp

from _auth_flow_helpers import verify_registration_email
from app.extensions import db
from app.models import User


# ── Helpers ────────────────────────────────────────────────────────────────────

def register(client, username="alice01", email="alice@example.com",
             password="correct horse battery staple",
             full_name="Alice Test", phone_number="91234567"):
    verify_registration_email(client, email)
    return client.post("/register", data={
        "username": username,
        "email": email,
        "full_name": full_name,
        "phone_number": phone_number,
        "password": password,
        "confirm_password": password,
    }, follow_redirects=False)


def login(client, identifier="alice01", password="correct horse battery staple"):
    return client.post("/login", data={
        "identifier": identifier,
        "password": password,
    }, follow_redirects=False)


def enable_mfa(username="alice01"):
    from app.security.crypto import encrypt_mfa_secret
    user = db.session.execute(db.select(User).where(User.username == username)).scalar_one()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    db.session.commit()
    return user, secret


def mark_recent_mfa(client, user):
    user.mfa_enabled = True
    db.session.commit()
    now = int(time.time())
    with client.session_transaction() as sess:
        sess["auth_context"] = "password+mfa_bootstrap"
        sess["mfa_verified_at"] = now
        sess["fresh_mfa_verified_at"] = now
        sess.pop("risk_fingerprint", None)


def login_with_mfa(client, full_name="Alice Test"):
    """Register, log in, enable MFA, mark it fresh — returns the user."""
    register(client, full_name=full_name)
    login(client)
    user, _ = enable_mfa()
    mark_recent_mfa(client, user)
    return user


def get_user(username="alice01"):
    return db.session.execute(db.select(User).where(User.username == username)).scalar_one()


def set_account_number(user, number="123456789000"):
    user.account_number = number
    db.session.commit()


# ── Access control ──────────────────────────────────────────────────────────────

def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_dashboard_requires_mfa(client):
    register(client)
    login(client)
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/mfa/setup" in response.headers["Location"]


def test_dashboard_accessible_with_mfa(client):
    login_with_mfa(client)
    assert client.get("/dashboard").status_code == 200


# ── Bank account card ──────────────────────────────────────────────────────────

def test_dashboard_shows_bank_account_card(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "bank-account-card" in markup
    assert "Savings Account" in markup
    assert "Available Balance" in markup


def test_dashboard_shows_full_name_on_card(client):
    login_with_mfa(client, full_name="Alice Test")
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "Alice Test" in markup


def test_dashboard_shows_masked_balance_by_default(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "card-balance-masked" in markup
    assert "card-balance-full" in markup


def test_dashboard_balance_eye_toggle_button_present(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "bal-eye-btn" in markup


def test_dashboard_shows_account_number_label(client):
    user = login_with_mfa(client)
    set_account_number(user, "123456789000")
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "Account No." in markup


def test_dashboard_masks_account_number_showing_last_three_digits(client):
    user = login_with_mfa(client)
    set_account_number(user, "123456789000")
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "card-acct-masked" in markup
    assert "000" in markup


def test_dashboard_account_number_full_in_hidden_span(client):
    user = login_with_mfa(client)
    set_account_number(user, "123456789000")
    markup = client.get("/dashboard").data.decode("utf-8")
    assert 'id="card-acct-full" hidden' in markup
    assert "123-456-789-000" in markup


def test_dashboard_account_number_masked_format_uses_dashes(client):
    user = login_with_mfa(client)
    set_account_number(user, "123456789000")
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "•••-•••-•••-000" in markup


def test_dashboard_account_number_eye_toggle_button_present(client):
    user = login_with_mfa(client)
    set_account_number(user, "123456789000")
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "acct-eye-btn" in markup


def test_dashboard_loads_eye_toggle_script(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "dashboard.js" in markup


# ── Quick actions ──────────────────────────────────────────────────────────────

def test_dashboard_quick_actions_have_correct_labels(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "Local Transfer" in markup
    assert "PayUp" in markup
    assert "Past Transaction" in markup
    assert "Monthly Statement" in markup


def test_dashboard_no_quick_actions_are_coming_soon_once_mfa_ready(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert markup.count("Coming soon") == 0


def test_dashboard_quick_actions_are_all_enabled_once_mfa_ready(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert markup.count("is-disabled") == 0


def test_dashboard_local_transfer_links_to_payees_when_mfa_ready(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert 'href="/banking/payees"' in markup
    assert "Local Transfer" in markup


def test_dashboard_payup_links_to_payup_when_mfa_ready(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert 'href="/banking/payup"' in markup
    assert "PayUp" in markup


def test_dashboard_past_transaction_links_to_transactions_when_mfa_ready(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert 'href="/transactions"' in markup
    assert "Past Transaction" in markup


def test_dashboard_monthly_statement_links_to_statement_when_mfa_ready(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert 'href="/banking/statement"' in markup
    assert "Monthly Statement" in markup


# ── Recent transactions panel ──────────────────────────────────────────────────

def test_dashboard_shows_recent_transactions_heading(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "Recent Transactions" in markup


def test_dashboard_shows_empty_state_when_no_transactions(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "No recent transactions to display." in markup


def test_dashboard_recent_transactions_has_more_link(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "More..." in markup
    assert 'href="/transactions"' in markup


# ── Security notices relocated off dashboard ───────────────────────────────────

def test_dashboard_does_not_show_recovery_codes_count(client):
    from app.auth.recovery_codes import generate_recovery_codes_for_user
    user = login_with_mfa(client)
    generate_recovery_codes_for_user(user)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "unused recovery codes remain." not in markup


def test_dashboard_does_not_show_low_recovery_codes_warning(client):
    from app.auth.recovery_codes import generate_recovery_codes_for_user
    user = login_with_mfa(client)
    generate_recovery_codes_for_user(user, count=2)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "Regenerate soon" not in markup


def test_recovery_codes_count_shown_on_mfa_page(client):
    from app.auth.recovery_codes import generate_recovery_codes_for_user
    user = login_with_mfa(client)
    generate_recovery_codes_for_user(user)
    markup = client.get("/mfa/setup").data.decode("utf-8")
    assert "unused recovery codes remain." in markup


def test_low_recovery_codes_warning_shown_on_mfa_page(client):
    from app.auth.recovery_codes import generate_recovery_codes_for_user
    user = login_with_mfa(client)
    generate_recovery_codes_for_user(user, count=2)
    markup = client.get("/mfa/setup").data.decode("utf-8")
    assert "2 unused recovery codes remain." in markup
    assert "Regenerate soon" in markup


# ── Frozen account ─────────────────────────────────────────────────────────────

def test_dashboard_shows_frozen_notice_when_account_is_frozen(client):
    user = login_with_mfa(client)
    user.is_frozen = True
    db.session.commit()
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "Account frozen" in markup


def test_dashboard_does_not_show_frozen_notice_for_active_account(client):
    login_with_mfa(client)
    markup = client.get("/dashboard").data.decode("utf-8")
    assert "Account frozen" not in markup
