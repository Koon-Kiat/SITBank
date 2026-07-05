from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest

from app.banking.routes import _csv_safe
from app.extensions import db
from test_dashboard import login_with_mfa
from test_transaction_history_idor import _create_transaction, _second_customer


def test_statement_view_requires_login(client):
    response = client.get("/banking/statement")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_statement_view_shows_current_month_by_default(client):
    login_with_mfa(client)
    response = client.get("/banking/statement")
    assert response.status_code == 200
    assert "Monthly Statement" in response.data.decode("utf-8")


def test_statement_view_shows_balance_summary_and_period_nav(client):
    login_with_mfa(client)
    markup = client.get("/banking/statement").data.decode("utf-8")
    assert "statement-summary" in markup
    assert "Opening balance" in markup
    assert "Closing balance" in markup
    assert "statement-period-nav" in markup


def test_statement_view_rejects_invalid_period_without_crashing(client):
    login_with_mfa(client)
    # A period well before the account's creation date always triggers the
    # rejection path deterministically (unlike a "future month," which would
    # need date-relative logic since `year` is clamped server-side).
    response = client.get("/banking/statement?year=2020&month=1")
    assert response.status_code == 200
    markup = response.data.decode("utf-8")
    assert "did not exist yet" in markup
    assert "statement-summary" not in markup


def test_statement_download_returns_csv_with_safe_headers(client):
    alice = login_with_mfa(client)
    client.post("/logout")
    bob, bob_secret = _second_customer(client)
    _create_transaction(alice, bob, Decimal("10.00"))

    from test_transaction_history_idor import _login_customer

    _login_customer(client, "bob02", bob_secret)

    now = datetime.now(timezone.utc)
    response = client.get(f"/banking/statement/download?year={now.year}&month={now.month}")

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    disposition = response.headers.get("Content-Disposition", "")
    assert "attachment" in disposition
    assert f"sitbank-statement-{now.year:04d}-{now.month:02d}.csv" in disposition


def test_statement_download_neutralizes_formula_like_counterparty_name(client):
    from test_dashboard import enable_mfa, login, mark_recent_mfa, register

    register(client, username="alice01", full_name="Alice Test")
    login(client, identifier="alice01")
    alice, alice_secret = enable_mfa(username="alice01")
    mark_recent_mfa(client, alice)
    client.post("/logout")

    bob, _bob_secret = _second_customer(
        client, username="formulabob", email="formulabob@example.com", phone_number="91234571"
    )
    bob.full_name = "=cmd|'/c calc'!A1"
    db.session.commit()
    _create_transaction(alice, bob, Decimal("10.00"))

    from test_transaction_history_idor import _login_customer

    _login_customer(client, "alice01", alice_secret)

    now = datetime.now(timezone.utc)
    response = client.get(f"/banking/statement/download?year={now.year}&month={now.month}")
    assert response.status_code == 200
    body = response.data.decode("utf-8")
    assert ",=cmd" not in body
    assert "'=cmd" in body


@pytest.mark.parametrize(
    "prefix",
    ["", " ", "\t", "\r", "\n", "  ", " \t", "\x00", "\x1f", "\x7f", " \x00\t"],
)
@pytest.mark.parametrize("trigger", ["=", "+", "-", "@"])
def test_csv_safe_neutralizes_masked_formula_triggers(prefix, trigger):
    value = f"{prefix}{trigger}cmd|'/c calc'!A1"
    safe = _csv_safe(value)
    assert safe == "'" + value


@pytest.mark.parametrize("value", ["hello", "", "10 - 5 = value", "a=b", "SGD 10.00"])
def test_csv_safe_leaves_ordinary_text_untouched(value):
    assert _csv_safe(value) == value


def test_statement_download_neutralizes_reference_with_leading_whitespace_trigger(client):
    alice = login_with_mfa(client)
    client.post("/logout")
    bob, bob_secret = _second_customer(client)
    txn = _create_transaction(alice, bob, Decimal("10.00"))
    txn.reference = "\t=cmd|'/c calc'!A1"
    db.session.commit()

    from test_transaction_history_idor import _login_customer

    _login_customer(client, "bob02", bob_secret)

    now = datetime.now(timezone.utc)
    response = client.get(f"/banking/statement/download?year={now.year}&month={now.month}")
    assert response.status_code == 200
    body = response.data.decode("utf-8")
    assert ",\t=cmd" not in body
    assert "'\t=cmd" in body


def test_statement_download_neutralizes_counterparty_name_with_leading_space_trigger(client):
    from test_dashboard import enable_mfa, login, mark_recent_mfa, register

    register(client, username="alice01", full_name="Alice Test")
    login(client, identifier="alice01")
    alice, alice_secret = enable_mfa(username="alice01")
    mark_recent_mfa(client, alice)
    client.post("/logout")

    bob, _bob_secret = _second_customer(
        client, username="formulabob", email="formulabob@example.com", phone_number="91234571"
    )
    bob.full_name = " @cmd|'/c calc'!A1"
    db.session.commit()
    _create_transaction(alice, bob, Decimal("10.00"))

    from test_transaction_history_idor import _login_customer

    _login_customer(client, "alice01", alice_secret)

    now = datetime.now(timezone.utc)
    response = client.get(f"/banking/statement/download?year={now.year}&month={now.month}")
    assert response.status_code == 200
    body = response.data.decode("utf-8")
    assert ", @cmd" not in body
    assert "' @cmd" in body


def test_statement_download_rejects_future_period_with_redirect(client):
    login_with_mfa(client)
    response = client.get("/banking/statement/download?year=2099&month=1", follow_redirects=False)
    assert response.status_code == 302
    assert "/banking/statement" in response.headers["Location"]


def test_statement_download_is_rate_limited(client):
    login_with_mfa(client)
    now = datetime.now(timezone.utc)
    last_status = None
    for _ in range(11):
        last_status = client.get(f"/banking/statement/download?year={now.year}&month={now.month}").status_code
    assert last_status == 429
