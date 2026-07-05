from __future__ import annotations

import os
from decimal import Decimal

import pytest

from app.extensions import db
from app.models import User
from tests.e2e.support import (
    RUN_E2E_ENV,
    browser_page,
    create_e2e_customer,
    create_e2e_payee,
    current_totp,
    live_server,
    login_customer_with_mfa,
)


pytestmark = [pytest.mark.e2e]
if os.environ.get(RUN_E2E_ENV) != "1":
    pytestmark.append(
        pytest.mark.skip(reason=f"set {RUN_E2E_ENV}=1 to run Playwright E2E browser tests")
    )

_PASSWORD = "Correct Horse Battery Staple 2026!"


@pytest.fixture()
def e2e_banking_pair(app):
    sender = create_e2e_customer(
        app,
        username="e2e_banking_sender",
        password=_PASSWORD,
        email="e2e.banking.sender@example.test",
        phone_number="91234564",
        account_number="012345678914",
        full_name="E2E Banking Sender",
        balance=Decimal("5000.00"),
        mfa_enabled=True,
    )
    recipient = create_e2e_customer(
        app,
        username="e2e_banking_recipient",
        password=_PASSWORD,
        email="e2e.banking.recipient@example.test",
        phone_number="81234564",
        account_number="012345678924",
        full_name="E2E Banking Recipient",
        balance=Decimal("1000.00"),
    )
    # Raise the sender's Local Transfer daily limit above the default SGD 500.00
    # so this fixture's large test amounts (e.g. SGD 9000.00, used to prove
    # server-side insufficient-funds handling) exercise balance validation
    # rather than being pre-empted by the daily-limit check.
    with app.app_context():
        sender_user = db.session.get(User, int(sender["id"]))
        sender_user.local_transfer_daily_limit = Decimal("10000.00")
        db.session.commit()
    return {"sender": sender, "recipient": recipient}


def test_add_payee_requires_totp_and_displays_only_masked_account(
    live_server,
    browser_page,
    e2e_banking_pair,
):
    sender = e2e_banking_pair["sender"]
    recipient = e2e_banking_pair["recipient"]
    login_customer_with_mfa(browser_page, live_server, sender)
    browser_page.goto(f"{live_server}/banking/payees/add", wait_until="load")
    browser_page.locator("input[name='nickname']").fill("Browser Recipient")
    browser_page.locator("input[name='account_number']").fill(
        recipient["account_number"]
    )
    browser_page.locator("input[name='totp_code']").fill(current_totp(sender["secret"]))
    browser_page.get_by_role("button", name="Look Up Recipient").click()

    browser_page.wait_for_url("**/banking/payees/confirm", wait_until="load")
    content = browser_page.content()
    assert recipient["full_name"] in content
    assert recipient["account_number"] not in content
    assert recipient["account_number"][-3:] in content
    browser_page.get_by_role("button", name="Confirm and Add Payee").click()
    browser_page.wait_for_url("**/banking/payees", wait_until="load")
    browser_page.get_by_text("Browser Recipient", exact=True).wait_for()


def test_self_payee_and_invalid_account_fail_without_recipient_disclosure(
    live_server,
    browser_page,
    e2e_banking_pair,
):
    sender = e2e_banking_pair["sender"]
    recipient = e2e_banking_pair["recipient"]
    login_customer_with_mfa(browser_page, live_server, sender)
    browser_page.goto(f"{live_server}/banking/payees/add", wait_until="load")
    browser_page.locator("input[name='nickname']").fill("Self")
    browser_page.locator("input[name='account_number']").fill(sender["account_number"])
    browser_page.locator("input[name='totp_code']").fill(current_totp(sender["secret"]))
    browser_page.get_by_role("button", name="Look Up Recipient").click()

    browser_page.get_by_text(
        "You cannot add your own account as a payee.",
        exact=True,
    ).wait_for()
    assert recipient["full_name"] not in browser_page.content()


@pytest.mark.parametrize(
    ("amount", "expected_text"),
    [
        ("125.50", "Transfer of SGD 125.50000"),
        ("9000.00", "Insufficient funds."),
    ],
)
def test_transfer_review_and_completion_paths_are_server_bound(
    app,
    live_server,
    browser_page,
    e2e_banking_pair,
    amount,
    expected_text,
):
    sender = e2e_banking_pair["sender"]
    recipient = e2e_banking_pair["recipient"]
    payee_id = create_e2e_payee(
        app,
        customer_id=int(sender["id"]),
        recipient=recipient,
    )
    login_customer_with_mfa(browser_page, live_server, sender)
    browser_page.goto(
        f"{live_server}/banking/transfer/{payee_id}",
        wait_until="load",
    )
    browser_page.locator("input[name='amount']").fill(amount)
    browser_page.locator("input[name='reference']").fill("Browser transfer")
    browser_page.locator("input[name='totp_code']").fill(current_totp(sender["secret"]))
    browser_page.get_by_role("button", name="Review Transfer").click()

    browser_page.wait_for_url(
        f"**/banking/transfer/{payee_id}/confirm",
        wait_until="load",
    )
    browser_page.get_by_role("heading", name="Confirm Transfer").wait_for()
    assert recipient["account_number"] not in browser_page.content()
    browser_page.get_by_role("button", name="Confirm Transfer").click()
    browser_page.wait_for_url("**/banking/payees", wait_until="load")
    browser_page.get_by_text(expected_text, exact=False).wait_for()
