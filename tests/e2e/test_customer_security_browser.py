from __future__ import annotations

import os
from decimal import Decimal

import pytest

from tests.e2e.support import (
    RUN_E2E_ENV,
    browser_page,
    create_e2e_customer,
    current_totp,
    live_server,
    login_customer_with_mfa,
    record_console_errors,
)


pytestmark = [pytest.mark.e2e]
if os.environ.get(RUN_E2E_ENV) != "1":
    pytestmark.append(
        pytest.mark.skip(reason=f"set {RUN_E2E_ENV}=1 to run Playwright E2E browser tests")
    )

_PASSWORD = "Correct Horse Battery Staple 2026!"


@pytest.fixture()
def e2e_mfa_customer(app):
    return create_e2e_customer(
        app,
        username="e2e_mfa_customer",
        password=_PASSWORD,
        email="e2e.mfa@example.test",
        phone_number="91234567",
        account_number="012345678901",
        full_name="E2E MFA Customer",
        mfa_enabled=True,
    )


@pytest.fixture()
def e2e_payup_pair(app, e2e_mfa_customer):
    recipient = create_e2e_customer(
        app,
        username="e2e_payup_recipient",
        password=_PASSWORD,
        email="e2e.payup.recipient@example.test",
        phone_number="81234567",
        account_number="012555999123",
        full_name="E2E PayUp Recipient",
        balance=Decimal("1000.00"),
        mfa_enabled=False,
    )
    return {"sender": e2e_mfa_customer, "recipient": recipient}


def test_mfa_login_logout_then_protected_banking_redirects_to_login(
    live_server,
    browser_page,
    e2e_mfa_customer,
):
    console_errors = record_console_errors(browser_page)

    login_customer_with_mfa(browser_page, live_server, e2e_mfa_customer)
    browser_page.get_by_role("heading", name="E2E MFA Customer").wait_for()
    browser_page.locator("#account-menu-button").click()
    browser_page.get_by_role("menuitem", name="Log Out").click()
    browser_page.wait_for_url("**/login", wait_until="load")
    browser_page.goto(f"{live_server}/banking/payees", wait_until="load")

    assert browser_page.url.endswith("/login")
    browser_page.get_by_role("heading", name="Welcome back").wait_for()
    assert console_errors == []


def test_payup_lookup_browser_flow_requires_totp_before_recipient_name(
    live_server,
    browser_page,
    e2e_payup_pair,
):
    sender = e2e_payup_pair["sender"]
    recipient = e2e_payup_pair["recipient"]
    console_errors = record_console_errors(browser_page)

    login_customer_with_mfa(browser_page, live_server, sender)
    browser_page.goto(f"{live_server}/banking/payup", wait_until="load")
    browser_page.locator("input[name='phone_number']").fill(recipient["phone_number"])
    browser_page.locator("input[name='totp_code']").fill(current_totp(sender["secret"]))
    browser_page.get_by_role("button", name="Continue").click()
    browser_page.wait_for_url("**/banking/payup/amount", wait_until="load")

    browser_page.get_by_role("heading", name=f"Pay to {recipient['full_name']}").wait_for()
    assert console_errors == []


def test_customer_app_does_not_register_admin_browser_surface(
    live_server,
    browser_page,
    e2e_mfa_customer,
):
    login_customer_with_mfa(browser_page, live_server, e2e_mfa_customer)
    response = browser_page.goto(f"{live_server}/admin", wait_until="load")

    assert response is not None
    assert response.status == 404
    assert "Admin Dashboard" not in browser_page.content()
