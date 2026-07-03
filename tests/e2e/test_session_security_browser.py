from __future__ import annotations

import os

import pytest

from tests.e2e.support import (
    RUN_E2E_ENV,
    browser_context_factory,
    browser_page,
    create_e2e_customer,
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
def e2e_session_customer(app):
    return create_e2e_customer(
        app,
        username="e2e_session_customer",
        password=_PASSWORD,
        email="e2e.session@example.test",
        phone_number="91234565",
        account_number="012345678915",
        full_name="E2E Session Customer",
        mfa_enabled=True,
    )


def test_session_page_enforces_single_session_cap_and_public_refs(
    live_server,
    browser_context_factory,
    e2e_session_customer,
):
    first_page = browser_context_factory()
    second_page = browser_context_factory()
    login_customer_with_mfa(first_page, live_server, e2e_session_customer)
    login_customer_with_mfa(
        second_page,
        live_server,
        e2e_session_customer,
        totp_offset_seconds=30,
    )

    second_page.goto(f"{live_server}/sessions", wait_until="load")
    second_page.get_by_text("Current session", exact=True).wait_for()
    session_refs = second_page.locator("table[aria-label='Active sessions'] code")
    past_refs = second_page.locator("table[aria-label='Past sessions'] code")
    assert session_refs.count() == 1
    assert past_refs.count() >= 1
    assert len(session_refs.first.inner_text()) == 32
    assert all(
        len(past_refs.nth(index).inner_text()) == 32
        for index in range(past_refs.count())
    )
    assert second_page.get_by_role("button", name="Terminate").count() == 0
    assert "revoke-others" not in second_page.content()

    first_page.goto(f"{live_server}/dashboard", wait_until="load")
    first_page.wait_for_url("**/login", wait_until="load")
    first_page.get_by_role("heading", name="Welcome back").wait_for()


def test_password_change_requires_totp_and_invalidates_the_browser_session(
    live_server,
    browser_page,
    e2e_session_customer,
):
    login_customer_with_mfa(browser_page, live_server, e2e_session_customer)
    browser_page.goto(f"{live_server}/password/change", wait_until="load")
    browser_page.locator("input[name='current_password']").fill(_PASSWORD)
    new_password = "New Correct Horse Battery Staple 2026!"
    browser_page.locator("input[name='new_password']").fill(new_password)
    browser_page.locator("input[name='confirm_new_password']").fill(new_password)
    browser_page.locator("input[name='totp_code']").fill(
        current_totp(e2e_session_customer["secret"])
    )
    browser_page.get_by_role("button", name="Verify and change password").click()

    browser_page.wait_for_url("**/login", wait_until="load")
    browser_page.get_by_text(
        "Password changed. Please log in again.",
        exact=True,
    ).wait_for()
    browser_page.goto(f"{live_server}/dashboard", wait_until="load")
    browser_page.wait_for_url("**/login", wait_until="load")


def test_account_freeze_blocks_follow_on_high_risk_banking(
    live_server,
    browser_page,
    e2e_session_customer,
):
    login_customer_with_mfa(browser_page, live_server, e2e_session_customer)
    browser_page.goto(f"{live_server}/account/freeze", wait_until="load")
    browser_page.locator("input[name='totp_code']").fill(
        current_totp(e2e_session_customer["secret"])
    )
    browser_page.get_by_role("button", name="Verify and freeze account").click()
    browser_page.get_by_text(
        "Account frozen. Unfreeze requires manual support review.",
        exact=True,
    ).wait_for()

    browser_page.goto(f"{live_server}/banking/payees/add", wait_until="load")
    browser_page.wait_for_url("**/dashboard", wait_until="load")
    browser_page.get_by_text(
        "Account is frozen. This action is blocked pending review.",
        exact=True,
    ).wait_for()
