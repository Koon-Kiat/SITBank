from __future__ import annotations

import os

import pytest

from tests.e2e.support import (
    RUN_E2E_ENV,
    browser_page,
    create_e2e_customer,
    current_totp,
    live_server,
    record_console_errors,
)


pytestmark = [pytest.mark.e2e]
if os.environ.get(RUN_E2E_ENV) != "1":
    pytestmark.append(
        pytest.mark.skip(reason=f"set {RUN_E2E_ENV}=1 to run Playwright E2E browser tests")
    )

_PASSWORD = "Correct Horse Battery Staple 2026!"


@pytest.fixture()
def e2e_mfa_setup_customer(app):
    return create_e2e_customer(
        app,
        username="e2e_mfa_setup_customer",
        password=_PASSWORD,
        email="e2e.mfa.setup@example.test",
        phone_number="91234561",
        account_number="012345678911",
        full_name="E2E MFA Setup Customer",
    )


@pytest.fixture()
def e2e_mfa_login_customer(app):
    return create_e2e_customer(
        app,
        username="e2e_mfa_login_customer",
        password=_PASSWORD,
        email="e2e.mfa.login@example.test",
        phone_number="91234562",
        account_number="012345678912",
        full_name="E2E MFA Login Customer",
        mfa_enabled=True,
    )


def test_mfa_setup_completes_and_recovery_codes_are_one_time(
    live_server,
    browser_page,
    e2e_mfa_setup_customer,
):
    console_errors = record_console_errors(browser_page)
    browser_page.goto(f"{live_server}/login", wait_until="load")
    browser_page.locator("input[name='identifier']").fill(
        e2e_mfa_setup_customer["username"]
    )
    browser_page.locator("input[name='password']").fill(
        e2e_mfa_setup_customer["password"]
    )
    browser_page.locator("button[type='submit']").click()
    browser_page.wait_for_url("**/mfa/setup", wait_until="load")

    browser_page.get_by_role(
        "button",
        name="Generate authenticator setup",
    ).first.click()
    manual_secret = browser_page.locator("#manual-entry-secret").input_value()
    browser_page.locator("input[name='totp_code']").fill(current_totp(manual_secret))
    browser_page.get_by_role("button", name="Enable MFA").click()

    browser_page.get_by_text("MFA is now enabled.", exact=True).wait_for()
    recovery_codes = browser_page.locator("[data-recovery-code]")
    assert recovery_codes.count() >= 8
    assert browser_page.locator("#manual-entry-secret").count() == 0
    browser_page.goto(f"{live_server}/dashboard", wait_until="load")
    followup = browser_page.goto(f"{live_server}/mfa/setup", wait_until="load")
    assert browser_page.locator("[data-recovery-code]").count() == 0
    assert followup is not None
    assert "no-store" in followup.headers["cache-control"]
    assert console_errors == []


def test_mfa_failure_is_generic_and_repeated_attempts_use_branded_429(
    live_server,
    browser_page,
    e2e_mfa_login_customer,
):
    browser_page.goto(f"{live_server}/login", wait_until="load")
    browser_page.locator("input[name='identifier']").fill(
        e2e_mfa_login_customer["username"]
    )
    browser_page.locator("input[name='password']").fill(
        e2e_mfa_login_customer["password"]
    )
    browser_page.locator("button[type='submit']").click()
    browser_page.wait_for_url("**/mfa/verify", wait_until="load")

    browser_page.locator("input[name='totp_code']").fill("000000")
    browser_page.get_by_role("button", name="Verify code").click()
    browser_page.get_by_text(
        "Incorrect code. Check your authenticator and try again.",
        exact=True,
    ).wait_for()

    for _attempt in range(3):
        browser_page.locator("input[name='totp_code']").fill("000000")
        browser_page.get_by_role("button", name="Verify code").click()
        browser_page.wait_for_load_state("load")
        if browser_page.get_by_role("heading", name="429").count():
            break

    browser_page.get_by_role("heading", name="429").wait_for()
    browser_page.get_by_text(
        "Too many attempts. Please try again later.",
        exact=True,
    ).wait_for()
    assert e2e_mfa_login_customer["secret"] not in browser_page.content()
