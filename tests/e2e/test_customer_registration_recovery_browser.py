from __future__ import annotations

import os

import pytest

from app.auth.password_reset import (
    GENERIC_FORGOT_PASSWORD_MESSAGE,
    GENERIC_MANUAL_RECOVERY_MESSAGE,
)
from tests.e2e.support import (
    RUN_E2E_ENV,
    browser_page,
    create_e2e_customer,
    current_totp,
    latest_password_reset_token,
    latest_registration_code,
    live_server,
)


pytestmark = [pytest.mark.e2e]
if os.environ.get(RUN_E2E_ENV) != "1":
    pytestmark.append(
        pytest.mark.skip(reason=f"set {RUN_E2E_ENV}=1 to run Playwright E2E browser tests")
    )

_PASSWORD = "Correct Horse Battery Staple 2026!"


@pytest.fixture()
def e2e_recovery_customer(app):
    return create_e2e_customer(
        app,
        username="e2e_recovery_customer",
        password=_PASSWORD,
        email="e2e.recovery@example.com",
        phone_number="91234563",
        account_number="012345678913",
        full_name="E2E Recovery Customer",
        mfa_enabled=True,
    )


def test_registration_email_otp_and_required_fields_complete_in_browser(
    app,
    live_server,
    browser_page,
):
    browser_page.goto(f"{live_server}/register", wait_until="load")
    browser_page.get_by_role("button", name="Send verification code").click()
    browser_page.get_by_text("This field is required.", exact=True).wait_for()

    browser_page.locator("#otp_request_email").fill("new.e2e.customer@example.com")
    browser_page.get_by_role("button", name="Send verification code").click()
    browser_page.locator("input[name='otp_code']").fill(
        latest_registration_code(app)
    )
    browser_page.get_by_role("button", name="Verify email").click()
    browser_page.get_by_role("heading", name="Complete your account").wait_for()

    browser_page.locator("input[name='username']").fill("new_e2e_customer")
    browser_page.locator("input[name='full_name']").fill("New Browser Customer")
    browser_page.locator("input[name='phone_number']").fill("81234563")
    browser_page.locator("input[name='password']").fill(_PASSWORD)
    browser_page.locator("input[name='confirm_password']").fill(_PASSWORD)
    browser_page.get_by_role("button", name="Create account").click()

    browser_page.wait_for_url("**/login", wait_until="load")
    browser_page.get_by_text(
        "Registration successful. Please log in.",
        exact=True,
    ).wait_for()
    assert "new.e2e.customer@example.com" not in browser_page.url


def test_forgot_password_is_generic_and_reset_token_leaves_the_url(
    app,
    live_server,
    browser_page,
    e2e_recovery_customer,
):
    browser_page.goto(f"{live_server}/forgot-password", wait_until="load")
    browser_page.locator("input[name='email']").fill(e2e_recovery_customer["email"])
    browser_page.get_by_role("button", name="Send reset link").click()
    browser_page.get_by_text(GENERIC_FORGOT_PASSWORD_MESSAGE, exact=True).wait_for()
    token = latest_password_reset_token(app)

    browser_page.goto(
        f"{live_server}/reset-password?token={token}",
        wait_until="load",
    )
    browser_page.get_by_role("button", name="Continue password reset").click()
    browser_page.wait_for_url("**/reset-password/continue", wait_until="load")
    assert token not in browser_page.url
    browser_page.locator("input[name='totp_code']").fill(
        current_totp(e2e_recovery_customer["secret"])
    )
    browser_page.get_by_role("button", name="Verify code").click()

    new_password = "New Correct Horse Battery Staple 2026!"
    browser_page.locator("input[name='new_password']").fill(new_password)
    browser_page.locator("input[name='confirm_new_password']").fill(new_password)
    browser_page.get_by_role("button", name="Reset Password").click()
    browser_page.wait_for_url("**/login", wait_until="load")
    browser_page.get_by_text(
        "Your password has been reset. You can now log in.",
        exact=True,
    ).wait_for()

    browser_page.goto(f"{live_server}/forgot-password", wait_until="load")
    browser_page.locator("input[name='email']").fill("unknown@example.com")
    browser_page.get_by_role("button", name="Send reset link").click()
    browser_page.get_by_text(GENERIC_FORGOT_PASSWORD_MESSAGE, exact=True).wait_for()


def test_manual_recovery_known_and_unknown_identifiers_share_generic_message(
    live_server,
    browser_page,
    e2e_recovery_customer,
):
    for identifier in (
        e2e_recovery_customer["username"],
        "unknown-e2e-recovery-user",
    ):
        browser_page.goto(f"{live_server}/account-recovery", wait_until="load")
        browser_page.locator("input[name='identifier']").fill(identifier)
        browser_page.get_by_role("button", name="Request recovery review").click()
        browser_page.get_by_text(
            GENERIC_MANUAL_RECOVERY_MESSAGE,
            exact=True,
        ).wait_for()
        assert identifier not in browser_page.url
