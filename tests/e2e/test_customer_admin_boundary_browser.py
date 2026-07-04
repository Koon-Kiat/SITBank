from __future__ import annotations

import os

import pytest

from app.security.http_errors import CSRF_ERROR_MESSAGE, RATE_LIMIT_MESSAGE
from tests.e2e.support import (
    RUN_E2E_ENV,
    admin_live_server,
    browser_page,
    create_e2e_admin,
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


def test_customer_and_admin_browser_sessions_remain_isolated(
    app,
    live_server,
    admin_live_server,
    browser_page,
):
    admin_app, admin_base_url = admin_live_server
    customer = create_e2e_customer(
        app,
        username="e2e_boundary_customer",
        password=_PASSWORD,
        email="e2e.boundary.customer@example.test",
        phone_number="91234566",
        account_number="012345678916",
        full_name="E2E Boundary Customer",
        mfa_enabled=True,
    )
    admin = create_e2e_admin(
        admin_app,
        email="root1@sit.singaporetech.edu.sg",
        password=_PASSWORD,
    )
    login_customer_with_mfa(browser_page, live_server, customer)

    response = browser_page.goto(admin_base_url, wait_until="load")
    assert response is not None
    assert response.status == 401
    assert "E2E Boundary Customer" not in browser_page.content()

    browser_page.goto(f"{admin_base_url}/login", wait_until="load")
    browser_page.locator("input[name='workplace_email']").fill(admin["email"])
    browser_page.locator("input[name='password']").fill(admin["password"])
    browser_page.get_by_role("button", name="Continue").click()
    browser_page.wait_for_url("**/mfa/verify", wait_until="load")
    browser_page.locator("input[name='totp_code']").fill(current_totp(admin["secret"]))
    browser_page.get_by_role("button", name="Verify").click()
    browser_page.wait_for_url(admin_base_url + "/", wait_until="load")
    browser_page.get_by_text("Staff and admin operations", exact=True).wait_for()

    browser_page.goto(f"{live_server}/dashboard", wait_until="load")
    browser_page.get_by_role("heading", name="E2E Boundary Customer").wait_for()
    cookie_names = {cookie["name"] for cookie in browser_page.context.cookies()}
    assert "__Host-sitbank_session" in cookie_names
    assert "__Host-sitbank_admin_session" in cookie_names


def test_admin_browser_csrf_and_backoff_are_distinct_private_pages(
    admin_live_server,
    browser_page,
):
    admin_app, admin_base_url = admin_live_server
    admin_app.config["WTF_CSRF_ENABLED"] = True
    browser_page.goto(f"{admin_base_url}/login", wait_until="load")
    browser_page.locator("input[name='workplace_email']").fill(
        "fake.admin@sit.singaporetech.edu.sg"
    )
    browser_page.locator("input[name='password']").fill("clearly-fake-password")
    browser_page.locator("input[name='csrf_token']").evaluate(
        "(element) => { element.value = 'invalid-test-token'; }"
    )
    browser_page.get_by_role("button", name="Continue").click()
    browser_page.get_by_text(CSRF_ERROR_MESSAGE, exact=True).wait_for()
    assert browser_page.get_by_role("heading", name="400").count() == 1
    assert RATE_LIMIT_MESSAGE not in browser_page.content()

    admin_app.config["WTF_CSRF_ENABLED"] = False
    for _attempt in range(4):
        browser_page.goto(f"{admin_base_url}/login", wait_until="load")
        browser_page.locator("input[name='workplace_email']").fill(
            "unknown.admin@sit.singaporetech.edu.sg"
        )
        browser_page.locator("input[name='password']").fill("clearly-fake-password")
        browser_page.get_by_role("button", name="Continue").click()
        browser_page.wait_for_load_state("load")
        if browser_page.get_by_role("heading", name="429").count():
            break

    browser_page.get_by_role("heading", name="429").wait_for()
    browser_page.get_by_text(RATE_LIMIT_MESSAGE, exact=True).wait_for()
    assert "Authentication backoff" not in browser_page.content()
