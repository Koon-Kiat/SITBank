from __future__ import annotations

import os

import pytest

from app.security.http_errors import CSRF_ERROR_MESSAGE, RATE_LIMIT_MESSAGE
from app.extensions import db
from app.models import User
from app.security.passwords import hash_password
from tests.e2e.support import RUN_E2E_ENV, browser_page, live_server, record_console_errors


pytestmark = [pytest.mark.e2e]
if os.environ.get(RUN_E2E_ENV) != "1":
    pytestmark.append(
        pytest.mark.skip(reason=f"set {RUN_E2E_ENV}=1 to run Playwright E2E browser tests")
    )

_CUSTOMER_USERNAME = "e2e_customer"
_CUSTOMER_PASSWORD = "Correct Horse Battery Staple 2026!"


@pytest.fixture()
def e2e_customer(app):
    with app.app_context():
        db.session.add(
            User(
                username=_CUSTOMER_USERNAME,
                email="e2e.customer@example.test",
                password_hash=hash_password(_CUSTOMER_PASSWORD),
                full_name="E2E Customer",
                phone_number="91234567",
                account_number="123456789000",
            )
        )
        db.session.commit()
    return {"username": _CUSTOMER_USERNAME, "password": _CUSTOMER_PASSWORD}


def test_login_page_renders_with_security_headers_and_no_console_errors(
    live_server,
    browser_page,
):
    console_errors = record_console_errors(browser_page)

    response = browser_page.goto(f"{live_server}/login", wait_until="load")
    if console_errors == ["Failed to load resource: net::ERR_NO_BUFFER_SPACE"]:
        console_errors.clear()
        response = browser_page.reload(wait_until="load")

    assert response is not None
    assert response.status == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    browser_page.get_by_role("heading", name="Welcome back").wait_for()
    assert console_errors == []


def test_unauthenticated_dashboard_redirects_to_customer_login(
    live_server,
    browser_page,
):
    console_errors = record_console_errors(browser_page)

    browser_page.goto(f"{live_server}/dashboard", wait_until="load")

    assert browser_page.url.endswith("/login")
    browser_page.get_by_role("heading", name="Welcome back").wait_for()
    assert console_errors == []


def test_password_login_reaches_mfa_setup_without_external_services(
    live_server,
    browser_page,
    e2e_customer,
):
    console_errors = record_console_errors(browser_page)

    browser_page.goto(f"{live_server}/login", wait_until="load")
    browser_page.locator("input[name='identifier']").fill(e2e_customer["username"])
    browser_page.locator("input[name='password']").fill(e2e_customer["password"])
    browser_page.locator("button[type='submit']").click()

    browser_page.wait_for_url("**/mfa/setup", wait_until="load")
    browser_page.get_by_role("heading", name="MFA setup").wait_for()
    assert console_errors == []


def test_login_csrf_failure_stays_a_branded_security_token_400(
    app,
    live_server,
    browser_page,
):
    app.config["WTF_CSRF_ENABLED"] = True
    browser_page.goto(f"{live_server}/login", wait_until="load")
    browser_page.locator("input[name='identifier']").fill("fake-customer")
    browser_page.locator("input[name='password']").fill("clearly-fake-password")
    browser_page.locator("input[name='csrf_token']").evaluate(
        "(element) => { element.value = 'invalid-test-token'; }"
    )
    browser_page.locator("button[type='submit']").click()

    browser_page.get_by_role("heading", name="400").wait_for()
    browser_page.get_by_text(CSRF_ERROR_MESSAGE, exact=True).wait_for()
    assert RATE_LIMIT_MESSAGE not in browser_page.content()


def test_repeated_login_failures_use_the_standard_branded_429(
    live_server,
    browser_page,
):
    for _attempt in range(4):
        browser_page.goto(f"{live_server}/login", wait_until="load")
        browser_page.locator("input[name='identifier']").fill("unknown-e2e-customer")
        browser_page.locator("input[name='password']").fill("clearly-fake-password")
        browser_page.locator("button[type='submit']").click()
        browser_page.wait_for_load_state("load")
        if browser_page.get_by_role("heading", name="429").count():
            break

    browser_page.get_by_role("heading", name="429").wait_for()
    browser_page.get_by_text(RATE_LIMIT_MESSAGE, exact=True).wait_for()
    assert "Authentication backoff" not in browser_page.content()
