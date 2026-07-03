from __future__ import annotations

import os

import pytest

from tests.e2e.support import (
    RUN_E2E_ENV,
    browser_page,
    create_e2e_customer,
    live_server,
    login_customer_with_mfa,
)


pytestmark = [pytest.mark.e2e]
if os.environ.get(RUN_E2E_ENV) != "1":
    pytestmark.append(
        pytest.mark.skip(reason=f"set {RUN_E2E_ENV}=1 to run Playwright E2E browser tests")
    )


def test_sensitive_values_do_not_appear_in_dom_url_or_console(
    app,
    live_server,
    browser_page,
):
    password = "Correct Horse Battery Staple 2026!"
    customer = create_e2e_customer(
        app,
        username="e2e_sensitive_customer",
        password=password,
        email="e2e.sensitive@example.test",
        phone_number="91234567",
        account_number="012345678917",
        full_name="E2E Sensitive Customer",
        mfa_enabled=True,
    )
    console_messages: list[str] = []
    browser_page.on("console", lambda message: console_messages.append(message.text))
    login_customer_with_mfa(browser_page, live_server, customer)
    browser_page.goto(f"{live_server}/sessions", wait_until="load")

    content = browser_page.content()
    assert password not in content
    assert customer["secret"] not in content
    assert customer["account_number"] not in content
    assert password not in browser_page.url
    assert customer["secret"] not in browser_page.url
    assert customer["account_number"] not in browser_page.url
    assert not any(password in message for message in console_messages)
    assert not any(customer["secret"] in message for message in console_messages)
