from __future__ import annotations

import os
import threading
from decimal import Decimal
from urllib.parse import urlparse

import pyotp
import pytest
from werkzeug.serving import make_server

from app.extensions import db
from app.models import User
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password


RUN_E2E_ENV = "SITBANK_RUN_E2E"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


@pytest.fixture()
def live_server(app):
    # Keep the browser smoke server serial so the shared in-memory SQLite test
    # database is not touched concurrently by page and asset requests.
    server = make_server("127.0.0.1", 0, app, threaded=False)
    base_url = f"http://127.0.0.1:{server.server_port}"
    _assert_local_base_url(base_url)
    thread = threading.Thread(
        target=server.serve_forever,
        name="sitbank-e2e-server",
        daemon=True,
    )
    thread.start()
    try:
        yield base_url
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture()
def browser_page():
    sync_api = pytest.importorskip(
        "playwright.sync_api",
        reason="install requirements-dev.lock to run Playwright E2E tests",
    )
    headless = os.environ.get("SITBANK_E2E_HEADLESS", "1") != "0"
    with sync_api.sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(headless=headless)
        except Exception as exc:  # pragma: no cover - depends on local browser cache
            if _looks_like_missing_browser(exc):
                pytest.skip(
                    "Playwright Chromium is not installed; run "
                    "python -m playwright install chromium"
                )
            raise
        context = browser.new_context(ignore_https_errors=False)
        page = context.new_page()
        try:
            yield page
        finally:
            context.close()
            browser.close()


def create_e2e_customer(
    app,
    *,
    username: str,
    password: str,
    email: str,
    phone_number: str,
    account_number: str,
    full_name: str,
    balance: Decimal = Decimal("5000.00"),
    mfa_enabled: bool = False,
) -> dict[str, str]:
    with app.app_context():
        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            full_name=full_name,
            phone_number=phone_number,
            account_number=account_number,
            account_type="customer",
            account_status="active",
            balance=balance,
        )
        db.session.add(user)
        db.session.flush()
        secret = ""
        if mfa_enabled:
            secret = pyotp.random_base32(length=32)
            user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
            user.mfa_enabled = True
        db.session.commit()
    return {
        "username": username,
        "password": password,
        "secret": secret,
        "phone_number": phone_number,
        "full_name": full_name,
    }


def login_customer_with_mfa(page, base_url: str, customer: dict[str, str]) -> None:
    page.goto(f"{base_url}/login", wait_until="load")
    page.locator("input[name='identifier']").fill(customer["username"])
    page.locator("input[name='password']").fill(customer["password"])
    page.locator("button[type='submit']").click()
    page.wait_for_url("**/mfa/verify", wait_until="load")
    page.locator("input[name='totp_code']").fill(current_totp(customer["secret"]))
    page.get_by_role("button", name="Verify code").click()
    page.wait_for_url("**/dashboard", wait_until="load")


def current_totp(secret: str) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).now()


def record_console_errors(page) -> list[str]:
    errors: list[str] = []

    def collect_error(message):
        if message.type == "error":
            errors.append(message.text)

    page.on("console", collect_error)
    return errors


def _assert_local_base_url(base_url: str) -> None:
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname not in LOCAL_HOSTS:
        raise RuntimeError("Playwright E2E tests may only use a loopback live server")


def _looks_like_missing_browser(exc: Exception) -> bool:
    message = str(exc).casefold()
    return (
        "executable doesn't exist" in message
        or "playwright install" in message
        or "browser has not been installed" in message
    )
