from __future__ import annotations

import os
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from urllib.parse import urlparse

import pyotp
import pytest
from werkzeug.serving import make_server

from app.extensions import db
from app.models import Payee, User
from app.security.email import password_reset_outbox
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password


RUN_E2E_ENV = "SITBANK_RUN_E2E"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
_TOTP_INTERVAL_SECONDS = 30
_MIN_TOTP_SECONDS_REMAINING = 10


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


@pytest.fixture()
def browser_context_factory():
    sync_api = pytest.importorskip(
        "playwright.sync_api",
        reason="install requirements-dev.lock to run Playwright E2E tests",
    )
    headless = os.environ.get("SITBANK_E2E_HEADLESS", "1") != "0"
    contexts = []
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

        def create_page():
            context = browser.new_context(ignore_https_errors=False)
            contexts.append(context)
            return context.new_page()

        try:
            yield create_page
        finally:
            for context in reversed(contexts):
                context.close()
            browser.close()


@pytest.fixture()
def admin_live_server():
    from app import create_app
    from conftest import TestConfig

    admin_app = create_app(TestConfig, app_mode="admin")
    with admin_app.app_context():
        db.create_all()
    with _serve_loopback(admin_app) as base_url:
        yield admin_app, base_url
    with admin_app.app_context():
        db.session.remove()
        db.drop_all()


@contextmanager
def _serve_loopback(flask_app):
    server = make_server("127.0.0.1", 0, flask_app, threaded=False)
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
    account_type: str = "customer",
    account_status: str = "active",
    is_frozen: bool = False,
) -> dict[str, str]:
    with app.app_context():
        user = User(
            username=username,
            email=email,
            password_hash=_cached_fake_password_hash(app, password),
            full_name=full_name,
            phone_number=phone_number,
            account_number=account_number,
            account_type=account_type,
            account_status=account_status,
            is_frozen=is_frozen,
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
        user_id = int(user.id)
    return {
        "id": str(user_id),
        "username": username,
        "password": password,
        "secret": secret,
        "phone_number": phone_number,
        "full_name": full_name,
        "account_number": account_number,
        "email": email,
    }


def create_e2e_admin(
    app,
    *,
    email: str,
    password: str,
    full_name: str = "E2E Root Admin",
) -> dict[str, str]:
    with app.app_context():
        user = User(
            username="e2e-root-admin",
            email=email,
            password_hash=_cached_fake_password_hash(app, password),
            full_name=full_name,
            phone_number="91234567",
            account_number=None,
            account_type="root_admin",
            account_status="active",
            workplace_email_verified_at=datetime.now(timezone.utc),
        )
        db.session.add(user)
        db.session.flush()
        secret = pyotp.random_base32(length=32)
        user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
        user.mfa_enabled = True
        db.session.commit()
    return {"email": email, "password": password, "secret": secret}


def create_e2e_payee(
    app,
    *,
    customer_id: int,
    recipient: dict[str, str],
    nickname: str = "Trusted Recipient",
    cooldown_elapsed: bool = True,
) -> int:
    created_at = datetime.now(timezone.utc)
    if cooldown_elapsed:
        created_at -= timedelta(days=2)
    with app.app_context():
        payee = Payee(
            user_id=customer_id,
            nickname=nickname,
            account_number=recipient["account_number"],
            recipient_name=recipient["full_name"],
            created_at=created_at,
        )
        db.session.add(payee)
        db.session.commit()
        return int(payee.id)


def login_customer_with_mfa(
    page,
    base_url: str,
    customer: dict[str, str],
    *,
    totp_offset_seconds: int = 0,
) -> None:
    page.goto(f"{base_url}/login", wait_until="load")
    page.locator("input[name='identifier']").fill(customer["username"])
    page.locator("input[name='password']").fill(customer["password"])
    page.locator("button[type='submit']").click()
    page.wait_for_url("**/mfa/verify", wait_until="load")
    page.locator("input[name='totp_code']").fill(
        totp_for_offset(customer["secret"], totp_offset_seconds)
    )
    page.get_by_role("button", name="Verify code").click()
    page.wait_for_url("**/dashboard", wait_until="load")


def current_totp(secret: str) -> str:
    _wait_for_stable_totp_window()
    return pyotp.TOTP(secret, digits=6, interval=30).now()


def totp_for_offset(secret: str, offset_seconds: int) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).at(
        int(time.time()) + offset_seconds
    )


def _wait_for_stable_totp_window() -> None:
    remaining = _TOTP_INTERVAL_SECONDS - (time.time() % _TOTP_INTERVAL_SECONDS)
    if remaining < _MIN_TOTP_SECONDS_REMAINING:
        time.sleep(remaining + 0.2)


def record_console_errors(page) -> list[str]:
    errors: list[str] = []

    def collect_error(message):
        if message.type == "error":
            errors.append(message.text)

    page.on("console", collect_error)
    return errors


def latest_registration_code(app) -> str:
    with app.app_context():
        body = password_reset_outbox()[-1]["body"]
    match = re.search(r"\b([0-9]{6})\b", body)
    if match is None:
        raise AssertionError("fake registration delivery did not contain a code")
    return match.group(1)


def latest_password_reset_token(app) -> str:
    with app.app_context():
        deliveries = list(password_reset_outbox())
    for delivery in reversed(deliveries):
        match = re.search(
            r"/reset-password\?token=([A-Za-z0-9_.-]+)",
            delivery["body"],
        )
        if match is not None:
            return match.group(1)
    raise AssertionError("fake password-reset delivery did not contain a token")


def _cached_fake_password_hash(app, password: str) -> str:
    cache = app.extensions.setdefault("e2e_fake_password_hashes", {})
    password_hash = cache.get(password)
    if password_hash is None:
        password_hash = hash_password(password)
        cache[password] = password_hash
    return password_hash


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
