from __future__ import annotations

import os
import threading
from urllib.parse import urlparse

import pytest
from werkzeug.serving import make_server


RUN_E2E_ENV = "SITBANK_RUN_E2E"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


@pytest.fixture()
def live_server(app):
    server = make_server("127.0.0.1", 0, app, threaded=True)
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
