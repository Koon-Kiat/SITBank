from __future__ import annotations

from contextlib import contextmanager

import pytest

from app.auth.services import AuthError
from app.extensions import db, limiter
from app.security.http_errors import CSRF_ERROR_MESSAGE, RATE_LIMIT_MESSAGE
from conftest import TestConfig


@contextmanager
def _admin_test_app():
    from app import create_app

    admin_app = create_app(TestConfig, app_mode="admin")
    with admin_app.app_context():
        db.create_all()
        limiter.reset()
        try:
            yield admin_app
        finally:
            limiter.reset()
            db.session.remove()
            db.drop_all()


def _raise_auth_error(message: str, status_code: int, *, retry_after: int | None = None):
    def raise_error(*_args, **_kwargs):
        raise AuthError(message, status_code, retry_after=retry_after)

    return raise_error


def test_customer_browser_auth_backoff_uses_standard_branded_response(app, monkeypatch):
    monkeypatch.setattr(
        "app.web.routes.authenticate_primary",
        _raise_auth_error("backend-specific throttling detail", 429, retry_after=17),
    )

    response = app.test_client().post(
        "/login",
        data={"identifier": "fake-customer", "password": "clearly-fake-password"},
    )

    assert response.status_code == 429
    assert response.content_type.startswith("text/html")
    assert RATE_LIMIT_MESSAGE.encode() in response.data
    assert b"SITBank" in response.data
    assert b"backend-specific throttling detail" not in response.data


def test_customer_limiter_and_auth_api_keep_safe_channel_specific_responses(app, monkeypatch):
    monkeypatch.setattr(
        "app.web.routes.authenticate_primary",
        _raise_auth_error("Invalid username or password", 401),
    )
    browser_client = app.test_client()
    for _attempt in range(5):
        response = browser_client.post(
            "/login",
            data={"identifier": "fake-customer", "password": "clearly-fake-password"},
        )
        assert response.status_code == 401

    browser_limited = browser_client.post(
        "/login",
        data={"identifier": "fake-customer", "password": "clearly-fake-password"},
    )

    limiter.reset()
    monkeypatch.setattr(
        "app.auth.routes.authenticate_primary",
        _raise_auth_error("API throttling detail", 429, retry_after=11),
    )
    api_limited = app.test_client().post(
        "/auth/login",
        json={"identifier": "fake-customer", "password": "clearly-fake-password"},
    )

    assert browser_limited.status_code == 429
    assert browser_limited.content_type.startswith("text/html")
    assert RATE_LIMIT_MESSAGE.encode() in browser_limited.data
    assert api_limited.status_code == 429
    assert api_limited.is_json
    assert api_limited.get_json() == {"error": "API throttling detail"}
    assert api_limited.headers["X-Auth-Retry-After"] == "11"
    assert int(api_limited.headers["Retry-After"]) > 0


def test_customer_csrf_failure_stays_distinct_from_rate_limiting(app):
    original = app.config["WTF_CSRF_ENABLED"]
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        response = app.test_client().post(
            "/login",
            data={"identifier": "fake-customer", "password": "clearly-fake-password"},
        )
    finally:
        app.config["WTF_CSRF_ENABLED"] = original

    assert response.status_code == 400
    assert response.content_type.startswith("text/html")
    assert CSRF_ERROR_MESSAGE.encode() in response.data
    assert RATE_LIMIT_MESSAGE.encode() not in response.data
    assert b'href="/login"' in response.data


def test_admin_browser_backoff_and_csrf_use_private_admin_pages(monkeypatch):
    with _admin_test_app() as admin_app:
        monkeypatch.setattr(
            "app.admin.routes.authenticate_admin_primary",
            _raise_auth_error("private authentication detail", 429, retry_after=13),
        )
        browser_client = admin_app.test_client()
        backoff = browser_client.post(
            "/login",
            data={
                "workplace_email": "fake.admin@sit.singaporetech.edu.sg",
                "password": "clearly-fake-password",
            },
        )

        admin_app.config["WTF_CSRF_ENABLED"] = True
        csrf_failure = admin_app.test_client().post(
            "/login",
            data={
                "workplace_email": "fake.admin@sit.singaporetech.edu.sg",
                "password": "clearly-fake-password",
            },
        )

    assert backoff.status_code == 429
    assert backoff.content_type.startswith("text/html")
    assert b"Private admin request status" in backoff.data
    assert RATE_LIMIT_MESSAGE.encode() in backoff.data
    assert b"private authentication detail" not in backoff.data
    assert csrf_failure.status_code == 400
    assert csrf_failure.content_type.startswith("text/html")
    assert CSRF_ERROR_MESSAGE.encode() in csrf_failure.data
    assert RATE_LIMIT_MESSAGE.encode() not in csrf_failure.data
    assert b"Return to admin login" in csrf_failure.data


def test_admin_json_limiter_response_remains_structured(monkeypatch):
    with _admin_test_app() as admin_app:
        monkeypatch.setattr(
            "app.admin.routes.authenticate_admin_primary",
            _raise_auth_error("Invalid workplace email, password, or authentication code", 401),
        )
        client = admin_app.test_client()
        for _attempt in range(5):
            response = client.post(
                "/login",
                json={
                    "workplace_email": "fake.admin@sit.singaporetech.edu.sg",
                    "password": "clearly-fake-password",
                },
            )
            assert response.status_code == 401

        limited = client.post(
            "/login",
            json={
                "workplace_email": "fake.admin@sit.singaporetech.edu.sg",
                "password": "clearly-fake-password",
            },
        )

    assert limited.status_code == 429
    assert limited.is_json
    assert limited.get_json() == {"error": RATE_LIMIT_MESSAGE}


@pytest.mark.parametrize(
    "path",
    [
        "/invites",
        "/invites/1/revoke",
        "/staff/1/deactivate",
        "/manual-recovery/requests/1/transition",
        "/manual-recovery/requests/1/complete",
        "/admin-action-requests/1/approve",
        "/alerts/deliver",
    ],
)
def test_admin_high_risk_browser_routes_share_rate_limit_page(path):
    with _admin_test_app() as admin_app:
        client = admin_app.test_client()
        responses = [
            client.post(
                path,
                data={"totp_code": "000000", "reason": "fake test reason", "status": "denied"},
                environ_overrides={"REMOTE_ADDR": "198.51.100.200"},
            )
            for _index in range(11)
        ]

    limited = next((response for response in responses if response.status_code == 429), None)
    assert limited is not None
    assert limited.content_type.startswith("text/html")
    assert b"Private admin request status" in limited.data
    assert RATE_LIMIT_MESSAGE.encode() in limited.data
