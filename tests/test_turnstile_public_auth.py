import pytest
from flask import render_template_string

from app.security import turnstile


_TURNSTILE_ORIGIN = "https://challenges.cloudflare.com"


def test_customer_login_turnstile_accepts_standard_cloudflare_field(app, client, monkeypatch):
    app.config.update(
        TURNSTILE_ENABLED=True,
        TURNSTILE_SECRET_KEY="fake-turnstile-secret",
        TURNSTILE_CUSTOMER_LOGIN_ENABLED=True,
    )
    calls = []

    def fake_verify(token, *, expected_action=None):
        calls.append((token, expected_action))

    monkeypatch.setattr(turnstile, "verify_turnstile_token", fake_verify)

    response = client.post(
        "/auth/login",
        json={
            "identifier": "missing-user",
            "password": "wrong-password-value",
            "cf-turnstile-response": "browser-token",
        },
    )

    assert response.status_code == 401
    assert calls == [("browser-token", "customer_login")]
    assert "browser-token" not in response.get_data(as_text=True)


def test_route_specific_turnstile_disabled_skips_verifier(app, client, monkeypatch):
    app.config.update(
        TURNSTILE_ENABLED=True,
        TURNSTILE_SECRET_KEY="fake-turnstile-secret",
        TURNSTILE_CUSTOMER_LOGIN_ENABLED=False,
    )

    def fail_verify(_token, *, expected_action=None):
        raise AssertionError("route-disabled Turnstile should not verify")

    monkeypatch.setattr(turnstile, "verify_turnstile_token", fail_verify)

    response = client.post(
        "/auth/login",
        json={"identifier": "missing-user", "password": "wrong-password-value"},
    )

    assert response.status_code == 401


def test_turnstile_widget_and_csp_are_narrow(app, client):
    app.config.update(
        TURNSTILE_ENABLED=True,
        TURNSTILE_SITE_KEY="fake-site-key",
        TURNSTILE_CUSTOMER_LOGIN_ENABLED=True,
    )

    response = client.get("/login")
    markup = response.get_data(as_text=True)
    csp = response.headers["Content-Security-Policy"]
    csp_directives = _csp_directives(csp)

    assert response.status_code == 200
    assert 'class="cf-turnstile"' in markup
    assert 'data-action="customer_login"' in markup
    assert _TURNSTILE_ORIGIN in csp_directives.get("script-src", [])
    assert _TURNSTILE_ORIGIN in csp_directives.get("frame-src", [])
    assert "*.cloudflare.com" not in csp_directives.get("script-src", [])
    assert "*.cloudflare.com" not in csp_directives.get("frame-src", [])
    assert "'unsafe-inline'" not in csp_directives.get("script-src", [])


def test_production_enabled_route_requires_site_key(app):
    app.config.update(
        APP_ENV="production",
        DEPLOYMENT_TARGET="production",
        TURNSTILE_ENABLED=True,
        TURNSTILE_SECRET_KEY="fake-turnstile-secret",
        TURNSTILE_SITE_KEY="",
        TURNSTILE_CUSTOMER_LOGIN_ENABLED=True,
        TURNSTILE_VERIFY_URL=turnstile.OFFICIAL_TURNSTILE_VERIFY_URL,
    )

    with app.test_request_context("/auth/login", method="POST"):
        with pytest.raises(turnstile.TurnstileError):
            turnstile.require_turnstile("customer_login", "browser-token")


def test_unknown_turnstile_action_fails_closed_even_when_disabled(app):
    app.config.update(TURNSTILE_ENABLED=False)

    with app.test_request_context("/auth/login", method="POST"):
        with pytest.raises(turnstile.TurnstileError):
            turnstile.require_turnstile("customer_lgoin", "browser-token")


def test_multiple_turnstile_widgets_load_script_once(app):
    app.config.update(
        TURNSTILE_ENABLED=True,
        TURNSTILE_SITE_KEY="fake-site-key",
        TURNSTILE_CUSTOMER_LOGIN_ENABLED=True,
        TURNSTILE_CUSTOMER_REGISTER_OTP_ENABLED=True,
    )

    with app.test_request_context("/"):
        markup = render_template_string(
            """
            {% import "_turnstile.html" as turnstile with context %}
            {{ turnstile.widget("customer_login") }}
            {{ turnstile.widget("customer_register_otp") }}
            """
        )

    assert markup.count('class="cf-turnstile"') == 2
    assert markup.count("https://challenges.cloudflare.com/turnstile/v0/api.js") == 1


def _csp_directives(csp: str) -> dict[str, list[str]]:
    directives = {}
    for raw_directive in csp.split(";"):
        parts = raw_directive.strip().split()
        if parts:
            directives[parts[0]] = parts[1:]
    return directives
