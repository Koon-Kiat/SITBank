from __future__ import annotations

import json
import http.client
from urllib import parse

from flask import Flask, current_app, request


class TurnstileError(ValueError):
    pass


_CHALLENGE_FAILED_MESSAGE = "Challenge verification failed"
OFFICIAL_TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_TEST_SITE_KEY = "1x00000000000000000000AA"
TURNSTILE_TEST_SECRET_KEY = "1x0000000000000000000000000000000AA"
TURNSTILE_TEST_TOKEN = "XXXX.DUMMY.TOKEN.XXXX"
TURNSTILE_TEST_ACTION = "test"
_TURNSTILE_TOKEN_FIELDS = ("cf-turnstile-response", "turnstile_token")
_ACTION_CONFIG = {
    "customer_login": "TURNSTILE_CUSTOMER_LOGIN_ENABLED",
    "customer_register_otp": "TURNSTILE_CUSTOMER_REGISTER_OTP_ENABLED",
    "customer_register": "TURNSTILE_CUSTOMER_REGISTER_ENABLED",
    "customer_password_reset": "TURNSTILE_CUSTOMER_PASSWORD_RESET_ENABLED",
    "customer_manual_recovery": "TURNSTILE_CUSTOMER_MANUAL_RECOVERY_ENABLED",
    "admin_login": "TURNSTILE_ADMIN_LOGIN_ENABLED",
    "admin_invite_accept": "TURNSTILE_ADMIN_INVITE_ACCEPT_ENABLED",
}


def verify_turnstile_token(token: str | None, *, expected_action: str | None = None) -> None:
    if not current_app.config.get("TURNSTILE_ENABLED", False):
        return
    token_text = str(token or "").strip()
    secret_key = str(current_app.config.get("TURNSTILE_SECRET_KEY") or "").strip()
    if not token_text or not secret_key:
        raise TurnstileError(_CHALLENGE_FAILED_MESSAGE)

    payload = parse.urlencode(
        {
            "secret": secret_key,
            "response": token_text,
            "remoteip": request.remote_addr or "",
        }
    ).encode("utf-8")
    try:
        host, port, target = _turnstile_verify_target()
        connection = http.client.HTTPSConnection(host, port=port, timeout=5)
        try:
            connection.request(
                "POST",
                target,
                body=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response = connection.getresponse()
            body = response.read(16 * 1024)
        finally:
            connection.close()
        result = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise TurnstileError(_CHALLENGE_FAILED_MESSAGE) from exc
    if not isinstance(result, dict) or result.get("success") is not True:
        raise TurnstileError(_CHALLENGE_FAILED_MESSAGE)
    action_matches = not expected_action or result.get("action") == expected_action
    if not action_matches and not _accepts_test_action(token_text, result):
        raise TurnstileError(_CHALLENGE_FAILED_MESSAGE)
    _verify_turnstile_hostname(result)


def _verify_turnstile_hostname(result: dict[str, object]) -> None:
    """Fail closed unless the Siteverify response hostname is expected.

    When ``TURNSTILE_ALLOWED_HOSTNAMES`` is configured, the provider-returned
    hostname must match it in every environment. When it is not configured,
    production-like deployments still fail closed rather than silently
    accepting a token solved against an unexpected hostname; local/test
    deployments are left permissive so fixtures do not need a hostname field.
    """
    allowed_hostnames = current_app.config.get("TURNSTILE_ALLOWED_HOSTNAMES") or frozenset()
    if allowed_hostnames:
        provided_hostname = str(result.get("hostname") or "").strip().casefold()
        if provided_hostname not in allowed_hostnames:
            raise TurnstileError(_CHALLENGE_FAILED_MESSAGE)
        return
    if _production_like():
        raise TurnstileError(_CHALLENGE_FAILED_MESSAGE)


def require_turnstile(action: str, token: str | None = None) -> None:
    config_key = _turnstile_action_config_key(action)
    if (
        _production_like()
        and current_app.config.get("TURNSTILE_FAIL_CLOSED_IN_PRODUCTION", True)
        and (
            not current_app.config.get("TURNSTILE_ENABLED", False)
            or not current_app.config.get(config_key, False)
        )
    ):
        raise TurnstileError(_CHALLENGE_FAILED_MESSAGE)
    if not _turnstile_required_for_config(config_key):
        return
    validate_turnstile_runtime_config(action)
    verify_turnstile_token(
        token if token is not None else turnstile_token_from_request(),
        expected_action=action,
    )


def turnstile_required_for_action(action: str) -> bool:
    return _turnstile_required_for_config(_turnstile_action_config_key(action))


def turnstile_widget_enabled(action: str) -> bool:
    if not turnstile_required_for_action(action):
        return False
    return bool(str(current_app.config.get("TURNSTILE_SITE_KEY") or "").strip())


def turnstile_token_from_request() -> str | None:
    payload = request.get_json(silent=True) if request.is_json else None
    if isinstance(payload, dict):
        for field_name in _TURNSTILE_TOKEN_FIELDS:
            value = payload.get(field_name)
            if value:
                return str(value)
    for field_name in _TURNSTILE_TOKEN_FIELDS:
        value = request.form.get(field_name)
        if value:
            return str(value)
    return None


def validate_turnstile_runtime_config(action: str | None = None) -> None:
    if action:
        _turnstile_action_config_key(action)
    if not current_app.config.get("TURNSTILE_ENABLED", False):
        return
    secret_key = str(current_app.config.get("TURNSTILE_SECRET_KEY") or "").strip()
    if not secret_key:
        raise TurnstileError(_CHALLENGE_FAILED_MESSAGE)
    if action and _production_like():
        site_key = str(current_app.config.get("TURNSTILE_SITE_KEY") or "").strip()
        if not site_key:
            raise TurnstileError(_CHALLENGE_FAILED_MESSAGE)
    _turnstile_verify_target()


def register_turnstile_template_helpers(app: Flask) -> None:
    @app.context_processor
    def turnstile_context() -> dict[str, object]:
        return {
            "turnstile_site_key": str(app.config.get("TURNSTILE_SITE_KEY") or ""),
            "turnstile_widget_enabled": turnstile_widget_enabled,
        }


def _turnstile_verify_target() -> tuple[str, int | None, str]:
    raw_url = str(current_app.config["TURNSTILE_VERIFY_URL"])
    parsed = parse.urlsplit(raw_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise TurnstileError(_CHALLENGE_FAILED_MESSAGE)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise TurnstileError(_CHALLENGE_FAILED_MESSAGE)
    if _production_like() and raw_url != OFFICIAL_TURNSTILE_VERIFY_URL:
        raise TurnstileError(_CHALLENGE_FAILED_MESSAGE)
    path = parsed.path or "/"
    return parsed.hostname, parsed.port, path


def _turnstile_action_config_key(action: str) -> str:
    config_key = _ACTION_CONFIG.get(str(action or "").strip())
    if not config_key:
        raise TurnstileError(_CHALLENGE_FAILED_MESSAGE)
    return config_key


def _accepts_test_action(token: str, result: dict[str, object]) -> bool:
    return (
        current_app.config.get("TURNSTILE_ALLOW_TEST_ACTION") is True
        and token == TURNSTILE_TEST_TOKEN
        and result.get("action") == TURNSTILE_TEST_ACTION
        and str(current_app.config.get("DEPLOYMENT_TARGET") or "").strip().casefold() == "smoke"
        and str(current_app.config.get("TURNSTILE_SITE_KEY") or "").strip()
        == TURNSTILE_TEST_SITE_KEY
        and str(current_app.config.get("TURNSTILE_SECRET_KEY") or "").strip()
        == TURNSTILE_TEST_SECRET_KEY
    )


def _turnstile_required_for_config(config_key: str) -> bool:
    return bool(current_app.config.get("TURNSTILE_ENABLED", False)) and bool(
        current_app.config.get(config_key, False)
    )


def _production_like() -> bool:
    app_env = str(current_app.config.get("APP_ENV") or "").strip().casefold()
    deployment_target = str(current_app.config.get("DEPLOYMENT_TARGET") or "").strip().casefold()
    return app_env == "production" or deployment_target in {"staging", "production"}
