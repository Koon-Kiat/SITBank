from __future__ import annotations

import importlib

import pytest

from app.extensions import db
from app.security.production_guard import (
    ProductionReadinessResult,
    ProductionStartupSecurityError,
    enforce_production_startup_guard,
    validate_production_security_prerequisites,
)
from config import MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS, MIN_PRODUCTION_PASSWORD_LENGTH
from conftest import TestConfig


def _production_app(monkeypatch, *, app_mode: str = "customer"):
    from app import create_app
    import app.security.production_guard as production_guard

    monkeypatch.setattr(production_guard, "validate_common_password_dictionary", lambda: 100000)
    app = create_app(TestConfig, app_mode=app_mode)
    app.config.update(
        APP_ENV="production",
        TRUSTED_PROXY_COUNT=1,
        WTF_CSRF_ENABLED=True,
        WTF_CSRF_CHECK_DEFAULT=True,
        TALISMAN_FORCE_HTTPS=True,
        PAYEE_COOLDOWN_SECONDS=MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS,
        MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS=MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS,
        PASSWORD_MIN_LENGTH=MIN_PRODUCTION_PASSWORD_LENGTH,
        SECURITY_ALERT_ENABLED=True,
        SECURITY_ALERT_WEBHOOK_URL="https://hooks.example.test/sitbank-security-alerts",
    )
    if app_mode == "admin":
        app.config["RATELIMIT_KEY_PREFIX"] = "ospbank:admin:ratelimit:"
    with app.app_context():
        db.create_all()
    return app


def test_shared_validator_accepts_safe_customer_production_configuration(monkeypatch):
    app = _production_app(monkeypatch)

    result = validate_production_security_prerequisites(app, app_mode="customer")

    assert result.ready
    assert result.details["password_min_length"] == MIN_PRODUCTION_PASSWORD_LENGTH
    assert result.details["session_hmac_key_count"] == 2
    assert result.details["mfa_kek_count"] == 2


def test_shared_validator_rejects_weak_production_password_minimum(monkeypatch):
    app = _production_app(monkeypatch)
    app.config["PASSWORD_MIN_LENGTH"] = MIN_PRODUCTION_PASSWORD_LENGTH - 1

    result = validate_production_security_prerequisites(app, app_mode="customer")

    assert not result.ready
    assert any("PASSWORD_MIN_LENGTH" in failure for failure in result.failures)


def test_production_check_rejects_weak_password_minimum(monkeypatch):
    app = _production_app(monkeypatch)
    app.config["PASSWORD_MIN_LENGTH"] = MIN_PRODUCTION_PASSWORD_LENGTH - 1

    result = app.test_cli_runner().invoke(args=["production-check"])

    assert result.exit_code != 0
    assert "PASSWORD_MIN_LENGTH" in result.output
    assert str(MIN_PRODUCTION_PASSWORD_LENGTH) in result.output
    assert "password_pepper" not in result.output


def test_startup_guard_fails_closed_and_logs_only_sanitized_reason(monkeypatch, caplog):
    app = _production_app(monkeypatch)
    raw_lookup_key = "lookup-key-that-must-never-appear-in-logs"
    app.config["SESSION_LOOKUP_HMAC_KEY"] = raw_lookup_key

    with pytest.raises(ProductionStartupSecurityError, match="SESSION_LOOKUP_HMAC_KEY"):
        enforce_production_startup_guard(app, app_mode="customer")

    assert raw_lookup_key not in caplog.text
    assert "Production startup security guard failed" in caplog.text


def test_production_readiness_fails_closed_without_disclosing_failure_details(monkeypatch, caplog):
    app = _production_app(monkeypatch)
    client = app.test_client()

    assert client.get("/health/ready").get_json() == {"status": "ready"}

    app.config["SESSION_LOOKUP_HMAC_KEY"] = b"too-short"
    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.get_json() == {"status": "unavailable"}
    assert "SESSION_LOOKUP_HMAC_KEY must be configured as 32 bytes" in caplog.text
    assert "too-short" not in caplog.text


def test_admin_validator_enforces_admin_isolation(monkeypatch):
    app = _production_app(monkeypatch, app_mode="admin")
    app.config["ADMIN_AUTH_ENABLED"] = False

    result = validate_production_security_prerequisites(app, app_mode="admin")

    assert "Admin authentication must be enabled" in result.failures


def test_startup_guard_is_inactive_outside_production(monkeypatch):
    from app import create_app

    app = create_app(TestConfig)
    app.config["SESSION_LOOKUP_HMAC_KEY"] = None

    enforce_production_startup_guard(app, app_mode="customer")


@pytest.mark.parametrize(
    ("module_name", "mode"),
    [("wsgi", "customer"), ("admin_wsgi", "admin")],
)
def test_wsgi_entrypoints_enforce_the_guard_for_runtime_processes(monkeypatch, module_name, mode):
    module = importlib.import_module(module_name)
    expected_app = object()
    observed: list[tuple[object, str]] = []

    monkeypatch.setattr(module, "create_app", lambda **_kwargs: expected_app)
    monkeypatch.setattr(module, "_is_flask_cli_process", lambda: False)
    monkeypatch.setattr(
        module,
        "enforce_production_startup_guard",
        lambda app, *, app_mode: observed.append((app, app_mode)),
    )

    assert module.create_runtime_wsgi_app() is expected_app
    assert observed == [(expected_app, mode)]


def test_wsgi_entrypoint_skips_guard_for_flask_cli(monkeypatch):
    import wsgi

    expected_app = object()
    monkeypatch.setattr(wsgi, "create_app", lambda **_kwargs: expected_app)
    monkeypatch.setattr(wsgi, "_is_flask_cli_process", lambda: True)
    monkeypatch.setattr(
        wsgi,
        "enforce_production_startup_guard",
        lambda *_args, **_kwargs: pytest.fail("WSGI guard must not run for Flask CLI"),
    )

    assert wsgi.create_runtime_wsgi_app() is expected_app


def test_production_check_uses_shared_validator(monkeypatch):
    from app import create_app
    import app.ops.commands as commands

    app = create_app(TestConfig)
    monkeypatch.setattr(
        commands,
        "validate_production_security_prerequisites",
        lambda *_args, **_kwargs: ProductionReadinessResult(
            failures=["shared validator failure"],
        ),
    )

    result = app.test_cli_runner().invoke(args=["production-check"])

    assert result.exit_code != 0
    assert "shared validator failure" in result.output
