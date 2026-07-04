from __future__ import annotations

import importlib

import pytest

from app.extensions import db
from app.models import User
from app.security.production_guard import (
    ProductionReadinessResult,
    ProductionStartupSecurityError,
    _validate_admin_mode_and_routes,
    _validate_customer_mode_and_routes,
    _validate_registration_identity_policy,
    _validate_turnstile_policy,
    enforce_production_startup_guard,
    validate_production_security_prerequisites,
)
from config import MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS, MIN_PRODUCTION_PASSWORD_LENGTH
from conftest import TestConfig


EXPLICIT_ROOT_ADMIN_EMAILS = frozenset(
    f"chief{index}@sit.singaporetech.edu.sg"
    for index in range(1, 6)
)


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
        TURNSTILE_ENABLED=True,
        TURNSTILE_SITE_KEY="1x00000000000000000000AA",
        TURNSTILE_SECRET_KEY="1x0000000000000000000000000000000AA",
        TURNSTILE_CUSTOMER_LOGIN_ENABLED=True,
        TURNSTILE_CUSTOMER_REGISTER_OTP_ENABLED=True,
        TURNSTILE_CUSTOMER_REGISTER_ENABLED=True,
        TURNSTILE_CUSTOMER_PASSWORD_RESET_ENABLED=True,
        TURNSTILE_CUSTOMER_MANUAL_RECOVERY_ENABLED=True,
        TURNSTILE_ADMIN_LOGIN_ENABLED=True,
        TURNSTILE_ADMIN_INVITE_ACCEPT_ENABLED=True,
        TURNSTILE_FAIL_CLOSED_IN_PRODUCTION=True,
    )
    if app_mode == "admin":
        app.config["RATELIMIT_KEY_PREFIX"] = "ospbank:admin:ratelimit:"
        app.config["ROOT_ADMIN_EMAILS"] = EXPLICIT_ROOT_ADMIN_EMAILS
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


def test_identity_and_turnstile_readiness_reject_missing_policy_inputs(monkeypatch):
    app = _production_app(monkeypatch)
    app.config.update(
        TURNSTILE_SECRET_KEY="",
        CUSTOMER_EMAIL_PLUS_ALIAS_DOMAINS=(),
        CUSTOMER_EMAIL_DOT_INSENSITIVE_DOMAINS=("gmail.com",),
        CUSTOMER_TEMP_EMAIL_DOMAINS=(),
    )
    result = ProductionReadinessResult()

    _validate_turnstile_policy(app, result)
    _validate_registration_identity_policy(app, result)

    assert "TURNSTILE_SECRET_KEY must be configured" in result.failures
    assert "CUSTOMER_EMAIL_PLUS_ALIAS_DOMAINS must be configured" in result.failures
    assert any(
        failure.startswith("CUSTOMER_EMAIL_DOT_INSENSITIVE_DOMAINS")
        for failure in result.failures
    )
    assert "CUSTOMER_TEMP_EMAIL_DOMAINS must be configured" in result.failures

    app.config.update(
        CUSTOMER_EMAIL_PLUS_ALIAS_DOMAINS=("gmail.com",),
        CUSTOMER_EMAIL_DOT_INSENSITIVE_DOMAINS=("gmail.com",),
        CUSTOMER_TEMP_EMAIL_DOMAINS=("sit.singaporetech.edu.sg",),
    )
    overlap_result = ProductionReadinessResult()
    _validate_registration_identity_policy(app, overlap_result)

    assert (
        "CUSTOMER_TEMP_EMAIL_DOMAINS must not include workplace domains"
        in overlap_result.failures
    )


def test_production_readiness_rejects_turnstile_test_action_allowance(monkeypatch):
    app = _production_app(monkeypatch)
    app.config["TURNSTILE_ALLOW_TEST_ACTION"] = True
    result = ProductionReadinessResult()

    _validate_turnstile_policy(app, result)

    assert "TURNSTILE_ALLOW_TEST_ACTION must be false" in result.failures


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


def test_mode_helpers_report_every_isolation_misconfiguration(monkeypatch):
    admin_app = _production_app(monkeypatch, app_mode="admin")
    admin_app.config.update(
        SESSION_COOKIE_NAME="wrong",
        SESSION_KEY_PREFIX="customer-",
        AUTH_FAILURE_KEY_PREFIX="customer:",
        RATELIMIT_KEY_PREFIX="customer:",
        ROOT_ADMIN_EMAILS=(),
    )
    admin_result = ProductionReadinessResult()

    _validate_admin_mode_and_routes(
        admin_app,
        {"main.index"},
        admin_result,
    )

    assert {
        "Admin session cookie name must be isolated",
        "Admin session key prefix must be isolated",
        "Admin auth security-state prefix must be isolated",
        "Admin rate-limit key prefix must be isolated",
        "ROOT_ADMIN_EMAILS must configure exactly 5 root administrators",
        "Admin runtime must not register customer routes",
    } <= set(admin_result.failures)

    customer_app = _production_app(monkeypatch)
    customer_app.config.update(
        ADMIN_AUTH_ENABLED=True,
        SESSION_COOKIE_NAME="__Host-sitbank_admin_session",
        SESSION_KEY_PREFIX="admin-session:",
    )
    customer_result = ProductionReadinessResult()

    _validate_customer_mode_and_routes(
        customer_app,
        {"admin.dashboard"},
        customer_result,
    )

    assert {
        "Customer runtime must not enable admin authentication",
        "Customer session cookie name must not collide with admin",
        "Customer session key prefix must not use the admin namespace",
        "Customer runtime must not register admin routes",
    } <= set(customer_result.failures)


def test_admin_validator_rejects_root_admin_allowlist_outside_admin_domains(monkeypatch):
    app = _production_app(monkeypatch, app_mode="admin")
    app.config["ROOT_ADMIN_EMAILS"] = frozenset(
        {
            "root1@example.com",
            "root2@sit.singaporetech.edu.sg",
            "root3@sit.singaporetech.edu.sg",
            "root4@sit.singaporetech.edu.sg",
            "root5@sit.singaporetech.edu.sg",
        }
    )

    result = validate_production_security_prerequisites(app, app_mode="admin")

    assert "ROOT_ADMIN_EMAILS must use approved admin workplace domains" in result.failures


@pytest.mark.parametrize(
    ("emails", "expected_failure"),
    [
        (
            TestConfig.ROOT_ADMIN_EMAILS,
            "ROOT_ADMIN_EMAILS must be explicitly configured for production/admin runtime",
        ),
        (
            tuple(reversed(tuple(TestConfig.ROOT_ADMIN_EMAILS))),
            "ROOT_ADMIN_EMAILS must be explicitly configured for production/admin runtime",
        ),
        (
            tuple(item.upper() for item in TestConfig.ROOT_ADMIN_EMAILS),
            "ROOT_ADMIN_EMAILS must be explicitly configured for production/admin runtime",
        ),
        (
            (
                "chief1@sit.singaporetech.edu.sg",
                "chief1@sit.singaporetech.edu.sg",
                "chief3@sit.singaporetech.edu.sg",
                "chief4@sit.singaporetech.edu.sg",
                "chief5@sit.singaporetech.edu.sg",
            ),
            "ROOT_ADMIN_EMAILS must not contain duplicate email addresses",
        ),
        (
            (
                "demo@sit.singaporetech.edu.sg",
                "chief2@sit.singaporetech.edu.sg",
                "chief3@sit.singaporetech.edu.sg",
                "chief4@sit.singaporetech.edu.sg",
                "chief5@sit.singaporetech.edu.sg",
            ),
            "ROOT_ADMIN_EMAILS must not contain placeholder, demo, or example identities",
        ),
    ],
)
def test_admin_validator_rejects_unsafe_root_admin_allowlists(
    monkeypatch,
    emails,
    expected_failure,
):
    app = _production_app(monkeypatch, app_mode="admin")
    app.config["ROOT_ADMIN_EMAILS"] = emails

    result = validate_production_security_prerequisites(app, app_mode="admin")

    assert expected_failure in result.failures


def test_admin_startup_guard_rejects_builtin_root_admin_default(monkeypatch):
    app = _production_app(monkeypatch, app_mode="admin")
    app.config["ROOT_ADMIN_EMAILS"] = TestConfig.ROOT_ADMIN_EMAILS

    with pytest.raises(ProductionStartupSecurityError, match="ROOT_ADMIN_EMAILS"):
        enforce_production_startup_guard(app, app_mode="admin")


def test_admin_production_check_reports_legacy_privileged_email_noncompliance(monkeypatch):
    app = _production_app(monkeypatch, app_mode="admin")
    legacy_email = "legacy.admin@gmail.com"
    with app.app_context():
        legacy = User(
            username="legacy-admin",
            email=legacy_email,
            password_hash="not-used",
            account_type="admin",
            account_status="active",
            full_name="Legacy Admin",
            phone_number="91234567",
            account_number=None,
        )
        compliant = User(
            username="compliant-admin",
            email="compliant.admin@sit.singaporetech.edu.sg",
            password_hash="not-used",
            account_type="admin",
            account_status="active",
            full_name="Compliant Admin",
            phone_number="91234568",
            account_number=None,
        )
        db.session.add_all([legacy, compliant])
        db.session.commit()
        legacy_id = legacy.id

    result = validate_production_security_prerequisites(app, app_mode="admin")
    cli_result = app.test_cli_runner().invoke(args=["production-check"])

    assert result.ready
    assert result.details["privileged_email_noncompliant_accounts"] == 1
    assert cli_result.exit_code == 0
    assert "privileged_email_noncompliant_accounts: 1" in cli_result.output
    assert legacy_email not in cli_result.output
    with app.app_context():
        assert db.session.get(User, legacy_id).email == legacy_email


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
