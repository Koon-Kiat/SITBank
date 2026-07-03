from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.security import production_guard


def test_startup_guard_skips_nonproduction_and_fails_closed_with_sanitized_labels(
    app,
    monkeypatch,
):
    production_guard.enforce_production_startup_guard(app, app_mode="customer")

    app.config["APP_ENV"] = "production"
    monkeypatch.setattr(
        production_guard,
        "validate_production_security_prerequisites",
        lambda _app, *, app_mode: production_guard.ProductionReadinessResult(),
    )
    production_guard.enforce_production_startup_guard(app, app_mode="customer")

    result = production_guard.ProductionReadinessResult(
        failures=["Safe prerequisite label"]
    )
    monkeypatch.setattr(
        production_guard,
        "validate_production_security_prerequisites",
        lambda _app, *, app_mode: result,
    )
    with pytest.raises(
        production_guard.ProductionStartupSecurityError,
        match="Safe prerequisite label",
    ):
        production_guard.enforce_production_startup_guard(app, app_mode="customer")
    production_guard.log_production_readiness_failure(app, result)
    assert result.ready is False


def test_mode_and_route_isolation_collects_admin_and_customer_failures(app, monkeypatch):
    monkeypatch.setattr(
        production_guard,
        "is_privileged_workplace_email",
        lambda email: str(email).startswith("approved"),
    )
    result = production_guard.ProductionReadinessResult()
    app.config.update(
        APP_MODE="customer",
        ADMIN_AUTH_ENABLED=False,
        SESSION_COOKIE_NAME="__Host-sitbank_session",
        SESSION_KEY_PREFIX="customer:",
        AUTH_FAILURE_KEY_PREFIX="customer:",
        RATELIMIT_KEY_PREFIX="customer:",
        ROOT_ADMIN_EMAILS={"unapproved@example.test"},
    )
    production_guard._validate_mode_and_route_isolation(app, "invalid", result)
    assert "Runtime app mode is invalid" in result.failures

    result = production_guard.ProductionReadinessResult()
    production_guard._validate_admin_mode_and_routes(
        app,
        {"auth.login", "admin.dashboard"},
        result,
    )
    for expected in (
        "Admin authentication must be enabled",
        "Admin session cookie name must be isolated",
        "Admin session key prefix must be isolated",
        "Admin auth security-state prefix must be isolated",
        "Admin rate-limit key prefix must be isolated",
        "exactly 5 root administrators",
        "approved admin workplace domains",
        "must not register customer routes",
    ):
        assert any(expected in failure for failure in result.failures)

    result = production_guard.ProductionReadinessResult()
    app.config.update(
        ADMIN_AUTH_ENABLED=True,
        SESSION_COOKIE_NAME="__Host-sitbank_admin_session",
        SESSION_KEY_PREFIX="admin-session:",
    )
    production_guard._validate_customer_mode_and_routes(
        app,
        {"admin.dashboard"},
        result,
    )
    assert len(result.failures) == 4


def test_password_session_and_mfa_policy_error_branches(app, monkeypatch):
    result = production_guard.ProductionReadinessResult()
    monkeypatch.setattr(
        production_guard,
        "_validate_password_length_config",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("bad length")),
    )
    monkeypatch.setattr(
        production_guard,
        "validate_common_password_dictionary",
        lambda: (_ for _ in ()).throw(RuntimeError("missing")),
    )
    monkeypatch.setattr(
        production_guard,
        "validate_password_hash_config",
        lambda: (_ for _ in ()).throw(RuntimeError("bad hash")),
    )
    production_guard._validate_password_policy(app, result)
    assert len(result.failures) == 3

    result = production_guard.ProductionReadinessResult()
    app.config["PASSWORD_MIN_LENGTH"] = 8
    monkeypatch.setattr(
        production_guard,
        "_validate_password_length_config",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(production_guard, "validate_common_password_dictionary", lambda: 10)
    monkeypatch.setattr(production_guard, "validate_password_hash_config", lambda: None)
    production_guard._validate_password_policy(app, result)
    assert result.details["password_min_length"] == 8
    assert result.details["common_password_dictionary_entries"] == 10
    assert len(result.failures) == 2

    result = production_guard.ProductionReadinessResult()
    app.config.update(
        SESSION_TYPE="filesystem",
        SESSION_LOOKUP_HMAC_KEY=b"short",
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_HTTPONLY=False,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="wrong",
    )
    monkeypatch.setattr(
        production_guard,
        "validate_session_hmac_config",
        lambda: (_ for _ in ()).throw(RuntimeError("bad hmac")),
    )
    production_guard._validate_session_policy(app, "customer", result)
    assert len(result.failures) >= 6

    result = production_guard.ProductionReadinessResult()
    app.config.update(
        MFA_KEK_KEYS={},
        MFA_KEK_ACTIVE_ID="missing",
        TOTP_LOGIN_VALID_WINDOW=2,
        TOTP_HIGH_RISK_VALID_WINDOW=1,
        FRESH_MFA_SECONDS="invalid",
    )
    production_guard._validate_mfa_policy(app, result)
    assert len(result.failures) == 4
    assert production_guard._int_config(app, "FRESH_MFA_SECONDS") is None


def test_alert_audit_edge_and_lifetime_validators_report_only_safe_reasons(
    app,
    monkeypatch,
):
    result = production_guard.ProductionReadinessResult()
    monkeypatch.setattr(
        production_guard,
        "validate_security_alert_config",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("secret detail")),
    )
    monkeypatch.setattr(
        production_guard,
        "validate_audit_integrity_config",
        lambda: (_ for _ in ()).throw(RuntimeError("secret detail")),
    )
    production_guard._validate_alert_and_audit_policy(result)
    assert result.failures == [
        "Security alert configuration check failed (RuntimeError)",
        "Audit integrity configuration check failed (RuntimeError)",
    ]
    assert "secret detail" not in " ".join(result.failures)

    result = production_guard.ProductionReadinessResult()
    monkeypatch.setattr(
        production_guard,
        "validate_security_alert_config",
        lambda **_kwargs: {
            "enabled": True,
            "min_severity": "high",
            "dedupe_ttl_seconds": 300,
        },
    )
    monkeypatch.setattr(production_guard, "validate_audit_integrity_config", lambda: 32)
    production_guard._validate_alert_and_audit_policy(result)
    assert result.details["security_alerting"]["enabled"] is True
    assert result.details["audit_hmac_key_length"] == 32

    app.config.update(
        PASSWORD_PBKDF2_ITERATIONS="bad",
        APP_ENV="testing",
        SQLALCHEMY_MIGRATION_DATABASE_URI="configured",
        WTF_CSRF_SECRET_KEY="short",
        TRUSTED_PROXY_COUNT=2,
        WTF_CSRF_ENABLED=False,
        WTF_CSRF_CHECK_DEFAULT=False,
        TALISMAN_FORCE_HTTPS=False,
        RATELIMIT_STORAGE_URI="redis://unsafe",
    )
    monkeypatch.setattr(
        production_guard,
        "validate_cloudflare_access_config",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("bad edge")),
    )
    production_guard._validate_edge_policy(app, result)
    assert len(result.failures) >= 9

    monkeypatch.setattr(
        production_guard,
        "_validate_payee_cooldown_config",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("fixed bound")),
    )
    monkeypatch.setattr(
        production_guard,
        "_validate_session_absolute_lifetime_config",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("fixed bound")),
    )
    production_guard._validate_lifetime_policy(app, result)
    assert any("Payee cooldown" in failure for failure in result.failures)
    assert any("Session absolute lifetime" in failure for failure in result.failures)


def test_runtime_database_privilege_validator_rejects_non_postgres(app):
    result = production_guard.ProductionReadinessResult()
    with app.app_context():
        app.testing = False
        production_guard._validate_runtime_database_privileges(app, result)
    assert result.failures == ["Runtime database must use PostgreSQL"]


def test_failure_helpers_rollback_best_effort(app, monkeypatch):
    result = production_guard.ProductionReadinessResult()
    rollbacks = []
    monkeypatch.setattr(
        production_guard.db.session,
        "rollback",
        lambda: rollbacks.append(True),
    )
    with app.app_context():
        production_guard._database_failure(result, "Database check", ValueError())
    assert result.failures == ["Database check failed (ValueError)"]
    assert rollbacks == [True]

    monkeypatch.setattr(
        production_guard.db.session,
        "rollback",
        lambda: (_ for _ in ()).throw(RuntimeError("rollback unavailable")),
    )
    with app.app_context():
        production_guard._database_failure(result, "Second check", RuntimeError())
    assert result.failures[-1] == "Second check failed (RuntimeError)"


def test_database_and_privileged_email_checks_handle_query_failures(app, monkeypatch):
    result = production_guard.ProductionReadinessResult()
    app.config["APP_MODE"] = "admin"
    production_guard._validate_mode_and_route_isolation(app, "customer", result)
    assert any("APP_MODE does not match" in failure for failure in result.failures)

    with app.app_context():
        monkeypatch.setattr(
            production_guard.db.session,
            "execute",
            lambda _statement: (_ for _ in ()).throw(RuntimeError("db unavailable")),
        )
        production_guard._validate_database_connectivity_and_tables("customer", result)
        assert any("PostgreSQL connectivity" in failure for failure in result.failures)

        calls = 0

        def fail_second(_statement):
            nonlocal calls
            calls += 1
            if calls == 1:
                return SimpleNamespace()
            raise RuntimeError("table unavailable")

        monkeypatch.setattr(production_guard.db.session, "execute", fail_second)
        production_guard._validate_database_connectivity_and_tables("customer", result)
        assert any("users table access" in failure for failure in result.failures)

        monkeypatch.setattr(
            production_guard.db.session,
            "execute",
            lambda _statement: (_ for _ in ()).throw(RuntimeError("report unavailable")),
        )
        production_guard._record_privileged_email_compliance("admin", result)
        assert any("privileged email compliance" in failure for failure in result.failures)


def test_session_mfa_and_postgres_privilege_success_and_failure_edges(app, monkeypatch):
    result = production_guard.ProductionReadinessResult()
    app.config.update(
        SESSION_TYPE="database",
        SESSION_LOOKUP_HMAC_KEY=b"x" * 32,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_NAME="__Host-sitbank_session",
    )
    monkeypatch.setattr(production_guard, "validate_session_hmac_config", lambda: 2)
    production_guard._validate_session_policy(app, "customer", result)
    assert result.details["session_hmac_key_count"] == 2

    app.config.update(
        MFA_KEK_KEYS={"configured": b"x" * 32},
        MFA_KEK_ACTIVE_ID="missing",
        TOTP_LOGIN_VALID_WINDOW=1,
        TOTP_HIGH_RISK_VALID_WINDOW=0,
        FRESH_MFA_SECONDS=300,
    )
    production_guard._validate_mfa_policy(app, result)
    assert any("MFA_KEK_ACTIVE_ID" in failure for failure in result.failures)

    class MappingResult:
        def __init__(self, value):
            self.value = value

        def mappings(self):
            return self

        def one(self):
            return self.value

    fake_db = SimpleNamespace(
        engine=SimpleNamespace(dialect=SimpleNamespace(name="postgresql")),
        session=SimpleNamespace(
            execute=lambda _statement: MappingResult(
                {
                    "database_create": True,
                    "schema_create": False,
                    "owns_schema_object": False,
                    "audit_update": True,
                    "audit_delete": False,
                    "audit_truncate": False,
                }
            )
        ),
    )
    monkeypatch.setattr(production_guard, "db", fake_db)
    app.testing = False
    production_guard._validate_runtime_database_privileges(app, result)
    assert any("mutate schema objects" in failure for failure in result.failures)
    assert any("must not mutate security audit" in failure for failure in result.failures)

    fake_db.session.execute = lambda _statement: (_ for _ in ()).throw(
        RuntimeError("privilege query failed")
    )
    production_guard._validate_runtime_database_privileges(app, result)
    assert any("Runtime database privilege check" in failure for failure in result.failures)
