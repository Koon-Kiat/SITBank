from __future__ import annotations

import importlib
import logging
from datetime import timedelta

from app.extensions import db
from app.models import SecurityAuditEvent, ServerSideSession, User
from app.security.audit import verify_audit_hash_chain
from app.security.passwords import hash_password
from conftest import TestConfig


def _rules(flask_app):
    return {
        rule.rule: rule.endpoint
        for rule in flask_app.url_map.iter_rules()
        if rule.endpoint != "static"
    }


def test_customer_and_admin_apps_have_isolated_route_surfaces(monkeypatch):
    from app import create_app

    customer_app = create_app(TestConfig, app_mode="customer")
    admin_app = create_app(TestConfig, app_mode="admin")

    customer_rules = _rules(customer_app)
    admin_rules = _rules(admin_app)

    assert customer_app.config["APP_MODE"] == "customer"
    assert admin_app.config["APP_MODE"] == "admin"
    assert not any(endpoint.startswith("admin.") for endpoint in customer_rules.values())
    assert not any(endpoint.startswith(("auth.", "web.", "banking.", "main.")) for endpoint in admin_rules.values())
    assert "/health/live" in customer_rules
    assert "/health/ready" in customer_rules
    assert "banking" in customer_app.blueprints
    assert "/dashboard" in customer_rules
    assert "/dashboard" not in admin_rules
    assert not any(rule.startswith("/banking") for rule in admin_rules)
    assert admin_rules["/login"] == "admin.login"
    assert admin_rules["/mfa/verify"] == "admin.mfa_verify"
    assert "/invites" in admin_rules
    assert "admin.invite_create" in set(admin_rules.values())


def test_entrypoints_select_explicit_factory_modes(monkeypatch):
    wsgi = importlib.reload(importlib.import_module("wsgi"))
    admin_wsgi = importlib.reload(importlib.import_module("admin_wsgi"))

    assert wsgi.app.config["APP_MODE"] == "customer"
    assert admin_wsgi.app.config["APP_MODE"] == "admin"


def test_app_factory_reenables_shared_application_logger(monkeypatch):
    from app import create_app

    logger = logging.getLogger("app")
    logger.disabled = True
    try:
        flask_app = create_app(TestConfig, app_mode="customer")
        assert flask_app.logger.disabled is False
    finally:
        logger.disabled = False


def test_admin_health_reports_liveness_and_dependency_readiness(monkeypatch):
    from app import create_app

    admin_app = create_app(TestConfig, app_mode="admin")
    client = admin_app.test_client()

    live = client.get("/health/live")
    ready = client.get("/health/ready")

    assert live.status_code == 200
    assert live.get_json() == {"status": "ok", "app_mode": "admin"}
    assert ready.status_code == 200
    assert ready.get_json() == {"status": "ready", "app_mode": "admin"}


def test_admin_runtime_config_is_separate_and_stricter(monkeypatch):
    from app import create_app

    customer_app = create_app(TestConfig, app_mode="customer")
    admin_app = create_app(TestConfig, app_mode="admin")

    assert customer_app.config["SESSION_COOKIE_NAME"] == "__Host-sitbank_session"
    assert admin_app.config["SESSION_COOKIE_NAME"] == "__Host-sitbank_admin_session"
    assert customer_app.config["SECRET_ENV_NAMES"]["SECRET_KEY"] == "SECRET_KEY"
    assert admin_app.config["SECRET_ENV_NAMES"]["SECRET_KEY"] == "ADMIN_SECRET_KEY"
    assert customer_app.config["SESSION_LOOKUP_HMAC_KEY"] != admin_app.config["SESSION_LOOKUP_HMAC_KEY"]
    assert customer_app.config["SESSION_KEY_PREFIX"] != admin_app.config["SESSION_KEY_PREFIX"]
    assert customer_app.config["RATELIMIT_KEY_PREFIX"] != admin_app.config["RATELIMIT_KEY_PREFIX"]
    assert customer_app.config["AUTH_FAILURE_KEY_PREFIX"] != admin_app.config["AUTH_FAILURE_KEY_PREFIX"]
    assert customer_app.config["SQLALCHEMY_DATABASE_URI"] != admin_app.config["SQLALCHEMY_DATABASE_URI"]
    assert admin_app.config["SQLALCHEMY_MIGRATION_DATABASE_URI"] is None
    assert admin_app.config["ADMIN_AUTH_ENABLED"] is True
    assert admin_app.config["ADMIN_WEBAUTHN_PHASE"] == "disabled"
    assert admin_app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(minutes=5)
    assert admin_app.config["PERMANENT_SESSION_LIFETIME"] < customer_app.config["PERMANENT_SESSION_LIFETIME"]


def test_admin_auth_rejects_bad_requests_without_creating_privileged_sessions(monkeypatch):
    from app import create_app

    admin_app = create_app(TestConfig, app_mode="admin")
    with admin_app.app_context():
        db.create_all()
        client = admin_app.test_client()

        password_only = client.post("/login", json={"password": "not-used"})
        username_only = client.post("/login", json={"username": "root"})
        register = client.get("/register")
        customer_cookie = client.get("/", headers={"Cookie": "__Host-sitbank_session=customer"}).status_code

        assert password_only.status_code == 400
        assert username_only.status_code == 400
        assert register.status_code == 404
        assert customer_cookie == 401
        assert db.session.query(ServerSideSession).count() == 0
        for response in (password_only, username_only, register):
            assert not any(
                cookie.startswith(f"{admin_app.config['SESSION_COOKIE_NAME']}=")
                and not cookie.startswith(f"{admin_app.config['SESSION_COOKIE_NAME']}=;")
                for cookie in response.headers.getlist("Set-Cookie")
            )

        db.session.remove()
        db.drop_all()


def test_admin_login_failures_are_audited_and_redacted(monkeypatch):
    from app import create_app

    admin_app = create_app(TestConfig, app_mode="admin")
    with admin_app.app_context():
        db.create_all()
        db.session.add(
            User(
                username="root-admin",
                email="root1@sit.singaporetech.edu.sg",
                password_hash=hash_password("correct horse battery staple"),
                account_type="root_admin",
                account_status="active",
                full_name="Root Admin",
                phone_number="91234567",
                account_number=None,
                mfa_enabled=False,
            )
        )
        db.session.commit()
        response = admin_app.test_client().post(
            "/login",
            json={
                "workplace_email": "root1@sit.singaporetech.edu.sg",
                "password": "plaintext-password",
            },
        )

        assert response.status_code == 401
        event = db.session.query(SecurityAuditEvent).one()
        assert event.event_type == "admin_login"
        assert event.outcome == "failure"
        assert event.event_metadata["principal_ref"]
        assert "plaintext-password" not in str(event.event_metadata)
        assert verify_audit_hash_chain()["valid"] is True

        db.session.remove()
        db.drop_all()


def test_privileged_password_failures_lock_more_strictly(monkeypatch):
    from app import create_app

    admin_app = create_app(TestConfig, app_mode="admin")
    with admin_app.app_context():
        db.create_all()
        user = User(
            username="security-admin",
            email="security.admin@sit.singaporetech.edu.sg",
            password_hash=hash_password("correct horse battery staple"),
            account_type="admin",
            account_status="active",
            full_name="Security Admin",
            phone_number="91234567",
            account_number=None,
            mfa_enabled=True,
        )
        db.session.add(user)
        db.session.commit()
        client = admin_app.test_client()

        responses = [
            client.post(
                "/login",
                json={
                    "workplace_email": user.email,
                    "password": f"wrong-password-{index}",
                },
            )
            for index in range(2)
        ]
        db.session.refresh(user)

        assert [response.status_code for response in responses] == [401, 401]
        assert all(
            response.get_json()
            == {"error": "Invalid workplace email, password, or authentication code"}
            for response in responses
        )
        assert user.security_locked_at is not None
        assert user.security_lock_reason == "password_failed_attempts"

        db.session.remove()
        db.drop_all()


def test_admin_logout_requires_valid_csrf_token(monkeypatch):
    from app import create_app

    admin_app = create_app(TestConfig, app_mode="admin")
    admin_app.config["WTF_CSRF_ENABLED"] = True
    with admin_app.app_context():
        db.create_all()
        client = admin_app.test_client()
        token = client.get("/csrf-token").get_json()["csrf_token"]

        missing = client.post("/logout", json={})
        invalid = client.post(
            "/logout",
            json={},
            headers={"X-CSRFToken": "invalid"},
        )
        valid = client.post(
            "/logout",
            json={},
            headers={"X-CSRFToken": token},
        )

        assert missing.status_code == 400
        assert invalid.status_code == 400
        assert valid.status_code == 200
        assert valid.get_json() == {"message": "Logged out"}

        db.session.remove()
        db.drop_all()
