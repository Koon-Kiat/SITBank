from __future__ import annotations

import importlib
import logging
from datetime import timedelta

import fakeredis

from app.extensions import db
from app.models import SecurityAuditEvent
from app.security.audit import verify_audit_hash_chain
from conftest import TestConfig


def _install_fake_redis(monkeypatch):
    import app as app_module

    clients = {}

    def fake_from_url(url, decode_responses=False, **_options):
        key = (url, decode_responses)
        if key not in clients:
            clients[key] = fakeredis.FakeRedis(decode_responses=decode_responses)
        return clients[key]

    monkeypatch.setattr(
        app_module,
        "Redis",
        type("FakeRedisFactory", (), {"from_url": staticmethod(fake_from_url)}),
    )


def _rules(flask_app):
    return {
        rule.rule: rule.endpoint
        for rule in flask_app.url_map.iter_rules()
        if rule.endpoint != "static"
    }


def test_customer_and_admin_apps_have_isolated_route_surfaces(monkeypatch):
    _install_fake_redis(monkeypatch)
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
    assert admin_rules["/login"] == "admin.login_disabled"


def test_entrypoints_select_explicit_factory_modes(monkeypatch):
    _install_fake_redis(monkeypatch)

    wsgi = importlib.reload(importlib.import_module("wsgi"))
    admin_wsgi = importlib.reload(importlib.import_module("admin_wsgi"))

    assert wsgi.app.config["APP_MODE"] == "customer"
    assert admin_wsgi.app.config["APP_MODE"] == "admin"


def test_app_factory_reenables_shared_application_logger(monkeypatch):
    _install_fake_redis(monkeypatch)
    from app import create_app

    logger = logging.getLogger("app")
    logger.disabled = True
    try:
        flask_app = create_app(TestConfig, app_mode="customer")
        assert flask_app.logger.disabled is False
    finally:
        logger.disabled = False


def test_admin_runtime_config_is_separate_and_stricter(monkeypatch):
    _install_fake_redis(monkeypatch)
    from app import create_app

    customer_app = create_app(TestConfig, app_mode="customer")
    admin_app = create_app(TestConfig, app_mode="admin")

    assert customer_app.config["SESSION_COOKIE_NAME"] == "__Host-sitbank_session"
    assert admin_app.config["SESSION_COOKIE_NAME"] == "__Host-sitbank_admin_session"
    assert customer_app.config["SECRET_ENV_NAMES"]["SECRET_KEY"] == "SECRET_KEY"
    assert admin_app.config["SECRET_ENV_NAMES"]["SECRET_KEY"] == "ADMIN_SECRET_KEY"
    assert customer_app.config["REDIS_URL"] != admin_app.config["REDIS_URL"]
    assert customer_app.config["SESSION_KEY_PREFIX"] != admin_app.config["SESSION_KEY_PREFIX"]
    assert customer_app.config["RATELIMIT_KEY_PREFIX"] != admin_app.config["RATELIMIT_KEY_PREFIX"]
    assert customer_app.config["AUTH_FAILURE_KEY_PREFIX"] != admin_app.config["AUTH_FAILURE_KEY_PREFIX"]
    assert customer_app.config["SQLALCHEMY_DATABASE_URI"] != admin_app.config["SQLALCHEMY_DATABASE_URI"]
    assert admin_app.config["SQLALCHEMY_MIGRATION_DATABASE_URI"] is None
    assert admin_app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(minutes=5)
    assert admin_app.config["PERMANENT_SESSION_LIFETIME"] < customer_app.config["PERMANENT_SESSION_LIFETIME"]


def test_admin_auth_fails_closed_without_creating_sessions(monkeypatch):
    _install_fake_redis(monkeypatch)
    from app import create_app

    admin_app = create_app(TestConfig, app_mode="admin")
    with admin_app.app_context():
        db.create_all()
        client = admin_app.test_client()

        password_only = client.post("/login", json={"password": "not-used"})
        username_only = client.post("/login", json={"username": "root"})
        register = client.get("/register")
        customer_cookie = client.get("/", headers={"Cookie": "__Host-sitbank_session=customer"}).status_code

        assert password_only.status_code == 403
        assert username_only.status_code == 403
        assert register.status_code == 404
        assert customer_cookie == 403
        assert admin_app.extensions["redis_session"].keys(f"{admin_app.config['SESSION_KEY_PREFIX']}*") == []
        for response in (password_only, username_only, register):
            assert not any(
                cookie.startswith(f"{admin_app.config['SESSION_COOKIE_NAME']}=")
                and not cookie.startswith(f"{admin_app.config['SESSION_COOKIE_NAME']}=;")
                for cookie in response.headers.getlist("Set-Cookie")
            )

        db.session.remove()
        db.drop_all()


def test_disabled_admin_login_is_audited_and_redacted(monkeypatch):
    _install_fake_redis(monkeypatch)
    from app import create_app

    admin_app = create_app(TestConfig, app_mode="admin")
    with admin_app.app_context():
        db.create_all()
        response = admin_app.test_client().post(
            "/login",
            json={
                "username": "admin",
                "password": "plaintext-password",
                "token": "bearer sensitive",
            },
        )

        assert response.status_code == 403
        event = db.session.query(SecurityAuditEvent).one()
        assert event.event_type == "admin_login_disabled"
        assert event.outcome == "fail_closed"
        assert event.event_metadata["app_mode"] == "admin"
        assert event.event_metadata["password"] == "[redacted]"
        assert event.event_metadata["token"] == "[redacted]"
        assert event.event_metadata["phase"] == "phase_1a_fail_closed"
        assert verify_audit_hash_chain()["valid"] is True

        db.session.remove()
        db.drop_all()
