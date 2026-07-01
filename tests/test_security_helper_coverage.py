from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.auth import decorators, webauthn_services
from app.auth.services import AuthError
from app.security import email, turnstile


def test_security_email_backends_and_outbox_boundary(app, monkeypatch):
    with app.app_context():
        app.config["PASSWORD_RESET_EMAIL_BACKEND"] = "console"
        email.send_security_email("user@example.test", "Subject", "Fake body")
        assert email.password_reset_outbox() == [
            {
                "to": "user@example.test",
                "subject": "Subject",
                "body": "Fake body",
            }
        ]

        app.extensions["password_reset_outbox"] = "unsafe"
        assert email.password_reset_outbox() == []
        app.config["APP_ENV"] = "production"
        with pytest.raises(RuntimeError, match="not allowed in production"):
            email.send_security_email("user@example.test", "Subject", "Fake body")

        app.config["APP_ENV"] = "testing"
        app.config["PASSWORD_RESET_EMAIL_BACKEND"] = "unsupported"
        with pytest.raises(RuntimeError, match="Unsupported"):
            email.send_security_email("user@example.test", "Subject", "Fake body")

    events = []

    class SMTP:
        def __init__(self, host, port, timeout):
            events.append(("connect", host, port, timeout))

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def starttls(self, *, context):
            events.append(("tls", context.check_hostname, context.verify_mode))

        def login(self, username, password):
            events.append(("login", username, password))

        def send_message(self, message):
            events.append(("send", message["To"], message["Subject"], message.get_content().strip()))

    monkeypatch.setattr(email.smtplib, "SMTP", SMTP)
    with app.app_context():
        app.config.update(
            PASSWORD_RESET_EMAIL_BACKEND="smtp",
            PASSWORD_RESET_EMAIL_FROM="security@example.test",
            SMTP_HOST="smtp.example.test",
            SMTP_PORT=2525,
            SMTP_USE_TLS=True,
            SMTP_USERNAME="fake-user",
            SMTP_PASSWORD="fake-password",
        )
        email.send_security_email("user@example.test", "Subject", "Fake body")

    assert events == [
        ("connect", "smtp.example.test", 2525, 10),
        ("tls", True, email.ssl.CERT_REQUIRED),
        ("login", "fake-user", "fake-password"),
        ("send", "user@example.test", "Subject", "Fake body"),
    ]


def test_smtp_delivery_fails_closed_without_tls_in_production(app):
    with app.app_context():
        app.config.update(
            APP_ENV="production",
            DEPLOYMENT_TARGET="production",
            PASSWORD_RESET_EMAIL_BACKEND="smtp",
            PASSWORD_RESET_EMAIL_FROM="security@example.test",
            SMTP_HOST="smtp.example.test",
            SMTP_PORT=2525,
            SMTP_USE_TLS=False,
            SMTP_USERNAME="fake-user",
            SMTP_PASSWORD="fake-password",
        )

        with pytest.raises(RuntimeError, match="SMTP_USE_TLS=true is required"):
            email.send_security_email("user@example.test", "Subject", "Fake body")


def test_turnstile_disabled_missing_invalid_and_success_paths(app, monkeypatch):
    with app.test_request_context("/", environ_base={"REMOTE_ADDR": "192.0.2.10"}):
        app.config["TURNSTILE_ENABLED"] = False
        turnstile.verify_turnstile_token(None)

        app.config["TURNSTILE_ENABLED"] = True
        app.config["TURNSTILE_SECRET_KEY"] = ""
        with pytest.raises(turnstile.TurnstileError):
            turnstile.verify_turnstile_token("token")

        app.config["TURNSTILE_SECRET_KEY"] = "clearly-fake-secret"
        for url in (
            "http://example.test/verify",
            "https://user:pass@example.test/verify",
            "https://example.test/verify?query=bad",
        ):
            app.config["TURNSTILE_VERIFY_URL"] = url
            with pytest.raises(turnstile.TurnstileError):
                turnstile.verify_turnstile_token("token")

        app.config["TURNSTILE_VERIFY_URL"] = "https://example.test:8443/verify"
        requests = []

        class Connection:
            def __init__(self, host, *, port, timeout):
                assert (host, port, timeout) == ("example.test", 8443, 5)

            def request(self, method, target, body, headers):
                requests.append((method, target, body, headers))

            def getresponse(self):
                return SimpleNamespace(read=lambda _limit: b'{"success":true}')

            def close(self):
                requests.append(("closed",))

        monkeypatch.setattr(turnstile.http.client, "HTTPSConnection", Connection)
        turnstile.verify_turnstile_token("fake-token")
        assert requests[-1] == ("closed",)
        assert b"remoteip=192.0.2.10" in requests[0][2]

        class FailedConnection(Connection):
            def getresponse(self):
                return SimpleNamespace(read=lambda _limit: b'{"success":false}')

        monkeypatch.setattr(turnstile.http.client, "HTTPSConnection", FailedConnection)
        with pytest.raises(turnstile.TurnstileError):
            turnstile.verify_turnstile_token("fake-token")


def test_auth_decorators_enforce_each_boundary(app, monkeypatch):
    view = lambda: "allowed"
    user = SimpleNamespace(is_frozen=False, security_locked_at=None)

    with app.test_request_context("/"):
        assert decorators.login_required(view)()[1] == 401
        from flask import g, session

        session["user_id"] = 1
        g.current_user = user
        app.config["APP_MODE"] = "customer"
        monkeypatch.setattr(decorators, "is_customer_user", lambda _user: False)
        assert decorators.login_required(view)()[1] == 403
        monkeypatch.setattr(decorators, "is_customer_user", lambda _user: True)
        assert decorators.login_required(view)() == "allowed"

        assert decorators.mfa_verified_required(view)()[1] == 403
        session["mfa_verified_at"] = 1
        assert decorators.mfa_verified_required(view)() == "allowed"

        session["fresh_mfa_verified_at"] = 100
        app.config["FRESH_MFA_SECONDS"] = 50
        monkeypatch.setattr(decorators, "time", lambda: 200)
        assert decorators.fresh_mfa_required(view)()[1] == 403
        monkeypatch.setattr(decorators, "time", lambda: 120)
        assert decorators.fresh_mfa_required(view)() == "allowed"

        g.current_user = SimpleNamespace(is_frozen=True, security_locked_at=None)
        assert decorators.not_frozen_required(view)()[1] == 403
        g.current_user = user
        assert decorators.not_frozen_required(view)() == "allowed"


def test_webauthn_legacy_helpers_and_disabled_operations(app, monkeypatch):
    user = SimpleNamespace(id=None)
    assert webauthn_services.webauthn_credential_count(user) == 0
    assert webauthn_services.has_webauthn_credentials(user) is False
    assert webauthn_services.has_full_webauthn_access(user) is False
    assert webauthn_services.webauthn_required_for_user(user) is False
    assert webauthn_services.current_webauthn_credential_reference() is None
    assert webauthn_services.list_credentials_for_user(user) == []
    assert webauthn_services._step_up_token_cache_key("fake") == (
        webauthn_services.STEP_UP_TOKEN_PREFIX + "fake"
    )
    encoded = webauthn_services.bytes_to_base64url(b"credential")
    assert webauthn_services.base64url_to_bytes(encoded) == b"credential"
    with pytest.raises(AuthError, match="Invalid credential reference"):
        webauthn_services.base64url_to_bytes("\N{SNOWMAN}")

    audits = []
    monkeypatch.setattr(
        webauthn_services,
        "audit_event",
        lambda *args, **kwargs: audits.append((args, kwargs)),
    )
    calls = [
        lambda: webauthn_services.begin_registration_options(user, "label"),
        lambda: webauthn_services.verify_registration(user, {}),
        webauthn_services.begin_authentication_options,
        lambda: webauthn_services.verify_authentication({}),
        lambda: webauthn_services.begin_step_up_options(user, "transfer"),
        lambda: webauthn_services.verify_step_up(user, "transfer", {}),
        lambda: webauthn_services.begin_password_reset_options(user, "transaction"),
        lambda: webauthn_services.verify_password_reset_assertion(user, "transaction", {}),
        lambda: webauthn_services.consume_step_up_token(user, "transfer", None),
        lambda: webauthn_services.revoke_credential(
            user,
            "credential",
            stepup_token="fake",
            stepup_already_consumed=True,
        ),
        lambda: webauthn_services.stage_transaction_security_key_context(user, {}),
        lambda: webauthn_services.begin_transaction_security_key_challenge(user, "reference"),
        lambda: webauthn_services.verify_transaction_security_key_challenge(user, {}),
    ]
    for call in calls:
        with pytest.raises(AuthError) as exc:
            call()
        assert exc.value.status_code == 410
    assert len(audits) == len(calls)

    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    item = SimpleNamespace(
        id=4,
        credential_id=b"credential",
        label="Legacy",
        aaguid="fake-aaguid",
        attestation_format="packed",
        credential_kind="passkey",
        created_at=now,
        last_used_at=None,
    )
    public = webauthn_services._public_legacy_credential(item)
    assert public["active"] is False
    assert public["decommissioned"] is True
    assert public["created_at"] == "2026-01-02T00:00:00+00:00"
    assert public["last_used_at"] is None
