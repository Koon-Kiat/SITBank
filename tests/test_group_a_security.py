from __future__ import annotations

import re
import json
import secrets
import time
from datetime import datetime, timedelta, timezone

import pytest
import pyotp
from flask import current_app
from pathlib import Path
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.orm import Session
from webauthn.helpers.structs import CredentialDeviceType

from app.extensions import db
from app.models import RecoveryCode, SecurityAuditEvent, User, WebAuthnCredential
from app.security.passwords import (
    PASSWORD_MAX_CHARS,
    PASSWORD_MIN_LENGTH,
    PASSWORD_RECOMMENDED_MIN_LENGTH,
    PBKDF2_PREFIX,
    hash_password,
    verify_password,
)


def register(client, username="alice01", email="alice@example.com", password="correct horse battery staple"):
    return client.post(
        "/register",
        data={"username": username, "email": email, "password": password, "confirm_password": password},
        follow_redirects=False,
    )


def login(client, identifier="alice01", password="correct horse battery staple"):
    return client.post(
        "/login",
        data={"identifier": identifier, "password": password},
        follow_redirects=False,
    )


def password_inputs(response):
    return re.findall(rb"<input(?=[^>]*type=\"password\")[^>]*>", response.data)


def log_payloads(caplog, message):
    payloads = []
    for record in caplog.records:
        try:
            payload = json.loads(record.getMessage())
        except json.JSONDecodeError:
            continue
        if payload.get("message") == message:
            payloads.append(payload)
    return payloads


def api_login_from_ip(client, remote_addr, identifier="alice01", password="correct horse battery staple"):
    return client.post(
        "/auth/login",
        json={"identifier": identifier, "password": password},
        environ_overrides={"REMOTE_ADDR": remote_addr},
    )


def mark_recent_mfa(client, user):
    user.mfa_enabled = True
    db.session.commit()
    now = int(time.time())
    with client.session_transaction() as sess:
        sess["auth_context"] = "password+mfa_bootstrap"
        sess["mfa_verified_at"] = now
        sess["fresh_mfa_verified_at"] = now
        sess.pop("risk_fingerprint", None)


def decrypt_test_mfa_secret(user):
    from app.security.crypto import decrypt_mfa_secret

    return decrypt_mfa_secret(user.mfa_secret_nonce, user.mfa_secret_ciphertext, user.id)


def enable_mfa_for_user(username="alice01"):
    from app.security.crypto import encrypt_mfa_secret

    user = db.session.execute(db.select(User).where(User.username == username)).scalar_one()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    db.session.commit()
    return user, secret


def add_security_keys_for_user(user, count=2):
    for index in range(count):
        credential_id = f"credential-{user.id}-{index}".encode("utf-8")
        db.session.add(
            WebAuthnCredential(
                user_id=user.id,
                credential_id=credential_id,
                credential_public_key=b"public-key",
                sign_count=10 + index,
                label=f"Security Key {index + 1}",
                aaguid="11111111-1111-1111-1111-111111111111",
                attestation_format="packed",
                transports=["usb"],
                credential_device_type=CredentialDeviceType.SINGLE_DEVICE.value,
                credential_backed_up=False,
            )
        )
    db.session.commit()


def mint_stepup_token(client, user, action):
    from app.auth.webauthn_services import _step_up_token_cache_key

    with client.session_transaction() as sess:
        session_id = sess.sid
    token = secrets.token_urlsafe(32)
    current_app.extensions["redis"].set(
        _step_up_token_cache_key(token),
        json.dumps(
            {
                "user_id": user.id,
                "session_id": session_id,
                "action": action,
                "credential_id": f"credential-{user.id}-0",
                "issued_at": int(time.time()),
            }
        ),
        ex=current_app.config["WEBAUTHN_STEP_UP_TTL_SECONDS"],
    )
    return token


def complete_mfa_login(client, secret):
    login_response = login(client)
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).now()},
    )
    return login_response, mfa_response


def test_registration_rejects_common_password(client):
    response = register(client, password="password")

    assert response.status_code == 400
    assert db.session.query(User).count() == 0


def test_registration_uses_local_fallback_when_live_password_check_is_unavailable(client, monkeypatch):
    from app.security.passwords import HIBP_FALLBACK_WARNING, LivePasswordCheckUnavailable

    def unavailable(_password):
        raise LivePasswordCheckUnavailable("offline")

    monkeypatch.setattr("app.security.passwords._is_password_pwned_by_hibp", unavailable)

    response = client.post(
        "/register",
        data={
            "username": "alice01",
            "email": "alice@example.com",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert db.session.query(User).count() == 1
    assert HIBP_FALLBACK_WARNING.encode("utf-8") in response.data


def test_registration_rejects_live_breached_password(client, monkeypatch):
    monkeypatch.setattr("app.security.passwords._is_password_pwned_by_hibp", lambda _password: True)

    response = register(client)

    assert response.status_code == 400
    assert db.session.query(User).count() == 0
    assert b"Password is too common or has appeared in breach lists" in response.data


def test_registration_hashes_password_with_pbkdf2(client):
    response = register(client)

    assert response.status_code == 302
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert not user.password_hash.endswith("correct horse battery staple")
    assert user.password_hash.startswith(f"{PBKDF2_PREFIX}$v1$i=600000$")


def test_short_password_registration_retry_can_login(client):
    rejected = register(client, username="retry01", email="retry@example.com", password="short")
    created = register(client, username="retry01", email="retry@example.com")
    login_response = login(client, identifier="retry01")
    dashboard_response = client.get("/dashboard")

    assert rejected.status_code == 400
    assert created.status_code == 302
    assert created.headers["Location"].endswith("/login")
    assert login_response.status_code == 302
    assert login_response.headers["Location"].endswith("/mfa/setup")
    assert dashboard_response.status_code == 302
    assert dashboard_response.headers["Location"].endswith("/mfa/setup")


def test_long_unicode_password_can_register_login_and_change(client, monkeypatch):
    long_password = "correct horse battery staple " + ("安全な合言葉" * 12)
    new_password = long_password + " updated"

    response = register(client, password=long_password)
    login_response = login(client, password=long_password)
    user, secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    stepup_token = mint_stepup_token(client, user, "password_change")
    old_hash = user.password_hash
    change_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: change_time)

    change_response = client.post(
        "/password/change",
        data={
            "current_password": long_password,
            "new_password": new_password,
            "confirm_new_password": new_password,
            "stepup_token": stepup_token,
        },
    )
    db.session.refresh(user)

    assert response.status_code == 302
    assert login_response.status_code == 302
    assert change_response.status_code == 302
    assert user.password_hash != old_hash
    assert verify_password(new_password, user.password_hash)


def test_password_templates_do_not_truncate_and_show_max_length_guidance(client):
    register_response = client.get("/register")
    login_response = client.get("/login")
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    change_response = client.get("/password/change")

    assert register_response.status_code == 200
    assert login_response.status_code == 200
    assert change_response.status_code == 200
    assert len(password_inputs(register_response)) == 2
    assert len(password_inputs(login_response)) == 1
    assert len(password_inputs(change_response)) == 3
    assert all(b"maxlength" not in field for field in password_inputs(register_response))
    assert all(b"maxlength" not in field for field in password_inputs(login_response))
    assert all(b"maxlength" not in field for field in password_inputs(change_response))
    expected_guidance = (
        f"Use {PASSWORD_MIN_LENGTH} to {PASSWORD_MAX_CHARS} characters. "
        f"{PASSWORD_RECOMMENDED_MIN_LENGTH} or more is recommended."
    ).encode("utf-8")
    assert expected_guidance in register_response.data
    assert b"Maximum password length is 256 characters." in login_response.data
    assert expected_guidance in change_response.data
    assert b"Maximum password length is 256 characters." in change_response.data


def test_password_at_minimum_length_can_register_and_login(client):
    password = "Abcdef12"

    response = register(client, password=password)
    login_response = login(client, password=password)

    assert len(password) == PASSWORD_MIN_LENGTH
    assert response.status_code == 302
    assert login_response.status_code == 302
    assert db.session.query(User).count() == 1


def test_password_at_configured_max_length_can_register_and_login(client):
    password = "A" * PASSWORD_MAX_CHARS

    response = register(client, password=password)
    login_response = login(client, password=password)

    assert response.status_code == 302
    assert login_response.status_code == 302
    assert db.session.query(User).count() == 1


def test_oversized_registration_password_rejected_before_policy_processing(client, monkeypatch):
    def fail_policy(_password):
        pytest.fail("oversized password reached password policy processing")

    monkeypatch.setattr("app.auth.services.validate_password_policy", fail_policy)

    response = register(client, password="A" * 300)

    assert response.status_code == 400
    assert response.status_code != 500
    assert b"longer than 256 characters" in response.data
    assert db.session.query(User).count() == 0


def test_oversized_api_registration_password_rejected_cleanly(client, monkeypatch):
    def fail_policy(_password):
        pytest.fail("oversized password reached password policy processing")

    monkeypatch.setattr("app.auth.services.validate_password_policy", fail_policy)
    password = "A" * 300

    response = client.post(
        "/auth/register",
        json={
            "username": "oversized01",
            "email": "oversized@example.com",
            "password": password,
            "confirm_password": password,
        },
    )

    assert response.status_code == 400
    assert response.status_code != 500
    assert response.get_json() == {"error": "Invalid request"}
    assert db.session.query(User).count() == 0


def test_oversized_login_password_uses_generic_failure_without_hashing(app, client, monkeypatch):
    from app.auth.services import AuthError, authenticate_primary

    register(client)

    def fail_verify(_password, _password_hash):
        pytest.fail("oversized login password reached password hash verification")

    monkeypatch.setattr("app.auth.services.verify_password", fail_verify)

    with app.test_request_context(
        "/auth/login",
        method="POST",
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    ):
        with pytest.raises(AuthError) as exc_info:
            authenticate_primary("alice01", "A" * 300)

    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert exc_info.value.message == "Invalid username or password"
    assert exc_info.value.status_code == 401
    assert user.is_frozen is False
    assert user.security_locked_at is None


def test_oversized_web_login_password_fails_generically(client):
    register(client)

    response = login(client, password="A" * 300)

    assert response.status_code == 401
    assert response.status_code != 500
    assert b"Invalid username or password" in response.data
    assert b"longer than 256 characters" not in response.data


def test_oversized_api_login_password_fails_generically(client):
    register(client)

    response = client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "A" * 300},
    )

    assert response.status_code == 401
    assert response.status_code != 500
    assert response.get_json() == {"error": "Invalid username or password"}


def test_registration_requires_matching_confirm_password(client):
    response = client.post(
        "/register",
        data={
            "username": "alice01",
            "email": "alice@example.com",
            "password": "correct horse battery staple",
            "confirm_password": "different horse battery staple",
        },
    )

    assert response.status_code == 400
    assert db.session.query(User).count() == 0


def test_login_errors_are_generic_for_unknown_and_wrong_password(client):
    register(client)

    wrong_password = client.post(
        "/login",
        data={"identifier": "alice01", "password": "wrong-password"},
    )
    unknown_user = client.post(
        "/login",
        data={"identifier": "missing-user", "password": "wrong-password"},
    )

    assert wrong_password.status_code == 401
    assert unknown_user.status_code == 401
    assert b"Invalid username or password" in wrong_password.data
    assert b"Invalid username or password" in unknown_user.data


def test_failed_login_audit_includes_ip_timestamp_and_principal_ref(client, caplog):
    from app.security.audit import principal_reference

    register(client)
    caplog.set_level("INFO", logger=current_app.logger.name)

    response = client.post(
        "/auth/login",
        json={"identifier": "Alice@Example.com", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.10"},
    )

    event = (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="login", outcome="failure")
        .order_by(SecurityAuditEvent.id.desc())
        .one()
    )
    logs = "\n".join(record.getMessage() for record in caplog.records)
    payload = log_payloads(caplog, "security_audit_event")[-1]

    assert response.status_code == 401
    assert event.ip_address == "203.0.113.10"
    assert event.created_at is not None
    assert event.event_metadata["principal_ref"] == principal_reference("Alice@Example.com")
    assert len(event.event_metadata["principal_ref"]) == 32
    assert "Alice@Example.com" not in json.dumps(event.event_metadata)
    assert "Alice@Example.com" not in logs
    assert "wrong-password" not in logs
    assert payload["event_type"] == "login"
    assert payload["outcome"] == "failure"
    assert payload["ip_address"] == "203.0.113.10"
    assert payload["created_at"].endswith("Z")
    assert payload["logged_at"].endswith("Z")
    assert payload["metadata"]["principal_ref"] == event.event_metadata["principal_ref"]


def test_mfa_pending_api_response_does_not_leak_user_id(client):
    register(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    enable_mfa_for_user()

    response = client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "correct horse battery staple"},
    )
    payload = response.get_json()

    assert response.status_code == 200
    assert payload == {"message": "MFA verification required", "mfa_required": True}
    assert "user_id" not in payload


def test_login_backoff_starts_after_three_failures(client):
    register(client)

    failures = [
        client.post(
            "/auth/login",
            json={"identifier": "alice01", "password": "wrong-password"},
        )
        for _attempt in range(3)
    ]
    blocked = client.post("/auth/login", json={"identifier": "alice01", "password": "wrong-password"})

    assert [response.status_code for response in failures] == [401, 401, 401]
    assert blocked.status_code == 429
    assert blocked.get_json()["error"] == "Too many attempts. Please try again later."
    assert blocked.headers["X-Auth-Retry-After"] == "1"


def test_login_rate_limits_include_per_minute_and_daily_limits(client):
    auth_routes = Path("app/auth/routes.py").read_text(encoding="utf-8")
    web_routes = Path("app/web/routes.py").read_text(encoding="utf-8")

    for route_source in (auth_routes, web_routes):
        assert '@limiter.limit("50 per day", key_func=get_remote_address)' in route_source
        assert '@limiter.limit("50 per day", key_func=request_principal)' in route_source
        assert '@limiter.limit("5 per minute", key_func=get_remote_address)' in route_source
        assert '@limiter.limit("5 per minute", key_func=request_principal)' in route_source

    for attempt in range(5):
        response = client.post(
            "/auth/login",
            json={"identifier": f"missing{attempt}", "password": "wrong-password"},
        )
        assert response.status_code == 401

    limited = client.post(
        "/auth/login",
        json={"identifier": "missing-final", "password": "wrong-password"},
    )

    assert limited.status_code == 429


def test_login_identifier_limit_is_scoped_by_source_ip(client):
    register(client)

    attacker_ip = "198.51.100.10"
    victim_ip = "198.51.100.20"
    for _attempt in range(5):
        api_login_from_ip(client, attacker_ip, password="wrong-password")

    response = api_login_from_ip(client, victim_ip)
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["mfa_setup_required"] is True


def test_request_principal_is_hashed_and_ip_scoped(app):
    from app.security.rate_limits import request_principal

    with app.test_request_context(
        "/auth/login",
        method="POST",
        json={"identifier": "Victim@Example.COM", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "198.51.100.10"},
    ):
        first_key = request_principal()

    with app.test_request_context(
        "/auth/login",
        method="POST",
        json={"identifier": "victim@example.com", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "198.51.100.20"},
    ):
        second_key = request_principal()

    assert first_key.startswith("principal:")
    assert second_key.startswith("principal:")
    assert first_key != second_key
    assert "victim" not in first_key.casefold()
    assert "example" not in first_key.casefold()
    assert "198.51.100.10" not in first_key


def test_repeated_password_failures_do_not_freeze_account(app, client):
    from app.auth.services import AuthError, authenticate_primary
    from app.security.rate_limits import clear_failures

    register(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()

    for _attempt in range(10):
        with app.test_request_context(
            "/auth/login",
            method="POST",
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        ):
            try:
                authenticate_primary("alice01", "wrong-password")
            except AuthError:
                pass

    db.session.refresh(user)

    assert user.is_frozen is False
    assert user.security_locked_at is None
    assert user.security_lock_reason is None
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="account_lock", outcome="locked").count() == 0

    clear_failures("login", "127.0.0.1:alice01")
    response = login(client)
    db.session.refresh(user)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mfa/setup")
    assert user.failed_login_count == 0


def test_repeated_mfa_failures_freeze_account(app, client):
    from flask import session
    from app.auth.services import AuthError, complete_pending_mfa

    register(client)
    user, _secret = enable_mfa_for_user()

    for _attempt in range(10):
        with app.test_request_context("/auth/mfa/verify", method="POST"):
            session["pending_mfa_user_id"] = user.id
            try:
                complete_pending_mfa("000000")
            except AuthError:
                pass

    db.session.refresh(user)

    assert user.is_frozen is True
    assert user.security_locked_at is not None
    assert user.security_lock_reason == "mfa_failed_attempts"


def test_api_validation_errors_do_not_expose_schema_details(client):
    response = client.post("/auth/login", json={})
    payload = response.get_json()

    assert response.status_code == 400
    assert payload == {"error": "Invalid request"}


def test_login_sets_secure_session_cookie_and_hides_raw_session_id(client):
    register(client)

    response = login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    sessions_response = client.get("/auth/sessions")

    assert response.status_code == 302
    assert "__Host-sitbank_session=" in response.headers["Set-Cookie"]
    assert "Secure" in response.headers["Set-Cookie"]
    assert "HttpOnly" in response.headers["Set-Cookie"]
    assert "SameSite=Strict" in response.headers["Set-Cookie"]
    assert sessions_response.status_code == 200
    session_item = sessions_response.get_json()["sessions"][0]
    assert "session_ref" in session_item
    assert len(session_item["session_ref"]) == 32
    assert "session_id" not in session_item
    assert session_item["ip_address"] == "127.0.0.1"
    assert "login_time_display" in session_item
    assert "last_activity_display" in session_item


def test_logout_invalidates_current_session(client):
    register(client)
    login(client)

    logout_response = client.post("/logout")
    sessions_response = client.get("/auth/sessions")

    assert logout_response.status_code == 302
    assert sessions_response.status_code == 401


def test_logout_records_session_as_past_session_on_management_page(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    original_sessions = client.get("/auth/sessions").get_json()["sessions"]
    original_ref = next(item["session_ref"] for item in original_sessions if item["current"])

    logout_response = client.post("/logout")
    login_response, mfa_response = complete_mfa_login(client, secret)
    sessions_payload = client.get("/auth/sessions").get_json()
    sessions_page = client.get("/sessions")
    markup = sessions_page.data.decode("utf-8")
    current_ref = next(item["session_ref"] for item in sessions_payload["sessions"] if item["current"])
    past = next(item for item in sessions_payload["past_sessions"] if item["session_ref"] == original_ref)

    assert logout_response.status_code == 302
    assert login_response.status_code == 302
    assert mfa_response.status_code == 200
    assert past["ended_reason"] == "logout"
    assert past["ended_reason_display"] == "Logged out"
    assert past["ended_at_display"] != "Unknown"
    assert past["ip_address"] == "127.0.0.1"
    assert "session_id" not in past
    assert sessions_page.status_code == 200
    assert "Active Sessions" in markup
    assert "Past Sessions" in markup
    assert original_ref in markup
    assert f"/sessions/{original_ref}/terminate" not in markup
    assert f"/sessions/{current_ref}/terminate" in markup
    assert "Current" in markup


def test_incognito_logout_appears_in_past_sessions_for_existing_browser(app, client, monkeypatch):
    incognito_client = app.test_client()
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    normal_ref = next(
        item["session_ref"]
        for item in client.get("/auth/sessions").get_json()["sessions"]
        if item["current"]
    )

    incognito_login = login(incognito_client)
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    now = int(time.time())
    incognito_mfa_time = next(
        timestamp
        for timestamp in range(now + 30, now + 600, 30)
        if totp.at(timestamp) != totp.at(now)
    )
    monkeypatch.setattr("app.auth.services.time.time", lambda: incognito_mfa_time)
    incognito_mfa = incognito_client.post(
        "/auth/mfa/verify",
        json={"totp_code": totp.at(incognito_mfa_time)},
    )
    active_after_incognito_login = client.get("/auth/sessions").get_json()["sessions"]
    incognito_ref = next(
        item["session_ref"]
        for item in active_after_incognito_login
        if item["session_ref"] != normal_ref
    )

    incognito_logout = incognito_client.post("/logout")
    sessions_payload = client.get("/auth/sessions").get_json()
    sessions_page = client.get("/sessions")
    markup = sessions_page.data.decode("utf-8")
    past_incognito = next(
        item
        for item in sessions_payload["past_sessions"]
        if item["session_ref"] == incognito_ref
    )

    assert incognito_login.status_code == 302
    assert incognito_mfa.status_code == 200
    assert incognito_logout.status_code == 302
    assert past_incognito["ended_reason"] == "logout"
    assert past_incognito["ended_reason_display"] == "Logged out"
    assert incognito_ref in markup
    assert f"/sessions/{incognito_ref}/terminate" not in markup


def test_session_references_survive_hmac_key_rotation(app, client):
    from app.security.sessions import (
        public_session_reference,
        resolve_session_reference_for_user,
    )

    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    with client.session_transaction() as sess:
        session_id = sess.sid
    old_reference = public_session_reference(session_id)

    app.config["SESSION_HMAC_ACTIVE_KEY_ID"] = "test-previous"
    new_reference = public_session_reference(session_id)

    assert new_reference != old_reference
    assert resolve_session_reference_for_user(user.id, old_reference) == session_id
    assert resolve_session_reference_for_user(user.id, new_reference) == session_id


def test_dummy_password_hash_tracks_current_pbkdf2_configuration(app):
    from app.auth.services import _dummy_password_hash

    original_iterations = app.config["PASSWORD_PBKDF2_ITERATIONS"]
    original_hash = _dummy_password_hash()

    try:
        app.config["PASSWORD_PBKDF2_ITERATIONS"] = original_iterations + 1
        updated_hash = _dummy_password_hash()
    finally:
        app.config["PASSWORD_PBKDF2_ITERATIONS"] = original_iterations
        app.config.pop("_DUMMY_PASSWORD_HASH", None)
        app.config.pop("_DUMMY_PASSWORD_HASH_CONFIG", None)

    assert updated_hash != original_hash
    assert f"$i={original_iterations + 1}$" in updated_hash


def test_unknown_and_known_login_failures_use_same_backoff_path(client):
    register(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()

    known_response = client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "wrong-password-value"},
    )
    unknown_response = client.post(
        "/auth/login",
        json={"identifier": "missing-user", "password": "wrong-password-value"},
    )
    db.session.refresh(user)

    assert known_response.status_code == 401
    assert unknown_response.status_code == 401
    assert known_response.get_json() == unknown_response.get_json()
    assert user.failed_login_count == 0


def test_mfa_setup_stores_encrypted_secret_and_rejects_replay(client):
    register(client)
    login(client)

    setup_response = client.post("/mfa/setup", data={"action": "start"})
    assert setup_response.status_code == 200

    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    assert user.mfa_secret_ciphertext is not None
    assert user.mfa_secret_nonce is not None

    from app.security.crypto import decrypt_mfa_secret

    secret = decrypt_mfa_secret(user.mfa_secret_nonce, user.mfa_secret_ciphertext, user.id)
    setup_page = client.get("/mfa/setup")
    setup_markup = setup_page.data.decode("utf-8")
    code = pyotp.TOTP(secret, digits=6, interval=30).now()

    verify_response = client.post("/mfa/setup", data={"action": "verify", "totp_code": code})
    replay_response = client.post("/mfa/setup", data={"action": "verify", "totp_code": code})

    assert setup_page.status_code == 200
    assert "Manual setup key" in setup_markup
    assert 'id="manual-entry-secret"' in setup_markup
    assert f'value="{secret}"' in setup_markup
    assert verify_response.status_code == 200
    assert replay_response.status_code == 401


def test_mfa_setup_generates_ten_hashed_recovery_codes_and_shows_once(client):
    register(client)
    login(client)
    client.post("/mfa/setup", data={"action": "start"})

    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    secret = decrypt_test_mfa_secret(user)
    code = pyotp.TOTP(secret, digits=6, interval=30).now()

    response = client.post("/mfa/setup", data={"action": "verify", "totp_code": code})
    markup = response.data.decode("utf-8")
    recovery_codes = re.findall(r"<code[^>]*>([0-9a-f]{8}(?:-[0-9a-f]{8}){3})</code>", markup)
    stored_codes = list(
        db.session.execute(
            db.select(RecoveryCode).where(
                RecoveryCode.user_id == user.id,
                RecoveryCode.purpose == "totp_recovery",
                RecoveryCode.used_at.is_(None),
            )
        ).scalars()
    )
    followup = client.get("/mfa/setup")
    followup_markup = followup.data.decode("utf-8")

    assert response.status_code == 200
    assert "data-recovery-code-list" in markup
    assert "data-copy-recovery-codes" in markup
    assert "data-download-recovery-codes" in markup
    assert "Copy all codes" in markup
    assert "Download codes" in markup
    assert len(recovery_codes) == 10
    assert len(stored_codes) == 10
    assert all(len(code.replace("-", "")) == 32 for code in recovery_codes)
    assert all(item.code_hmac not in recovery_codes for item in stored_codes)
    assert recovery_codes[0] not in followup_markup
    assert "data-copy-recovery-codes" not in followup_markup
    assert "data-download-recovery-codes" not in followup_markup


def test_mfa_recovery_codes_are_separate_from_replacement_steps(client):
    register(client)
    login(client)
    enable_mfa_for_user()

    response = client.get("/mfa/setup")
    markup = response.data.decode("utf-8")
    script = Path("app/static/js/account.js").read_text(encoding="utf-8")
    recovery_heading = markup.index("<h2>Recovery codes</h2>")
    replacement_heading = markup.index("<h2>Replace authenticator</h2>")
    recovery_article_start = markup.rfind("<article", 0, recovery_heading)
    recovery_article_end = markup.index("</article>", recovery_heading)
    recovery_article = markup[recovery_article_start:recovery_article_end]

    assert response.status_code == 200
    assert recovery_heading < replacement_heading
    assert 'class="mfa-step recovery-code-panel"' in recovery_article
    assert '<span class="step-number">2</span>' not in recovery_article
    assert '<span class="step-number">2</span>' in markup[
        markup.rfind("<article", 0, replacement_heading):markup.index("</article>", replacement_heading)
    ]
    assert '<span class="step-number">3</span>' in markup
    assert '<span class="step-number">4</span>' in markup
    assert '<span class="step-number">5</span>' not in markup
    assert "navigator.clipboard" in script
    assert "sitbank-recovery-codes.txt" in script
    assert "console." not in script


def test_recovery_code_ui_uses_full_width_card_and_readable_code_chips(client):
    from app.auth.recovery_codes import generate_recovery_codes_for_user

    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    recovery_codes = generate_recovery_codes_for_user(user)
    stylesheet = Path("app/static/css/app.css").read_text(encoding="utf-8")

    response = client.post("/mfa/setup", data={"action": "recovery_codes_regenerate"})
    markup = response.data.decode("utf-8")

    assert response.status_code == 200
    assert recovery_codes[0] not in markup
    assert 'class="notice recovery-code-notice"' in markup
    assert "recovery-code-list-display" in markup
    assert "grid-template-columns: minmax(0, 1fr);" in stylesheet
    assert ".recovery-code-list code" in stylesheet
    assert "background: var(--surface-raised);" in stylesheet
    assert "margin-top: var(--space-5);" in stylesheet


def test_recovery_code_satisfies_pending_totp_login_once_and_notifies(app, client):
    from app.auth.recovery_codes import generate_recovery_codes_for_user
    from app.security.email import password_reset_outbox

    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    recovery_codes = generate_recovery_codes_for_user(user)

    client.post("/logout")
    login_response = login(client)
    verified = client.post("/auth/mfa/verify", json={"totp_code": recovery_codes[0]})
    dashboard = client.get("/dashboard")
    client.post("/logout")
    login(client)
    reused = client.post("/auth/mfa/verify", json={"totp_code": recovery_codes[0]})

    assert login_response.status_code == 302
    assert verified.status_code == 200
    assert verified.get_json()["recovery_codes_remaining"] == 9
    assert dashboard.status_code == 200
    assert "9 unused recovery codes remain." in dashboard.data.decode("utf-8")
    assert reused.status_code == 401
    assert reused.get_json()["error"] == "Invalid authentication code."
    assert db.session.query(RecoveryCode).filter_by(user_id=user.id).filter(RecoveryCode.used_at.is_not(None)).count() == 1
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="mfa_recovery_code_verify", outcome="success").count() == 1
    assert password_reset_outbox()[-1]["subject"] == "SITBank recovery code used"


def test_invalid_recovery_code_attempt_uses_generic_error_and_audits_failure(client):
    register(client)
    login(client)
    enable_mfa_for_user()

    client.post("/logout")
    login(client)
    response = client.post("/auth/mfa/verify", json={"totp_code": "not-a-valid-recovery-code"})

    assert response.status_code == 401
    assert response.get_json()["error"] == "Invalid authentication code."
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="mfa_recovery_code_verify", outcome="failure").count() == 1


def test_recovery_code_cannot_satisfy_login_when_security_key_primary_is_required(client):
    from app.auth.recovery_codes import generate_recovery_codes_for_user

    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    recovery_codes = generate_recovery_codes_for_user(user)
    add_security_keys_for_user(user)

    client.post("/logout")
    with client.session_transaction() as sess:
        sess["pending_mfa_user_id"] = user.id
        sess["password_authenticated_at"] = int(time.time())
    response = client.post("/auth/mfa/verify", json={"totp_code": recovery_codes[0]})

    assert response.status_code == 403
    assert response.get_json()["error"] == "Security key sign-in required for this account"
    assert db.session.query(RecoveryCode).filter_by(user_id=user.id).filter(RecoveryCode.used_at.is_not(None)).count() == 0


def test_recovery_code_regeneration_revokes_old_unused_codes(client):
    from app.auth.recovery_codes import generate_recovery_codes_for_user

    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    old_codes = generate_recovery_codes_for_user(user, count=3)

    response = client.post("/auth/mfa/recovery-codes/regenerate")
    payload = response.get_json()
    used_count = db.session.query(RecoveryCode).filter_by(user_id=user.id).filter(RecoveryCode.used_at.is_not(None)).count()
    unused_count = db.session.query(RecoveryCode).filter_by(user_id=user.id, used_at=None).count()

    assert response.status_code == 200
    assert len(payload["recovery_codes"]) == 10
    assert old_codes[0] not in payload["recovery_codes"]
    assert used_count == 3
    assert unused_count == 10


def test_recovery_code_use_and_regeneration_use_required_audit_writer(client, monkeypatch):
    from app.auth import services as auth_services
    from app.auth.recovery_codes import generate_recovery_codes_for_user

    calls = []

    def required_audit(event_type, outcome, **kwargs):
        calls.append((event_type, outcome, kwargs))
        db.session.commit()

    monkeypatch.setattr(auth_services, "audit_event_required", required_audit)

    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    recovery_codes = generate_recovery_codes_for_user(user)

    client.post("/logout")
    login(client)
    verify_response = client.post("/auth/mfa/verify", json={"totp_code": recovery_codes[0]})
    regenerate_response = client.post("/auth/mfa/recovery-codes/regenerate")

    assert verify_response.status_code == 200
    assert regenerate_response.status_code == 200
    assert ("mfa_recovery_code_verify", "success") in [(call[0], call[1]) for call in calls]
    assert ("recovery_codes_regenerate", "success") in [(call[0], call[1]) for call in calls]


def test_dashboard_warns_when_recovery_codes_are_low(client):
    from app.auth.recovery_codes import generate_recovery_codes_for_user

    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    generate_recovery_codes_for_user(user, count=2)

    response = client.get("/dashboard")
    markup = response.data.decode("utf-8")

    assert response.status_code == 200
    assert "2 unused recovery codes remain." in markup
    assert "Regenerate soon" in markup


def test_mfa_setup_generates_independent_user_secrets(app, client):
    second_client = app.test_client()
    register(client)
    register(second_client, username="bob02", email="bob@example.com")
    login(client)
    login(second_client, identifier="bob02")

    alice_setup = client.post("/mfa/setup", data={"action": "start"})
    bob_setup = second_client.post("/mfa/setup", data={"action": "start"})
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    bob = db.session.execute(db.select(User).where(User.username == "bob02")).scalar_one()

    alice_secret = decrypt_test_mfa_secret(alice)
    bob_secret = decrypt_test_mfa_secret(bob)

    assert alice_setup.status_code == 200
    assert bob_setup.status_code == 200
    assert alice.mfa_secret_ciphertext != bob.mfa_secret_ciphertext
    assert alice_secret != bob_secret


def test_mfa_code_verifies_only_for_own_enrolled_secret(app, client, monkeypatch):
    from app.security.rate_limits import clear_failures

    second_client = app.test_client()
    register(client)
    register(second_client, username="bob02", email="bob@example.com")
    login(client)
    login(second_client, identifier="bob02")

    client.post("/mfa/setup", data={"action": "start"})
    second_client.post("/mfa/setup", data={"action": "start"})
    alice = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    bob = db.session.execute(db.select(User).where(User.username == "bob02")).scalar_one()
    alice_secret = decrypt_test_mfa_secret(alice)
    bob_secret = decrypt_test_mfa_secret(bob)
    now = int(time.time())
    check_time = next(
        timestamp
        for timestamp in range(now, now + 600, 30)
        if pyotp.TOTP(alice_secret, digits=6, interval=30).at(timestamp)
        != pyotp.TOTP(bob_secret, digits=6, interval=30).at(timestamp)
    )
    monkeypatch.setattr("app.auth.services.time.time", lambda: check_time)

    alice_code = pyotp.TOTP(alice_secret, digits=6, interval=30).at(check_time)
    bob_code = pyotp.TOTP(bob_secret, digits=6, interval=30).at(check_time)
    wrong_user_response = second_client.post("/mfa/setup", data={"action": "verify", "totp_code": alice_code})
    clear_failures("mfa_setup", str(bob.id))
    own_user_response = second_client.post("/mfa/setup", data={"action": "verify", "totp_code": bob_code})

    assert wrong_user_response.status_code == 401
    assert own_user_response.status_code == 200


def test_pending_mfa_restart_replaces_previous_setup_secret(client, monkeypatch):
    from app.security.rate_limits import clear_failures

    register(client)
    login(client)

    first_setup = client.post("/mfa/setup", data={"action": "start"})
    first_page = client.get("/mfa/setup")
    first_page_markup = first_page.data.decode("utf-8")
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    first_secret = decrypt_test_mfa_secret(user)

    second_setup = client.post("/mfa/setup", data={"action": "start"})
    db.session.refresh(user)
    second_secret = decrypt_test_mfa_secret(user)
    now = int(time.time())
    check_time = next(
        timestamp
        for timestamp in range(now, now + 600, 30)
        if pyotp.TOTP(first_secret, digits=6, interval=30).at(timestamp)
        != pyotp.TOTP(second_secret, digits=6, interval=30).at(timestamp)
    )
    monkeypatch.setattr("app.auth.services.time.time", lambda: check_time)

    first_code = pyotp.TOTP(first_secret, digits=6, interval=30).at(check_time)
    second_code = pyotp.TOTP(second_secret, digits=6, interval=30).at(check_time)
    old_secret_response = client.post("/mfa/setup", data={"action": "verify", "totp_code": first_code})
    clear_failures("mfa_setup", str(user.id))
    new_secret_response = client.post("/mfa/setup", data={"action": "verify", "totp_code": second_code})

    assert first_setup.status_code == 200
    assert first_page.status_code == 200
    assert b"Restart Setup" in first_page.data
    assert 'class="button full" type="submit">Restart Setup' in first_page_markup
    assert second_setup.status_code == 200
    assert first_secret != second_secret
    assert old_secret_response.status_code == 401
    assert new_secret_response.status_code == 200


def test_mfa_management_page_shows_replacement_controls_when_enabled(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    response = client.get("/mfa/setup")
    markup = response.data.decode("utf-8")

    assert response.status_code == 200
    assert "Authenticator MFA" in markup
    assert "Authenticator MFA is enabled" in markup
    assert "Replace authenticator" in markup
    assert "Verify with security key" in markup
    assert "Disable MFA" not in markup
    assert "Remove MFA" not in markup


def test_security_management_pages_use_polished_stepup_ui(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    first_key = db.session.execute(
        db.select(WebAuthnCredential)
        .where(WebAuthnCredential.user_id == user.id)
        .order_by(WebAuthnCredential.id.asc())
    ).scalars().first()
    first_key.last_used_at = datetime(2026, 6, 5, 15, 11, tzinfo=timezone.utc)
    db.session.commit()

    mfa_page = client.get("/mfa/setup")
    keys_page = client.get("/security-keys")
    sessions_page = client.get("/sessions")
    freeze_page = client.get("/account/freeze")
    css = Path("app/static/css/app.css").read_text(encoding="utf-8")
    mfa_markup = mfa_page.data.decode("utf-8")
    keys_markup = keys_page.data.decode("utf-8")
    sessions_markup = sessions_page.data.decode("utf-8")
    freeze_markup = freeze_page.data.decode("utf-8")

    assert mfa_page.status_code == 200
    assert keys_page.status_code == 200
    assert sessions_page.status_code == 200
    assert freeze_page.status_code == 200
    assert 'class="mfa-step is-muted"' in mfa_markup
    assert ".mfa-step.is-muted .step-number" in css
    assert "background: var(--primary);" in css
    assert 'class="compact-verification-form"' in keys_markup
    assert "AAGUID" not in keys_markup
    assert "11111111-1111-1111-1111-111111111111" not in keys_markup
    assert "Last used: 05 Jun 2026 15:11 UTC" in keys_markup
    assert "Verify with security key and revoke" in keys_markup
    assert 'class="button danger-button button-small key-revoke-button"' in keys_markup
    assert "Revoke is disabled because at least two approved security keys must stay registered" in keys_markup
    assert 'class="button danger-button"' in sessions_markup
    assert "Verify with security key and terminate other sessions" in sessions_markup
    assert 'class="button danger-button full"' in freeze_markup
    assert "Verify with security key and freeze account" in freeze_markup
    assert "color: var(--button-primary-text);" in css
    assert "text-align: left;" in css


def test_mfa_replacement_start_requires_security_key_stepup(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    response = client.post("/mfa/setup", data={"action": "replace_start"})
    db.session.refresh(user)

    assert response.status_code == 403
    assert "replacement-manual-entry-secret" not in response.data.decode("utf-8")


def test_mfa_replacement_keeps_old_secret_until_new_code_is_verified(client, monkeypatch):
    from app.security.rate_limits import clear_failures

    register(client)
    login(client)
    user, old_secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    mark_recent_mfa(client, user)

    start_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: start_time)
    start_response = client.post(
        "/mfa/setup",
        data={
            "action": "replace_start",
            "stepup_token": mint_stepup_token(client, user, "mfa_replace_start"),
        },
    )
    db.session.refresh(user)
    markup = start_response.data.decode("utf-8")
    match = re.search(r'id="replacement-manual-entry-secret"[^>]*value="([^"]+)"', markup)
    assert match is not None
    replacement_secret = match.group(1)
    replacement_time = start_time + 30
    monkeypatch.setattr("app.auth.services.time.time", lambda: replacement_time)
    replacement_code = pyotp.TOTP(replacement_secret, digits=6, interval=30).at(replacement_time)
    wrong_code = "000000" if replacement_code != "000000" else "000001"

    wrong_response = client.post("/mfa/setup", data={"action": "replace_verify", "totp_code": wrong_code})
    db.session.refresh(user)
    active_secret_after_wrong_code = decrypt_test_mfa_secret(user)
    clear_failures("mfa_replace_verify", str(user.id))
    correct_response = client.post("/mfa/setup", data={"action": "replace_verify", "totp_code": replacement_code})
    db.session.refresh(user)

    assert start_response.status_code == 200
    assert replacement_secret != old_secret
    assert active_secret_after_wrong_code == old_secret
    assert decrypt_test_mfa_secret(user) == replacement_secret
    assert wrong_response.status_code == 401
    assert correct_response.status_code == 200
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="mfa_replace_verify", outcome="success").count() == 1

    client.post("/logout")
    login_response = login(client)

    assert login_response.status_code == 403
    assert b"Security key sign-in required for this account" in login_response.data


def test_unauthenticated_users_cannot_access_mfa_setup_material(client):
    page_response = client.get("/mfa/setup")
    web_post_response = client.post("/mfa/setup", data={"action": "start"})
    api_post_response = client.post("/auth/mfa/setup")

    assert page_response.status_code == 302
    assert page_response.headers["Location"].endswith("/login")
    assert web_post_response.status_code == 302
    assert web_post_response.headers["Location"].endswith("/login")
    assert api_post_response.status_code == 401


def test_mfa_verify_rejects_invalid_code(client):
    register(client)
    login(client)
    client.post("/mfa/setup", data={"action": "start"})

    response = client.post("/mfa/setup", data={"action": "verify", "totp_code": "000000"})

    assert response.status_code == 401


def test_revoke_other_sessions_requires_mfa(client):
    register(client)
    login(client)

    response = client.post("/sessions/revoke-others", data={"totp_code": "123456"})

    assert response.status_code == 302
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="session_revoke_others").count() == 0


def test_terminate_other_session_by_public_reference_revokes_it(app, client):
    second_client = app.test_client()
    register(client)
    login(client)
    login(second_client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    sessions = client.get("/auth/sessions").get_json()["sessions"]
    other_session = next(item for item in sessions if not item["current"])
    response = client.delete(f"/auth/sessions/{other_session['session_ref']}")
    revoked_response = second_client.get("/auth/sessions")

    assert response.status_code == 200
    assert revoked_response.status_code == 401
    assert revoked_response.get_json()["error"] in {"Session revoked", "Authentication required"}


def test_terminating_other_session_moves_it_to_past_sessions(app, client):
    second_client = app.test_client()
    register(client)
    login(client)
    login(second_client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    sessions = client.get("/auth/sessions").get_json()["sessions"]
    other_session = next(item for item in sessions if not item["current"])
    response = client.delete(f"/auth/sessions/{other_session['session_ref']}")
    sessions_payload = client.get("/auth/sessions").get_json()
    sessions_page = client.get("/sessions")
    markup = sessions_page.data.decode("utf-8")

    active_refs = {item["session_ref"] for item in sessions_payload["sessions"]}
    past = next(
        item
        for item in sessions_payload["past_sessions"]
        if item["session_ref"] == other_session["session_ref"]
    )

    assert response.status_code == 200
    assert other_session["session_ref"] not in active_refs
    assert past["ended_reason"] == "terminated"
    assert past["ended_reason_display"] == "Terminated"
    assert other_session["session_ref"] in markup
    assert f"/sessions/{other_session['session_ref']}/terminate" not in markup


def test_past_sessions_are_scoped_to_current_user(app, client):
    second_client = app.test_client()
    register(client)
    login(client)
    alice, _alice_secret = enable_mfa_for_user()
    mark_recent_mfa(client, alice)

    register(second_client, username="bob02", email="bob@example.com")
    login(second_client, identifier="bob02")
    bob, _bob_secret = enable_mfa_for_user("bob02")
    mark_recent_mfa(second_client, bob)
    bob_ref = second_client.get("/auth/sessions").get_json()["sessions"][0]["session_ref"]

    logout_response = second_client.post("/logout")
    alice_payload = client.get("/auth/sessions").get_json()
    sessions_page = client.get("/sessions")
    markup = sessions_page.data.decode("utf-8")

    assert logout_response.status_code == 302
    assert bob_ref not in {item["session_ref"] for item in alice_payload["sessions"]}
    assert bob_ref not in {item["session_ref"] for item in alice_payload["past_sessions"]}
    assert bob_ref not in markup


def test_revoke_other_sessions_requires_security_key_stepup_and_rotates_session(app, client, monkeypatch):
    second_client = app.test_client()
    register(client)
    login(client)
    login(second_client)

    client.post("/mfa/setup", data={"action": "start"})
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()

    from app.security.crypto import decrypt_mfa_secret

    secret = decrypt_mfa_secret(user.mfa_secret_nonce, user.mfa_secret_ciphertext, user.id)
    setup_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: setup_time)
    code = pyotp.TOTP(secret, digits=6, interval=30).at(setup_time)

    setup_verify = client.post("/mfa/setup", data={"action": "verify", "totp_code": code})
    add_security_keys_for_user(user)
    with client.session_transaction() as sess:
        session_after_setup = sess.sid

    revoke_without_stepup = client.post("/sessions/revoke-others")
    api_without_stepup = client.post("/auth/sessions/revoke-others", json={})
    other_session_before_revoke = second_client.get("/auth/sessions")

    revoke_time = setup_time + 30
    monkeypatch.setattr("app.auth.services.time.time", lambda: revoke_time)
    api_revoke_response = client.post(
        "/auth/sessions/revoke-others",
        json={
            "stepup_token": mint_stepup_token(client, user, "session_revoke_others"),
        },
    )
    with client.session_transaction() as sess:
        session_after_revoke = sess.sid
    revoked_response = second_client.get("/auth/sessions")

    assert setup_verify.status_code == 200
    assert revoke_without_stepup.status_code == 302
    assert api_without_stepup.status_code == 403
    assert other_session_before_revoke.status_code == 200
    assert api_revoke_response.status_code == 200
    assert session_after_revoke != session_after_setup
    assert revoked_response.status_code == 401


def test_session_termination_rejects_unowned_session_id(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    response = client.post("/sessions/00000000000000000000000000000000/terminate")

    assert response.status_code == 302
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="session_terminate", outcome="failure").count() == 1


def test_session_termination_rejects_raw_internal_session_id(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    with client.session_transaction() as sess:
        raw_session_id = sess.sid

    response = client.delete(f"/auth/sessions/{raw_session_id}")
    public_sessions = client.get("/auth/sessions")

    assert response.status_code == 400
    assert public_sessions.status_code == 200


def test_web_terminating_current_session_redirects_to_login_page(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    sessions_page = client.get("/sessions")
    current_ref = client.get("/auth/sessions").get_json()["sessions"][0]["session_ref"]
    response = client.post(f"/sessions/{current_ref}/terminate")
    login_page = client.get(response.headers["Location"])

    assert sessions_page.status_code == 200
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
    assert login_page.status_code == 200
    assert b"Log in to SITBank" in login_page.data
    assert b"Session revoked" not in login_page.data


def test_session_inactivity_expiry_revokes_session(client):
    register(client)
    login(client)

    with client.session_transaction() as sess:
        sess["last_activity_at"] = 1

    response = client.get("/auth/sessions")

    assert response.status_code == 401
    assert response.get_json()["error"] == "Session expired"


def test_pending_mfa_session_expires_by_absolute_age(app, client):
    register(client)
    login(client)
    _user, secret = enable_mfa_for_user()
    client.post("/logout")

    pending_response = login(client)
    assert pending_response.status_code == 302

    with client.session_transaction() as sess:
        assert sess["pending_mfa_user_id"]
        sess["last_activity_at"] = int(time.time())
        sess["password_authenticated_at"] = int(time.time()) - app.config["PENDING_MFA_MAX_AGE_SECONDS"] - 1

    response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).now()},
    )

    assert response.status_code == 401
    assert response.get_json()["error"] == "MFA challenge expired. Please log in again."


def test_account_freeze_is_durable_and_blocks_group_a_sensitive_actions(client):
    from app.auth.services import FrozenAccountError
    from app.banking.services import ensure_outbound_transfer_allowed
    from app.security.crypto import encrypt_mfa_secret

    register(client)
    login(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    db.session.commit()
    add_security_keys_for_user(user)

    response = client.post(
        "/account/freeze",
        data={
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
            "stepup_token": mint_stepup_token(client, user, "account_freeze"),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 302
    assert user.is_frozen is True
    with current_app.test_request_context("/banking/outbound-transfer", method="POST"):
        with pytest.raises(FrozenAccountError):
            ensure_outbound_transfer_allowed(user)

    event = (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="banking_outbound_transfer", outcome="blocked")
        .one()
    )
    assert event.user_id == user.id
    assert event.event_metadata["reason"] == "account_frozen"


def test_frozen_account_cannot_create_new_login_session(client):
    register(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    user.is_frozen = True
    user.security_locked_at = user.created_at
    user.security_lock_reason = "manual_review"
    db.session.commit()

    response = client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "correct horse battery staple"},
    )

    assert response.status_code == 403
    assert response.get_json()["error"] == "Authentication unavailable for this account"


def test_frozen_session_can_view_dashboard_and_sessions_but_not_sensitive_actions(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    user.is_frozen = True
    user.security_locked_at = user.created_at
    user.security_lock_reason = "manual_review"
    db.session.commit()

    dashboard_response = client.get("/dashboard")
    sessions_response = client.get("/sessions")
    profile_response = client.get("/profile")
    mfa_response = client.get("/mfa/setup")
    keys_response = client.get("/security-keys")
    freeze_response = client.get("/account/freeze")

    assert dashboard_response.status_code == 200
    assert sessions_response.status_code == 200
    assert profile_response.status_code == 302
    assert mfa_response.status_code == 302
    assert keys_response.status_code == 302
    assert freeze_response.status_code == 302


def test_templates_do_not_mark_user_controlled_data_safe():
    templates = Path("app/templates").glob("*.html")

    assert all("|safe" not in template.read_text(encoding="utf-8") for template in templates)


def test_theme_assets_are_csp_compatible_and_store_only_theme_preference(client):
    response = client.get("/")
    script = Path("app/static/js/theme.js").read_text(encoding="utf-8")
    stylesheet = Path("app/static/css/app.css").read_text(encoding="utf-8")
    logo = Path("app/static/img/sitbank-mark.svg").read_text(encoding="utf-8")

    assert response.status_code == 200
    assert b'/static/js/theme.js' in response.data
    assert b"<script>" not in response.data
    assert b"data-theme-toggle" in response.data
    assert b"data-theme-toggle-icon" in response.data
    assert b'aria-label="Switch to dark mode"' in response.data
    assert b'title="Switch to dark mode"' in response.data
    assert "Switch to light mode" in script
    assert "Switch to dark mode" in script
    assert 'setAttribute("title", actionLabel)' in script
    assert 'data-icon", isDark ? "sun" : "moon"' in script
    assert "localStorage" in script
    assert "sitbank-theme" in script
    assert "token" not in script.casefold()
    assert "session" not in script.casefold()
    assert "username" not in script.casefold()
    assert "--security: #143f66;" in stylesheet
    assert "--security: #86b9ec;" in stylesheet
    assert ".nav a.button" in stylesheet
    assert "--button-primary-text: #071421;" in stylesheet
    assert ".quick-card" in stylesheet
    assert ".profile-status-copy" in stylesheet
    assert ".alert {" in stylesheet
    assert "display: flex;" in stylesheet
    assert "flex: 0 0 14px;" in stylesheet
    assert ".mfa-step.is-complete .step-number" in stylesheet
    assert "background: var(--success);" not in stylesheet
    assert "#0f766e" not in logo
    assert 'fill="#143f66"' in logo
    assert 'fill="#28628f"' in logo


def test_authenticated_layout_contains_working_profile_menu_destinations(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    response = client.get("/dashboard")
    markup = response.data.decode("utf-8")

    assert response.status_code == 200
    assert 'data-account-menu' in markup
    assert 'aria-expanded="false"' in markup
    assert 'href="/profile"' in markup
    assert "Edit Profile" in markup
    assert "Change Password" in markup
    assert 'aria-disabled="true">Change Password' in markup
    assert 'href="/password/change"' not in markup
    assert "Authenticator MFA" in markup
    assert "Active Sessions" in markup
    assert "Security Keys" in markup
    assert "Freeze Account" in markup
    assert "Log Out" in markup
    assert markup.index('href="/mfa/setup"') < markup.index('href="/security-keys"') < markup.index('href="/sessions"')
    assert "No hardware security keys are enrolled yet" in markup
    assert "Transaction-ready" not in markup


def test_security_key_setup_prompts_for_authenticator_mfa_first(client):
    register(client)
    login(client)

    response = client.get("/security-keys")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mfa/setup")


def test_public_layout_does_not_expose_authenticated_account_actions(client):
    response = client.get("/login")
    markup = response.data.decode("utf-8")

    assert response.status_code == 200
    assert "data-account-menu" not in markup
    assert "Edit Profile" not in markup
    assert "data-webauthn-login-form" in markup
    assert "Available after two approved hardware security keys are registered." in markup
    assert 'href="/profile"' not in markup
    assert 'action="/logout"' not in markup


def test_authentication_pages_have_password_helpers_and_mfa_back_link(client):
    register_page = client.get("/register")
    login_page = client.get("/login")
    register(client)
    user, secret = enable_mfa_for_user()
    client.post("/logout")
    login(client)
    mfa_page = client.get("/mfa/verify")

    assert register_page.status_code == 200
    assert login_page.status_code == 200
    assert mfa_page.status_code == 200
    assert "data-password-toggle" in register_page.data.decode("utf-8")
    assert "data-password-strength" in register_page.data.decode("utf-8")
    assert "data-password-toggle" in login_page.data.decode("utf-8")
    assert "Back to login" in mfa_page.data.decode("utf-8")


def test_flash_messages_are_dismissible(client):
    response = client.post(
        "/register",
        data={
            "username": "flash01",
            "email": "flash@example.com",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "data-alert-dismiss" in response.data.decode("utf-8")


def test_landing_route_public_for_anonymous_and_dashboard_for_authenticated(client):
    public_response = client.get("/")

    register(client)
    login(client)
    authenticated_response = client.get("/")

    assert public_response.status_code == 200
    assert b"Log in securely" in public_response.data
    assert authenticated_response.status_code == 302
    assert authenticated_response.headers["Location"].endswith("/dashboard")


def test_authenticated_brand_link_targets_dashboard(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    response = client.get("/dashboard")
    markup = response.data.decode("utf-8")

    assert response.status_code == 200
    assert '<a class="brand" href="/dashboard"' in markup


def test_profile_requires_authentication(client):
    response = client.get("/profile")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_authenticated_user_can_open_own_edit_profile_page(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    response = client.get("/profile")
    markup = response.data.decode("utf-8")

    assert response.status_code == 200
    assert b"Edit profile" in response.data
    assert b"alice01" in response.data
    assert b"alice@example.com" in response.data
    assert 'name="username"' not in markup
    assert 'name="email"' not in markup
    assert "Update profile details" in markup
    assert "Save profile" not in markup
    assert "Security keys required" in markup
    assert "Manage keys" in markup
    assert "Manage MFA" in markup
    assert "Change password" in markup
    assert 'aria-disabled="true">Change password' in markup
    assert 'href="/password/change"' not in markup
    assert "profile-status-copy" in markup
    assert "Hardware keys are used for future high-risk transaction approval." in markup
    assert 'href="/security-keys"' in markup
    assert 'class="badge warning"' not in markup


def test_profile_enables_change_password_action_after_mfa_setup(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    add_security_keys_for_user(user)

    response = client.get("/profile")
    markup = response.data.decode("utf-8")

    assert response.status_code == 200
    assert "Change available" in markup
    assert 'href="/password/change"' in markup
    assert 'aria-disabled="true">Change password' not in markup


def test_password_change_page_requires_mfa_setup(client):
    register(client)
    login(client)

    response = client.get("/password/change")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mfa/setup")


def test_password_change_succeeds_with_recent_mfa_and_revokes_other_sessions(app, client, monkeypatch):
    from app.security.rate_limits import clear_failures

    second_client = app.test_client()
    register(client)
    login(client)
    login(second_client)
    user, secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    mark_recent_mfa(client, user)
    stepup_token = mint_stepup_token(client, user, "password_change")
    old_hash = user.password_hash
    change_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: change_time)
    with client.session_transaction() as sess:
        session_before_change = sess.sid

    response = client.post(
        "/password/change",
        data={
            "current_password": "correct horse battery staple",
            "new_password": "new correct horse battery staple",
            "confirm_new_password": "new correct horse battery staple",
            "stepup_token": stepup_token,
        },
    )
    db.session.refresh(user)
    with client.session_transaction() as sess:
        session_after_change = sess.sid
    client.post("/logout")
    old_login = login(client)
    clear_failures("login", "127.0.0.1:alice01")
    new_login = login(client, password="new correct horse battery staple")
    revoked_response = second_client.get("/auth/sessions")

    assert response.status_code == 302
    assert session_after_change != session_before_change
    assert user.password_hash != old_hash
    assert old_login.status_code == 401
    assert new_login.status_code == 403
    assert b"Security key sign-in required for this account" in new_login.data
    assert revoked_response.status_code == 401
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="password_change", outcome="success").count() == 1


def test_password_change_rejects_totp_only_without_security_key_stepup(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    mark_recent_mfa(client, user)
    old_hash = user.password_hash

    response = client.post(
        "/password/change",
        data={
            "current_password": "correct horse battery staple",
            "new_password": "new correct horse battery staple",
            "confirm_new_password": "new correct horse battery staple",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 403
    assert user.password_hash == old_hash


def test_password_change_rejects_over_limit_current_and_new_passwords(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    old_hash = user.password_hash

    oversized_current = client.post(
        "/password/change",
        data={
            "current_password": "A" * 300,
            "new_password": "new correct horse battery staple",
            "confirm_new_password": "new correct horse battery staple",
        },
    )
    oversized_new = client.post(
        "/password/change",
        data={
            "current_password": "correct horse battery staple",
            "new_password": "B" * 300,
            "confirm_new_password": "B" * 300,
        },
    )
    db.session.refresh(user)

    assert oversized_current.status_code == 400
    assert oversized_current.status_code != 500
    assert b"longer than 256 characters" in oversized_current.data
    assert oversized_new.status_code == 400
    assert oversized_new.status_code != 500
    assert b"longer than 256 characters" in oversized_new.data
    assert user.password_hash == old_hash


def test_password_change_rejects_common_or_reused_password(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    mark_recent_mfa(client, user)

    reused_response = client.post(
        "/password/change",
        data={
            "current_password": "correct horse battery staple",
            "new_password": "correct horse battery staple",
            "confirm_new_password": "correct horse battery staple",
        },
    )
    common_response = client.post(
        "/password/change",
        data={
            "current_password": "correct horse battery staple",
            "new_password": "password",
            "confirm_new_password": "password",
            "stepup_token": mint_stepup_token(client, user, "password_change"),
        },
    )

    assert reused_response.status_code == 400
    assert common_response.status_code == 400


def test_profile_details_update_succeeds_for_authenticated_user(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    add_security_keys_for_user(user)

    response = client.post(
        "/profile",
        data={
            "username": "alice02",
            "email": "alice.new@example.com",
            "stepup_token": mint_stepup_token(client, user, "profile_update"),
        },
    )
    db.session.refresh(user)
    client.post("/logout")
    new_username_login = login(client, identifier="alice02")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/profile")
    assert user.username == "alice02"
    assert user.email == "alice.new@example.com"
    assert new_username_login.status_code == 403
    assert b"Security key sign-in required for this account" in new_username_login.data
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="profile_update", outcome="success").count() == 1


def test_profile_email_update_requires_security_key_stepup_and_rotates_session(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    mark_recent_mfa(client, user)
    with client.session_transaction() as sess:
        session_before_update = sess.sid

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice.mfa@example.com",
            "stepup_token": mint_stepup_token(client, user, "profile_update"),
        },
    )
    db.session.refresh(user)
    with client.session_transaction() as sess:
        session_after_update = sess.sid

    assert response.status_code == 302
    assert session_after_update != session_before_update
    assert user.email == "alice.mfa@example.com"


def test_profile_email_update_rejects_totp_only_without_security_key_stepup(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    mark_recent_mfa(client, user)

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice.mfa@example.com",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 403
    assert user.email == "alice@example.com"


def test_profile_update_rejects_invalid_email(client):
    register(client)
    login(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    mark_recent_mfa(client, user)

    response = client.post("/profile", data={"username": "alice01", "email": "not-an-email"})
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.email == "alice@example.com"


def test_profile_update_rejects_invalid_username(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()

    response = client.post("/profile", data={"username": "bad user", "email": "alice@example.com"})
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.username == "alice01"


def test_profile_update_rejects_duplicate_username(client):
    register(client)
    register(client, username="bob02", email="bob@example.com")
    login(client)
    user, _secret = enable_mfa_for_user()

    response = client.post("/profile", data={"username": "BOB02", "email": "alice@example.com"})
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.username == "alice01"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="profile_update", outcome="failure").count() == 1


def test_profile_update_rejects_duplicate_email(client):
    register(client)
    register(client, username="bob02", email="bob@example.com")
    login(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    mark_recent_mfa(client, user)

    response = client.post("/profile", data={"username": "alice01", "email": "bob@example.com"})
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.email == "alice@example.com"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="profile_update", outcome="failure").count() == 1


def test_profile_post_requires_csrf_when_enabled(app, client):
    register(client)
    login(client)
    original = app.config["WTF_CSRF_ENABLED"]
    app.config["WTF_CSRF_ENABLED"] = True

    try:
        response = client.post("/profile", data={"username": "alice02", "email": "alice.new@example.com"})
    finally:
        app.config["WTF_CSRF_ENABLED"] = original

    assert response.status_code == 400


def test_json_auth_post_requires_global_csrf_header_when_enabled(app, client):
    original = app.config["WTF_CSRF_ENABLED"]
    app.config["WTF_CSRF_ENABLED"] = True

    try:
        token = client.get("/auth/csrf-token").get_json()["csrf_token"]
        missing_token = client.post(
            "/auth/login",
            json={"identifier": "missing-user", "password": "wrong-password-value"},
        )
        valid_token = client.post(
            "/auth/login",
            json={"identifier": "missing-user", "password": "wrong-password-value"},
            headers={"X-CSRFToken": token},
        )
    finally:
        app.config["WTF_CSRF_ENABLED"] = original

    assert missing_token.status_code == 400
    assert missing_token.get_json() == {
        "error": "Security token expired or invalid. Please try again."
    }
    assert valid_token.status_code == 401
    assert valid_token.get_json() == {"error": "Invalid username or password"}


def test_profile_submission_cannot_modify_privileged_fields(client):
    register(client)
    register(client, username="bob02", email="bob@example.com")
    login(client)
    user, secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    other_user = db.session.execute(db.select(User).where(User.username == "bob02")).scalar_one()
    original_password_hash = user.password_hash

    response = client.post(
        "/profile",
        data={
            "username": "alice02",
            "email": "alice.new@example.com",
            "stepup_token": mint_stepup_token(client, user, "profile_update"),
            "user_id": str(other_user.id),
            "mfa_enabled": "true",
            "is_frozen": "true",
            "password_hash": "not-a-real-hash",
            "role": "admin",
        },
    )
    db.session.refresh(user)
    db.session.refresh(other_user)

    assert response.status_code == 302
    assert user.username == "alice02"
    assert user.email == "alice.new@example.com"
    assert user.mfa_enabled is True
    assert user.is_frozen is False
    assert user.password_hash == original_password_hash
    assert other_user.username == "bob02"
    assert other_user.email == "bob@example.com"


def test_hash_password_uses_configured_pbkdf2_iterations(app):
    with app.app_context():
        password_hash = hash_password("correct horse battery staple")

    assert password_hash.startswith(f"{PBKDF2_PREFIX}$v1$i=600000$")


def test_pending_web_mfa_expiry_redirects_to_login_and_audits(app, client):
    register(client)
    _user, _secret = enable_mfa_for_user()
    login(client)

    with client.session_transaction() as sess:
        sess["password_authenticated_at"] = int(time.time()) - app.config["PENDING_MFA_MAX_AGE_SECONDS"] - 1

    response = client.get("/mfa/verify", follow_redirects=True)

    assert response.status_code == 200
    assert b"MFA challenge expired. Please log in again." in response.data
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="mfa_login_expired", outcome="expired").count() == 1


def test_pending_api_mfa_expiry_returns_stable_error_code(app, client):
    register(client)
    _user, secret = enable_mfa_for_user()
    login(client)

    with client.session_transaction() as sess:
        sess["password_authenticated_at"] = int(time.time()) - app.config["PENDING_MFA_MAX_AGE_SECONDS"] - 1

    response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).now()},
    )

    assert response.status_code == 401
    assert response.get_json() == {
        "error": "MFA challenge expired. Please log in again.",
        "code": "mfa_challenge_expired",
    }


def test_high_risk_stepup_token_is_scoped_one_time_and_expirable(app, client):
    from app.auth.webauthn_services import _step_up_token_cache_key

    second_client = app.test_client()
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    totp = pyotp.TOTP(secret, digits=6, interval=30)

    wrong_action_token = mint_stepup_token(client, user, "password_change")
    wrong_action_response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "wrong-action@example.com",
            "totp_code": totp.now(),
            "stepup_token": wrong_action_token,
        },
    )
    db.session.refresh(user)

    session_scoped_token = mint_stepup_token(client, user, "profile_update")
    now = int(time.time())
    with second_client.session_transaction() as sess:
        sess["user_id"] = user.id
        sess["auth_context"] = "password+mfa_bootstrap"
        sess["login_at"] = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now))
        sess["last_activity_at"] = now
    wrong_session_response = second_client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "wrong-session@example.com",
            "totp_code": totp.now(),
            "stepup_token": session_scoped_token,
        },
    )
    db.session.refresh(user)

    valid_token = mint_stepup_token(client, user, "profile_update")
    success_response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice.stepup@example.com",
            "totp_code": totp.now(),
            "stepup_token": valid_token,
        },
    )
    db.session.refresh(user)
    reuse_response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "reuse-token@example.com",
            "totp_code": totp.now(),
            "stepup_token": valid_token,
        },
    )
    db.session.refresh(user)

    expired_token = mint_stepup_token(client, user, "profile_update")
    current_app.extensions["redis"].delete(_step_up_token_cache_key(expired_token))
    expired_response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "expired-token@example.com",
            "totp_code": totp.now(),
            "stepup_token": expired_token,
        },
    )
    db.session.refresh(user)

    assert wrong_action_response.status_code == 403
    assert wrong_session_response.status_code == 403
    assert success_response.status_code == 302
    assert user.email == "alice.stepup@example.com"
    assert reuse_response.status_code == 403
    assert expired_response.status_code == 403
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="webauthn_step_up_consume", outcome="expired").count() >= 1


def test_high_risk_action_without_two_keys_returns_enrollment_error(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice.needs-keys@example.com",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 403
    assert b"Two registered security keys are required for this action" in response.data
    assert user.email == "alice@example.com"


def test_api_onboarding_requires_totp_before_authenticated_endpoints(client):
    register(client)
    login(client)

    sessions_response = client.get("/auth/sessions")
    csrf_response = client.get("/auth/csrf-token")

    assert sessions_response.status_code == 403
    assert sessions_response.get_json() == {
        "error": "Authenticator MFA setup required",
        "code": "mfa_setup_required",
    }
    assert csrf_response.status_code == 200


def test_totp_user_without_security_keys_can_navigate_but_high_risk_actions_are_locked(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    dashboard_response = client.get("/dashboard")
    profile_response = client.get("/profile")
    sessions_response = client.get("/sessions")
    keys_response = client.get("/security-keys")
    password_response = client.get("/password/change")
    freeze_response = client.get("/account/freeze")

    assert dashboard_response.status_code == 200
    assert profile_response.status_code == 200
    assert sessions_response.status_code == 200
    assert keys_response.status_code == 200
    assert password_response.status_code == 302
    assert password_response.headers["Location"].endswith("/security-keys")
    assert freeze_response.status_code == 200
    assert b"Security keys required" in profile_response.data
    assert b"Security keys required" in sessions_response.data
    assert b"Security keys required" in freeze_response.data


def test_security_key_page_allows_inline_totp_refresh_for_stale_session(client, monkeypatch):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    now = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: now)
    monkeypatch.setattr("app.security.sessions.time.time", lambda: now)
    with client.session_transaction() as sess:
        session_before_refresh = sess.sid

    stale_page = client.get("/security-keys")
    refresh_response = client.post(
        "/security-keys/mfa/refresh",
        data={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(now)},
    )
    with client.session_transaction() as sess:
        session_after_refresh = sess.sid
        fresh_mfa_verified_at = sess.get("fresh_mfa_verified_at")
    fresh_page = client.get("/security-keys")

    assert stale_page.status_code == 200
    assert b"Enter your authenticator code to continue" in stale_page.data
    assert b"Register security key</button>" in stale_page.data
    assert b"Register security key</button>" in fresh_page.data
    assert b"disabled>Register security key</button>" in stale_page.data
    assert b"disabled>Register security key</button>" not in fresh_page.data
    assert refresh_response.status_code == 302
    assert refresh_response.headers["Location"].endswith("/security-keys")
    assert session_after_refresh != session_before_refresh
    assert fresh_mfa_verified_at == now
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="webauthn_mfa_refresh", outcome="mfa_success").count() == 1


def test_security_key_inline_totp_refresh_requires_relogin_on_risk_drift(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    with client.session_transaction() as sess:
        sess["risk_fingerprint"] = "tampered"

    response = client.post(
        "/security-keys/mfa/refresh",
        data={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).now()},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="session_risk", outcome="step_up_required").count() == 1
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="webauthn_mfa_refresh", outcome="mfa_success").count() == 0


def test_session_risk_drift_requires_reauth_before_sensitive_action(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    mark_recent_mfa(client, user)
    token = mint_stepup_token(client, user, "profile_update")
    with client.session_transaction() as sess:
        sess["risk_fingerprint"] = "tampered"

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice.drift@example.com",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
            "stepup_token": token,
        },
    )
    db.session.refresh(user)

    assert response.status_code == 401
    assert b"Session verification required. Please sign in again." in response.data
    assert user.email == "alice@example.com"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="session_risk", outcome="step_up_required").count() == 1


def test_audit_metadata_strips_control_characters_and_redacts_secrets(app):
    from app.security.audit import audit_event

    with app.test_request_context("/"):
        audit_event(
            "audit_hygiene",
            "success",
            metadata={
                "note": "line1\r\nline2\tend",
                "password\nfield": "secret-value",
                "amount": "10.00",
            },
        )

    event = db.session.query(SecurityAuditEvent).filter_by(event_type="audit_hygiene").one()

    assert event.event_metadata["note"] == "line1 line2 end"
    assert event.event_metadata["password field"] == "[redacted]"
    assert event.event_metadata["amount"] == "10.00"


def test_structured_audit_log_output_is_sanitized(app, caplog):
    from app.security.audit import audit_event

    raw_session_id = "raw-session-id-should-not-be-logged"
    caplog.set_level("INFO", logger=app.logger.name)
    with app.test_request_context(
        "/audit/hygiene?token=query-secret",
        method="POST",
        environ_overrides={"REMOTE_ADDR": "198.51.100.44"},
        headers={"User-Agent": "AuditTest/1.0"},
    ):
        audit_event(
            "audit_hygiene",
            "success",
            metadata={
                "note": "line1\nline2",
                "password": "plain-password",
                "totp_code": "123456",
                "csrf_token": "csrf-secret",
                "bearer_token": "Bearer token-secret",
                "session_id": raw_session_id,
                "account_number": "1234 5678 9012 3456",
            },
            session_id=raw_session_id,
        )

    logs = "\n".join(record.getMessage() for record in caplog.records)
    payload = log_payloads(caplog, "security_audit_event")[-1]

    assert payload["path"] == "/audit/hygiene"
    assert payload["method"] == "POST"
    assert payload["session_ref"] != raw_session_id
    assert len(payload["session_ref"]) == 16
    assert payload["hash_algorithm"] == "hmac-sha256-v1"
    assert len(payload["event_hash"]) == 64
    assert len(payload["previous_event_hash"]) == 64
    assert payload["metadata"]["note"] == "line1 line2"
    assert payload["metadata"]["password"] == "[redacted]"
    assert payload["metadata"]["totp_code"] == "[redacted]"
    assert payload["metadata"]["csrf_token"] == "[redacted]"
    assert payload["metadata"]["bearer_token"] == "[redacted]"
    assert payload["metadata"]["session_id"] == "[redacted]"
    assert payload["metadata"]["account_number"] == "[redacted]"
    for forbidden in (
        "query-secret",
        "plain-password",
        "123456",
        "csrf-secret",
        "token-secret",
        raw_session_id,
        "1234 5678 9012 3456",
    ):
        assert forbidden not in logs


def test_audit_write_failure_warning_is_sanitized(app, caplog, monkeypatch):
    from app.security.audit import audit_event

    def fail_commit():
        raise RuntimeError("database password leaked")

    monkeypatch.setattr(db.session, "commit", fail_commit)
    caplog.set_level("WARNING", logger=app.logger.name)

    with app.test_request_context("/audit/fail", method="POST"):
        audit_event(
            "audit_failure",
            "failure",
            metadata={
                "password": "plain-password",
                "token": "Bearer token-secret",
            },
        )

    logs = "\n".join(record.getMessage() for record in caplog.records)
    payload = log_payloads(caplog, "security_audit_write_failed")[-1]

    assert payload["event_type"] == "audit_failure"
    assert payload["error_type"] == "RuntimeError"
    assert payload["metadata"]["password"] == "[redacted]"
    assert payload["metadata"]["token"] == "[redacted]"
    assert "database password leaked" not in logs
    assert "plain-password" not in logs
    assert "token-secret" not in logs


def test_required_audit_write_failure_raises_and_logs_sanitized_warning(app, caplog, monkeypatch):
    from app.security.audit import AuditWriteError, audit_event_required

    def fail_commit():
        raise RuntimeError("database password leaked")

    monkeypatch.setattr(db.session, "commit", fail_commit)
    caplog.set_level("WARNING", logger=app.logger.name)

    with app.test_request_context("/audit/required", method="POST"):
        with pytest.raises(AuditWriteError):
            audit_event_required(
                "banking_transaction_authorization",
                "approved",
                metadata={
                    "transaction_ref": "TXN-001",
                    "authorization": "Bearer token-secret",
                },
            )

    logs = "\n".join(record.getMessage() for record in caplog.records)
    payload = log_payloads(caplog, "security_audit_write_failed")[-1]

    assert payload["event_type"] == "banking_transaction_authorization"
    assert payload["metadata"]["authorization"] == "[redacted]"
    assert "database password leaked" not in logs
    assert "token-secret" not in logs


def test_webauthn_audit_wrapper_can_use_required_writer(monkeypatch):
    from app.security import audit as audit_module

    calls = []
    monkeypatch.setattr(
        audit_module,
        "audit_event_required",
        lambda event_type, outcome, **kwargs: calls.append((event_type, outcome, kwargs)),
    )
    monkeypatch.setattr(
        audit_module,
        "audit_event",
        lambda *_args, **_kwargs: pytest.fail("required WebAuthn audit must not use best-effort writer"),
    )

    audit_module.audit_webauthn_event("register", "success", credential_id=b"credential-id", required=True)

    assert calls
    assert calls[0][0] == "webauthn_register"
    assert calls[0][1] == "success"


def test_audit_system_writer_uses_append_only_runtime_read_path(app, monkeypatch):
    from app.security import audit as audit_module

    def reject_row_locks(execute_state):
        if getattr(execute_state.statement, "_for_update_arg", None) is not None:
            raise AssertionError("audit writer must not issue SELECT FOR UPDATE")

    sqlalchemy_event.listen(Session, "do_orm_execute", reject_row_locks)
    monkeypatch.setattr(db.engine.dialect, "name", "postgresql", raising=False)
    monkeypatch.setattr(audit_module, "_lock_audit_chain_for_insert", lambda: None)
    try:
        audit_module.audit_system_event(
            "runtime_audit_writer_probe",
            "success",
            metadata={"probe": "append_only_runtime"},
        )
    finally:
        sqlalchemy_event.remove(Session, "do_orm_execute", reject_row_locks)

    event = db.session.execute(
        db.select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "runtime_audit_writer_probe")
    ).scalar_one()
    verification = audit_module.verify_audit_hash_chain()

    assert event.outcome == "success"
    assert event.previous_event_hash == audit_module.AUDIT_CHAIN_START_HASH
    assert event.hash_algorithm == audit_module.AUDIT_HASH_ALGORITHM
    assert event.event_metadata["actor"] == "system"
    assert verification["valid"] is True
    assert verification["event_count"] == 1
    assert verification["latest_event_hash"] == event.event_hash


def test_audit_hash_chain_records_verifies_and_exports_anchor(app, tmp_path):
    from app.security.audit import audit_event, audit_log_anchor, verify_audit_hash_chain

    with app.test_request_context("/audit/chain-one", method="POST"):
        audit_event("chain_one", "success", metadata={"note": "top-secret-note"})
    with app.test_request_context("/audit/chain-two", method="POST"):
        audit_event("chain_two", "success", metadata={"note": "second"})

    events = db.session.query(SecurityAuditEvent).order_by(SecurityAuditEvent.id.asc()).all()
    first, second = events
    verification = verify_audit_hash_chain()
    anchor = audit_log_anchor()
    runner = app.test_cli_runner()
    verify_cli = runner.invoke(args=["verify-audit-log-chain"])
    anchor_cli = runner.invoke(args=["export-audit-log-anchor"])
    cli_anchor = json.loads(anchor_cli.output)
    anchor_path = tmp_path / "audit-anchor.json"
    anchor_path.write_text(json.dumps(anchor), encoding="utf-8")
    verify_anchor_cli = runner.invoke(args=["verify-audit-log-chain", "--anchor", str(anchor_path)])
    stale_anchor = dict(anchor)
    stale_anchor["latest_event_hash"] = "0" * 64
    stale_anchor_path = tmp_path / "stale-audit-anchor.json"
    stale_anchor_path.write_text(json.dumps(stale_anchor), encoding="utf-8")
    stale_anchor_cli = runner.invoke(
        args=["verify-audit-log-chain", "--anchor", str(stale_anchor_path)]
    )
    app.config["SECURITY_AUDIT_ANCHOR_PATH"] = str(anchor_path)
    matching_anchor_alert_cli = runner.invoke(
        args=["check-security-alerts", "--report-only", "--no-delivery"]
    )
    app.config["SECURITY_AUDIT_ANCHOR_PATH"] = str(stale_anchor_path)
    stale_anchor_alert_cli = runner.invoke(
        args=["check-security-alerts", "--report-only", "--no-delivery"]
    )
    strict_stale_anchor_alert_cli = runner.invoke(args=["check-security-alerts", "--no-delivery"])
    matching_anchor_report = json.loads(matching_anchor_alert_cli.output)
    stale_anchor_report = json.loads(stale_anchor_alert_cli.output)

    assert first.previous_event_hash == "0" * 64
    assert len(first.event_hash) == 64
    assert first.hash_algorithm == "hmac-sha256-v1"
    assert second.previous_event_hash == first.event_hash
    assert len(second.event_hash) == 64
    assert verification["valid"] is True
    assert verification["event_count"] == 2
    assert verification["latest_event_id"] == second.id
    assert verification["latest_event_hash"] == second.event_hash
    assert anchor["latest_event_id"] == second.id
    assert anchor["latest_event_hash"] == second.event_hash
    assert anchor["event_count"] == 2
    assert "top-secret-note" not in json.dumps(anchor)
    assert verify_cli.exit_code == 0, verify_cli.output
    assert json.loads(verify_cli.output)["valid"] is True
    assert anchor_cli.exit_code == 0, anchor_cli.output
    assert cli_anchor["latest_event_hash"] == second.event_hash
    assert "top-secret-note" not in anchor_cli.output
    assert verify_anchor_cli.exit_code == 0, verify_anchor_cli.output
    assert json.loads(verify_anchor_cli.output)["anchor_validated"] is True
    assert stale_anchor_cli.exit_code != 0
    assert "anchor_mismatch" in stale_anchor_cli.output
    assert matching_anchor_alert_cli.exit_code == 0, matching_anchor_alert_cli.output
    assert matching_anchor_report["audit_chain"]["anchor_validated"] is True
    assert not any(
        alert["alert_type"] == "audit_anchor_mismatch"
        for alert in matching_anchor_report["alerts"]
    )
    assert stale_anchor_alert_cli.exit_code == 0, stale_anchor_alert_cli.output
    assert stale_anchor_report["audit_chain"]["anchor_validated"] is False
    assert any(
        alert["alert_type"] == "audit_anchor_mismatch"
        for alert in stale_anchor_report["alerts"]
    )
    assert strict_stale_anchor_alert_cli.exit_code != 0
    assert "top-secret-note" not in stale_anchor_alert_cli.output


def test_audit_hash_chain_uses_hmac_key_and_reads_legacy_sha_rows(app):
    from app.security import audit as audit_module

    with app.test_request_context("/audit/hmac", method="POST"):
        audit_module.audit_event("chain_hmac", "success", metadata={"note": "keyed"})

    event = db.session.query(SecurityAuditEvent).one()
    original_hash = event.event_hash
    original_key = app.config["SECURITY_AUDIT_HMAC_KEY"]

    app.config["SECURITY_AUDIT_HMAC_KEY"] = "different-test-audit-hmac-key-that-is-long-enough"
    wrong_key = audit_module.verify_audit_hash_chain()
    app.config["SECURITY_AUDIT_HMAC_KEY"] = original_key

    event.hash_algorithm = audit_module.LEGACY_AUDIT_HASH_ALGORITHM
    event.event_hash = audit_module._compute_audit_event_hash(event)
    db.session.commit()
    legacy = audit_module.verify_audit_hash_chain()

    assert original_hash != event.event_hash
    assert wrong_key["valid"] is False
    assert "event_hash_mismatch" in {error["reason"] for error in wrong_key["errors"]}
    assert legacy["valid"] is True
    assert legacy["verified_event_count"] == 1


def test_audit_hash_chain_detects_metadata_link_missing_row_and_order_tampering(app):
    from sqlalchemy import text

    from app.security.alerts import build_security_alert_report
    from app.security.audit import audit_event, verify_audit_hash_chain

    with app.test_request_context("/audit/one", method="POST"):
        audit_event("chain_one", "success", metadata={"note": "one"})
    with app.test_request_context("/audit/two", method="POST"):
        audit_event("chain_two", "success", metadata={"note": "two"})
    with app.test_request_context("/audit/three", method="POST"):
        audit_event("chain_three", "success", metadata={"note": "three"})

    first, second, third = db.session.query(SecurityAuditEvent).order_by(SecurityAuditEvent.id.asc()).all()
    first.event_metadata = {"note": "tampered"}
    second.previous_event_hash = "1" * 64
    db.session.commit()

    tampered = verify_audit_hash_chain()
    tampered_alert_report = build_security_alert_report(deliver=False)
    tamper_reasons = {error["reason"] for error in tampered["errors"]}

    assert tampered["valid"] is False
    assert "event_hash_mismatch" in tamper_reasons
    assert "previous_hash_mismatch" in tamper_reasons
    assert any(
        alert["alert_type"] == "audit_chain_verification_failed"
        for alert in tampered_alert_report["alerts"]
    )
    assert "tampered" not in json.dumps(tampered_alert_report, sort_keys=True)

    db.session.delete(second)
    db.session.commit()
    missing_link = verify_audit_hash_chain()

    assert missing_link["valid"] is False
    assert any(error["event_id"] == third.id for error in missing_link["errors"])
    assert "previous_hash_mismatch" in {error["reason"] for error in missing_link["errors"]}

    db.session.execute(
        text("UPDATE security_audit_events SET id = :new_id WHERE id = :event_id"),
        {"new_id": third.id + 100, "event_id": first.id},
    )
    db.session.commit()
    reordered = verify_audit_hash_chain()

    assert reordered["valid"] is False
    assert "previous_hash_mismatch" in {error["reason"] for error in reordered["errors"]}


def test_security_alerts_detect_database_table_regression_from_external_state(app, tmp_path):
    from app.security.alerts import build_security_alert_report
    from app.security.audit import audit_event

    state_path = tmp_path / "security-alert-state.json"
    app.config["SECURITY_ALERT_STATE_PATH"] = str(state_path)
    user = User(
        username="alice01",
        email="alice@example.com",
        password_hash=hash_password("correct horse battery staple"),
    )
    db.session.add(user)
    db.session.commit()
    with app.test_request_context("/audit/baseline", method="POST"):
        audit_event("baseline", "success", user=user)

    baseline_report = build_security_alert_report(deliver=True)
    assert baseline_report["database_integrity"]["baseline_available"] is False
    assert state_path.exists()

    db.session.execute(db.delete(SecurityAuditEvent))
    db.session.execute(db.delete(User))
    db.session.commit()

    regression_report = build_security_alert_report(deliver=True)
    regression_alerts = [
        alert
        for alert in regression_report["alerts"]
        if alert["alert_type"] == "database_table_regression"
    ]
    regressed_sources = {alert["source"] for alert in regression_alerts}
    persisted_state = json.loads(state_path.read_text(encoding="utf-8"))

    assert regression_report["database_integrity"]["valid"] is False
    assert {"table:security_audit_events", "table:users"} <= regressed_sources
    assert persisted_state["tables"]["security_audit_events"]["count"] == 1
    assert persisted_state["tables"]["users"]["count"] == 1


def test_security_alert_evaluator_cli_and_output_are_sanitized(app):
    from app.security.alerts import evaluate_security_alerts
    from app.security.audit import audit_event, audit_reference, principal_reference

    raw_identifier = "Victim.User@example.com"
    raw_password = "plain-password"
    raw_token = "Bearer webhook-token-secret"
    raw_account = "1234 5678 9012 3456"
    raw_transaction = "TXN-SECRET-001"
    principal_ref = principal_reference(raw_identifier)
    transaction_ref = audit_reference("transaction", raw_transaction)

    with app.test_request_context(
        "/auth/login",
        method="POST",
        environ_overrides={"REMOTE_ADDR": "198.51.100.50"},
    ):
        for _attempt in range(10):
            audit_event(
                "login",
                "failure",
                metadata={"principal_ref": principal_ref, "password": raw_password},
            )
        for _attempt in range(5):
            audit_event("rate_limit", "blocked", metadata={"authorization": raw_token})
        audit_event("security_audit_write_failed", "failure", metadata={"token": raw_token})
        audit_event("account_lock", "locked", metadata={"reason": "mfa_failed"})
        audit_event("webauthn_clone_detected", "locked", metadata={"credential_id": "credential-ref"})
        audit_event("session_integrity", "failure", metadata={"reason": "invalid_signature"})

    with app.test_request_context(
        "/banking/transactions",
        method="POST",
        environ_overrides={"REMOTE_ADDR": "198.51.100.51"},
    ):
        for _attempt in range(10):
            audit_event(
                "banking_transaction_authorization",
                "failure",
                user_id=7,
                metadata={
                    "transaction_ref": transaction_ref,
                    "payee_account": raw_account,
                },
            )

    alerts = evaluate_security_alerts()
    alert_types = {alert["alert_type"] for alert in alerts}
    serialized_alerts = json.dumps(alerts, sort_keys=True)
    report_only = app.test_cli_runner().invoke(
        args=["check-security-alerts", "--report-only", "--no-delivery"]
    )
    strict = app.test_cli_runner().invoke(args=["check-security-alerts", "--no-delivery"])

    for expected in (
        "security_audit_write_failed",
        "account_lock",
        "webauthn_clone_detected",
        "session_integrity_failure",
        "login_failure_burst",
        "auth_backoff_or_rate_limit_burst",
        "transaction_failure_burst",
        "transaction_failure_global_burst",
    ):
        assert expected in alert_types
    for forbidden in (
        raw_identifier,
        raw_password,
        "webhook-token-secret",
        raw_account,
        raw_transaction,
    ):
        assert forbidden not in serialized_alerts
        assert forbidden not in report_only.output
    assert report_only.exit_code == 0, report_only.output
    assert json.loads(report_only.output)["alert_count"] >= len(alert_types)
    assert strict.exit_code != 0


def test_security_alert_webhook_delivery_is_sanitized(monkeypatch):
    from app.security.alerts import deliver_security_alerts

    captured = {}

    class FakeResponse:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["body"] = request.data.decode("utf-8")
        captured["user_agent"] = request.headers["User-agent"]
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("app.security.alerts.urllib.request.urlopen", fake_urlopen)
    alerts = [
        {
            "alert_type": "login_failure_burst",
            "severity": "high",
            "count": 10,
            "window_seconds": 300,
            "source": "principal_ref:abc123",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    ]
    result = deliver_security_alerts(
        alerts,
        webhook_url="https://hooks.example.test/services/secret-token",
    )
    serialized_result = json.dumps(result, sort_keys=True)

    assert result["attempted"] is True
    assert result["delivered"] is True
    assert captured["url"].endswith("/secret-token")
    assert captured["user_agent"] == "SITBank-SecurityAlerts/1.0"
    assert "secret-token" not in captured["body"]
    assert "secret-token" not in serialized_result

    def failing_urlopen(_request, timeout):
        del timeout
        raise RuntimeError("secret-token leaked by transport")

    monkeypatch.setattr("app.security.alerts.urllib.request.urlopen", failing_urlopen)
    failed = deliver_security_alerts(
        alerts,
        webhook_url="https://hooks.example.test/services/secret-token",
    )

    assert failed["delivered"] is False
    assert failed["error_type"] == "RuntimeError"
    assert "secret-token" not in json.dumps(failed, sort_keys=True)

    invalid_scheme = deliver_security_alerts(alerts, webhook_url="file:///tmp/secret-token")
    assert invalid_scheme["delivered"] is False
    assert invalid_scheme["error_type"] == "AlertConfigurationError"
    assert "secret-token" not in json.dumps(invalid_scheme, sort_keys=True)


def test_security_alert_webhook_delivery_redacts_final_payload_fields(monkeypatch):
    from app.security.alerts import deliver_security_alerts

    captured_bodies = []

    class FakeResponse:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

    def fake_urlopen(request, timeout):
        del timeout
        captured_bodies.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("app.security.alerts.urllib.request.urlopen", fake_urlopen)
    long_token = "alerttoken" + ("A1" * 24)
    private_key_marker = "BEGIN " + "PRIVATE KEY fake material"
    alert = {
        "alert_type": "manual_security_alert",
        "severity": "critical",
        "summary": "safe summary",
        "generated_at": "2026-06-19T08:00:00Z",
        "display_timestamp": "2026-06-19 16:00:00 UTC+8",
        "correlation_id": "corr-123",
        "public_session_ref": "public-session-ref-123",
        "safe_user_identifier": "user:7",
        "password": "plain-password",
        "Authorization": "Bearer authorization-secret",
        "cookie": "session=cookie-secret",
        "mfa_secret": "mfa-secret",
        "totp_secret": "totp-secret",
        "api_key": "api-secret",
        "private_key": private_key_marker,
        "database_url": "postgresql://user:postgres-password@db/sitbank",
        "redis_url": "redis://:redis-password@redis:6379/0",
        "webhook_url": "https://hooks.example.test/services/webhook-secret",
        "nested": {
            "refresh_token": long_token,
            "note": "safe nested note",
        },
        "list_values": [
            {"csrf_token": "csrf-secret"},
            "safe list note",
        ],
    }
    original_alert = json.loads(json.dumps(alert, sort_keys=True))

    generic = deliver_security_alerts(
        [alert],
        webhook_url="https://hooks.example.test/services/delivery-secret",
    )
    discord = deliver_security_alerts(
        [alert],
        webhook_url="https://discord.com/api/webhooks/123456789012345678/delivery-secret",
    )

    generic_payload = captured_bodies[0]
    discord_payload = captured_bodies[1]
    serialized_generic = json.dumps(generic_payload, sort_keys=True)
    serialized_discord = json.dumps(discord_payload, sort_keys=True)

    assert generic["delivered"] is True
    assert discord["delivered"] is True
    assert alert == original_alert
    delivered_alert = generic_payload["alerts"][0]
    assert delivered_alert["severity"] == "critical"
    assert delivered_alert["summary"] == "safe summary"
    assert delivered_alert["generated_at"] == "2026-06-19T08:00:00Z"
    assert delivered_alert["display_timestamp"] == "2026-06-19 16:00:00 UTC+8"
    assert delivered_alert["correlation_id"] == "corr-123"
    assert delivered_alert["public_session_ref"] == "public-session-ref-123"
    assert delivered_alert["safe_user_identifier"] == "user:7"
    assert delivered_alert["password"] == "[redacted]"
    assert delivered_alert["Authorization"] == "[redacted]"
    assert delivered_alert["cookie"] == "[redacted]"
    assert delivered_alert["mfa_secret"] == "[redacted]"
    assert delivered_alert["totp_secret"] == "[redacted]"
    assert delivered_alert["api_key"] == "[redacted]"
    assert delivered_alert["private_key"] == "[redacted]"
    assert delivered_alert["database_url"] == "[redacted]"
    assert delivered_alert["redis_url"] == "[redacted]"
    assert delivered_alert["webhook_url"] == "[redacted]"
    assert delivered_alert["nested"]["refresh_token"] == "[redacted]"
    assert delivered_alert["nested"]["note"] == "safe nested note"
    assert delivered_alert["list_values"][0]["csrf_token"] == "[redacted]"
    assert delivered_alert["list_values"][1] == "safe list note"
    assert discord_payload["allowed_mentions"] == {"parse": []}
    assert discord_payload["embeds"][0]["fields"][0]["name"] == "CRITICAL | manual_security_alert"
    for forbidden in (
        "plain-password",
        "authorization-secret",
        "cookie-secret",
        "mfa-secret",
        "totp-secret",
        "api-secret",
        "PRIVATE KEY fake material",
        "postgres-password",
        "redis-password",
        "webhook-secret",
        "delivery-secret",
        long_token,
    ):
        assert forbidden not in serialized_generic
        assert forbidden not in serialized_discord


def test_security_alert_delivery_formats_discord_webhooks(monkeypatch):
    from app.security.alerts import deliver_security_alerts

    captured = {}

    class FakeResponse:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

    def fake_urlopen(request, timeout):
        del timeout
        captured["body"] = request.data.decode("utf-8")
        captured["content_type"] = request.headers["Content-type"]
        captured["user_agent"] = request.headers["User-agent"]
        return FakeResponse()

    monkeypatch.setattr("app.security.alerts.urllib.request.urlopen", fake_urlopen)
    alerts = [
        {
            "alert_type": "login_failure_burst",
            "severity": "critical",
            "count": 10,
            "window_seconds": 300,
            "source": "principal_ref:abc123",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    ]
    result = deliver_security_alerts(
        alerts,
        webhook_url="https://discord.com/api/webhooks/123456789012345678/example-secret-token",
    )
    payload = json.loads(captured["body"])
    serialized_result = json.dumps(result, sort_keys=True)
    serialized_payload = json.dumps(payload, sort_keys=True)

    assert result["attempted"] is True
    assert result["delivered"] is True
    assert result["provider"] == "discord"
    assert captured["content_type"] == "application/json"
    assert captured["user_agent"] == "SITBank-SecurityAlerts/1.0"
    assert payload["allowed_mentions"] == {"parse": []}
    assert payload["content"] == "SITBank security alerts: 1 active"
    assert payload["embeds"][0]["title"] == "SITBank Security Alerts"
    assert payload["embeds"][0]["color"] == 0xD92D20
    assert "Date: " in payload["embeds"][0]["description"]
    assert "Time: " in payload["embeds"][0]["description"]
    assert "Timezone: UTC+8" in payload["embeds"][0]["description"]
    assert payload["embeds"][0]["fields"][0]["name"] == "CRITICAL | login_failure_burst"
    assert "Source: principal_ref:abc123" in payload["embeds"][0]["fields"][0]["value"]
    assert "Count: 10" in payload["embeds"][0]["fields"][0]["value"]
    assert "Window: 5 minute(s)" in payload["embeds"][0]["fields"][0]["value"]
    assert "example-secret-token" not in serialized_payload
    assert "example-secret-token" not in serialized_result


def test_security_alert_config_validation_and_redis_dedupe(app, monkeypatch):
    from app.security.alerts import (
        AlertConfigurationError,
        build_security_alert_report,
        validate_security_alert_config,
    )
    from app.security.audit import audit_event, principal_reference

    captured_bodies = []

    class FakeResponse:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

    def fake_urlopen(request, timeout):
        captured_bodies.append(json.loads(request.data.decode("utf-8")))
        assert timeout == 3.0
        return FakeResponse()

    app.config.update(
        SECURITY_ALERT_ENABLED=True,
        SECURITY_ALERT_WEBHOOK_URL="https://hooks.example.test/sitbank-security-alerts",
        SECURITY_ALERT_MIN_SEVERITY="high",
        SECURITY_ALERT_TIMEOUT_SECONDS=3.0,
        SECURITY_ALERT_DEDUPE_TTL_SECONDS=300,
    )
    monkeypatch.setattr("app.security.alerts.urllib.request.urlopen", fake_urlopen)

    with app.test_request_context(
        "/auth/login",
        method="POST",
        environ_overrides={"REMOTE_ADDR": "198.51.100.90"},
    ):
        principal_ref = principal_reference("victim@example.com")
        for _attempt in range(10):
            audit_event("login", "failure", metadata={"principal_ref": principal_ref})

    first_report = build_security_alert_report(deliver=True)
    second_report = build_security_alert_report(deliver=True)
    with app.test_request_context("/ops/check", method="POST"):
        audit_event("account_lock", "locked", metadata={"reason": "mfa_failed"})
    third_report = build_security_alert_report(deliver=True)

    assert first_report["delivery"]["attempted"] is True
    assert first_report["dedupe"]["suppressed"] == 0
    assert second_report["delivery"]["deduped"] is True
    assert second_report["dedupe"]["suppressed"] >= 1
    assert third_report["delivery"]["attempted"] is True
    assert len(captured_bodies) == 2

    with pytest.raises(AlertConfigurationError, match="WEBHOOK"):
        validate_security_alert_config(
            require_delivery=True,
            environ={"APP_ENV": "production", "SECURITY_ALERT_ENABLED": "true"},
        )
    with pytest.raises(AlertConfigurationError, match="HTTPS"):
        validate_security_alert_config(
            require_delivery=True,
            environ={
                "APP_ENV": "production",
                "SECURITY_ALERT_ENABLED": "true",
                "SECURITY_ALERT_WEBHOOK_URL": "http://hooks.example.test/insecure",
            },
        )
    with pytest.raises(AlertConfigurationError, match="MIN_SEVERITY"):
        validate_security_alert_config(environ={"SECURITY_ALERT_MIN_SEVERITY": "urgent"})
    with pytest.raises(AlertConfigurationError, match="TIMEOUT"):
        validate_security_alert_config(environ={"SECURITY_ALERT_TIMEOUT_SECONDS": "0"})
    with pytest.raises(AlertConfigurationError, match="DEDUPE"):
        validate_security_alert_config(environ={"SECURITY_ALERT_DEDUPE_TTL_SECONDS": "1"})


def test_500_handler_logs_sanitized_context(app, client, caplog):
    app.config["PROPAGATE_EXCEPTIONS"] = False

    @app.post("/explode")
    def explode():
        raise RuntimeError("boom")

    caplog.set_level("ERROR", logger=app.logger.name)
    response = client.post(
        "/explode?password=query-secret",
        data={"password": "form-secret"},
        headers={
            "Authorization": "Bearer header-secret",
            "Cookie": "session=cookie-secret",
        },
    )

    logs = "\n".join(record.getMessage() for record in caplog.records)
    payload = log_payloads(caplog, "system_error")[-1]

    assert response.status_code == 500
    assert payload["path"] == "/explode"
    assert payload["method"] == "POST"
    assert payload["exception_type"] == "RuntimeError"
    assert payload["correlation_id"]
    for forbidden in (
        "query-secret",
        "form-secret",
        "header-secret",
        "cookie-secret",
    ):
        assert forbidden not in logs


def test_webauthn_browser_errors_are_sanitized_before_display():
    source = Path("app/static/js/webauthn.js").read_text(encoding="utf-8")

    assert "Security key verification was not completed. Try again." in source
    assert "showError(errorNode, error.message)" not in source
    assert "webAuthnErrorMessage(error)" in source


def test_production_env_docs_require_pbkdf2_pepper_not_bcrypt():
    required = Path("ops/production-env.required").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")

    for setting in (
        "APP_ENV",
        "WTF_CSRF_SECRET_KEY",
        "SESSION_HMAC_ACTIVE_KEY_ID",
        "SESSION_HMAC_KEYS_JSON",
        "PASSWORD_PEPPER_B64",
        "PASSWORD_PBKDF2_ITERATIONS",
        "SECURITY_AUDIT_HMAC_KEY",
        "HIBP_CIRCUIT_FAILURE_THRESHOLD",
        "HIBP_CIRCUIT_OPEN_SECONDS",
        "SECURITY_ALERT_STATE_PATH",
        "WEBAUTHN_APPROVED_AAGUIDS_PATH",
        "WEBAUTHN_MDS_CACHE_PATH",
    ):
        assert setting in required
        assert setting in readme
    assert "BCRYPT_ROUNDS" not in required
    assert "BCRYPT_ROUNDS" not in readme


def test_checked_in_fido_allowlist_is_not_empty_or_test_placeholder():
    approved = json.loads(Path("ops/fido-approved-aaguids.json").read_text(encoding="utf-8"))
    cache = json.loads(Path("ops/fido-mds-cache.json").read_text(encoding="utf-8"))
    approved_aaguids = approved["approved_aaguids"]
    legacy_level1_aaguids = approved.get("legacy_level1_approved_aaguids", [])
    configured_aaguids = approved_aaguids + legacy_level1_aaguids
    cache_aaguids = {entry["aaguid"] for entry in cache["entries"]}

    assert len(configured_aaguids) >= 1
    assert "11111111-1111-1111-1111-111111111111" not in configured_aaguids
    assert set(approved_aaguids).issubset(cache_aaguids)
    assert "2fc0579f-8113-47ea-b116-bb5a8db9202a" in legacy_level1_aaguids


def test_future_transaction_payload_guardrails_reject_server_controlled_fields():
    from app.auth.services import AuthError
    from app.banking.services import validate_public_transaction_payload

    with pytest.raises(AuthError):
        validate_public_transaction_payload(
            {
                "idempotency_key": "11111111-1111-4111-8111-111111111111",
                "amount": "10.00",
                "account_id": "acct-1",
            }
        )
    with pytest.raises(AuthError):
        validate_public_transaction_payload({"amount": "10.00", "currency": "SGD"})
    with pytest.raises(AuthError):
        validate_public_transaction_payload(
            {
                "idempotency_key": "22222222-2222-4222-8222-222222222222",
                "amount": "10.00",
                "currency": "SGD",
                "payee": "PAYEE-001",
                "memo": "unexpected public field",
            }
        )

    normalized = validate_public_transaction_payload(
        {
            "idempotency_key": " 33333333-3333-4333-8333-333333333333 ",
            "amount": "10.00",
            "currency": "sgd",
            "payee": " payee-001 ",
        }
    )

    assert normalized["idempotency_key"] == "33333333-3333-4333-8333-333333333333"
    assert normalized["currency"] == "SGD"
    assert normalized["payee"] == "PAYEE-001"


def test_public_transaction_payload_business_rules_reject_unsafe_values():
    from app.auth.services import AuthError
    from app.banking.services import validate_public_transaction_payload

    valid = {
        "idempotency_key": "44444444-4444-4444-8444-444444444444",
        "amount": "10.00",
        "currency": "SGD",
        "payee": "PAYEE-001",
    }

    invalid_cases = [
        {**valid, "amount": "50000.01"},
        {**valid, "amount": "10.001"},
        {**valid, "amount": "0.00"},
        {**valid, "amount": "NaN"},
        {**valid, "currency": "USD"},
        {**valid, "payee": "../etc/passwd"},
        {**valid, "idempotency_key": "not-a-uuid"},
    ]

    for payload in invalid_cases:
        with pytest.raises(AuthError):
            validate_public_transaction_payload(payload)


def test_public_transaction_idempotency_binds_key_to_exact_payload():
    from app.auth.services import AuthError
    from app.banking.services import validate_public_transaction_payload

    store = {}
    payload = {
        "idempotency_key": "55555555-5555-4555-8555-555555555555",
        "amount": "25.00",
        "currency": "SGD",
        "payee": "PAYEE-002",
    }

    first = validate_public_transaction_payload(payload, idempotency_store=store)
    replay = validate_public_transaction_payload(dict(payload), idempotency_store=store)

    with pytest.raises(AuthError):
        validate_public_transaction_payload(
            {**payload, "amount": "30.00"},
            idempotency_store=store,
        )

    assert first == replay


def test_banking_transaction_approval_uses_required_audit_writer(monkeypatch):
    from app.banking import services as banking_services

    calls = []
    monkeypatch.setattr(
        banking_services,
        "audit_event_required",
        lambda event_type, outcome, **kwargs: calls.append((event_type, outcome, kwargs)),
    )
    monkeypatch.setattr(
        banking_services,
        "audit_event",
        lambda *_args, **_kwargs: pytest.fail("approval audit must be required"),
    )

    banking_services.audit_transaction_authorization(
        None,
        "approved",
        metadata={"decision": "approved"},
        transaction_reference="TXN-001",
    )

    assert calls
    assert calls[0][0] == "banking_transaction_authorization"
    assert calls[0][1] == "approved"
    assert calls[0][2]["metadata"]["decision"] == "approved"


def test_public_transaction_validation_audits_sanitized_success_and_failure(app):
    from app.auth.services import AuthError
    from app.banking.services import validate_public_transaction_payload

    with app.test_request_context("/banking/transactions", method="POST"):
        with pytest.raises(AuthError):
            validate_public_transaction_payload(
                {
                    "idempotency_key": "66666666-6666-4666-8666-666666666666",
                    "amount": "10.00",
                    "currency": "SGD",
                    "payee": "PAYEE-001",
                    "account_id": "server-controlled",
                }
            )
        validate_public_transaction_payload(
            {
                "idempotency_key": "77777777-7777-4777-8777-777777777777",
                "amount": "25.00",
                "currency": "SGD",
                "payee": "PAYEE-002",
            }
        )

    failure = (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="banking_public_transaction_validation", outcome="failure")
        .one()
    )
    success = (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="banking_public_transaction_validation", outcome="success")
        .one()
    )
    serialized = json.dumps([failure.event_metadata, success.event_metadata], sort_keys=True)

    assert failure.event_metadata["reason"] == "schema_validation_failed"
    assert "account_id" in failure.event_metadata["rejected_fields"]
    assert success.event_metadata["transaction_amount"] == "25.00"
    assert success.event_metadata["transaction_currency"] == "SGD"
    assert len(success.event_metadata["payload_hash_ref"]) == 32
    assert len(success.event_metadata["idempotency_key_ref"]) == 32
    assert len(success.event_metadata["payee_account_ref"]) == 32
    assert "66666666-6666-4666-8666-666666666666" not in serialized
    assert "77777777-7777-4777-8777-777777777777" not in serialized
    assert "PAYEE-001" not in serialized
    assert "PAYEE-002" not in serialized


def test_health_endpoints_report_liveness_and_dependency_readiness(app, client, monkeypatch):
    live = client.get("/health/live")
    ready = client.get("/health/ready")

    assert live.status_code == 200
    assert live.get_json() == {"status": "ok"}
    assert ready.status_code == 200
    assert ready.get_json() == {"status": "ready"}

    monkeypatch.setattr(
        app.extensions["redis"],
        "ping",
        lambda: (_ for _ in ()).throw(ConnectionError("offline")),
    )
    unavailable = client.get("/health/ready")

    assert unavailable.status_code == 503
    assert unavailable.get_json() == {"status": "unavailable"}
