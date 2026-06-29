from __future__ import annotations

from _auth_flow_helpers import *


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
    assert b"alice@sit.singaporetech.edu.sg" in response.data
    assert 'name="username"' in markup
    assert 'name="email"' in markup
    assert "Update profile details" in markup
    assert "Verify and save" in markup
    assert "Authenticator MFA required" not in markup
    assert "Manage passkeys" not in markup
    assert "Manage MFA" in markup
    assert "Change password" in markup
    assert 'aria-disabled="true">Change password' not in markup
    assert 'href="/password/change"' in markup
    assert "profile-status-copy" in markup
    assert "Use an authenticator app for login MFA." in markup
    assert 'href="/security-keys"' not in markup
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
    mark_recent_mfa(client, user)
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
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(change_time),
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
    assert new_login.status_code == 302
    assert new_login.headers["Location"].endswith("/mfa/verify")
    assert revoked_response.status_code == 401
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="password_change", outcome="success").count() == 1

def test_password_change_accepts_totp_stepup_without_passkey(client, monkeypatch):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    old_hash = user.password_hash
    change_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: change_time)

    response = client.post(
        "/password/change",
        data={
            "current_password": "correct horse battery staple",
            "new_password": "new correct horse battery staple",
            "confirm_new_password": "new correct horse battery staple",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(change_time),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 302
    assert user.password_hash != old_hash

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


def test_password_change_uses_configured_new_password_minimum(app, client):
    app.config["PASSWORD_MIN_LENGTH"] = 12
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    old_hash = user.password_hash

    response = client.post(
        "/password/change",
        data={
            "current_password": "correct horse battery staple",
            "new_password": "Abcdef12345",
            "confirm_new_password": "Abcdef12345",
        },
    )
    db.session.refresh(user)

    assert response.status_code == 400
    assert b"Field must be at least 12 characters long." in response.data
    assert user.password_hash == old_hash


def test_password_change_rejects_common_or_reused_password(client, monkeypatch):
    current_password = "correct horse battery staple"
    register_response = register(client, password=current_password)
    login_response = login(client, password=current_password)
    assert register_response.status_code == 302
    assert login_response.status_code == 302

    user, secret = enable_mfa_for_user()
    add_security_keys_for_user(user)
    mark_recent_mfa(client, user)

    reused_response = client.post(
        "/password/change",
        data={
            "current_password": current_password,
            "new_password": current_password,
            "confirm_new_password": current_password,
        },
    )
    stepup_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)
    common_response = client.post(
        "/password/change",
        data={
            "current_password": current_password,
            "new_password": "password",
            "confirm_new_password": "password",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(stepup_time),
        },
    )

    assert reused_response.status_code == 400
    assert common_response.status_code == 400

def test_profile_details_update_succeeds_for_authenticated_user(client, monkeypatch):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    stepup_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)

    response = client.post(
        "/profile",
        data={
            "username": "alice02",
            "email": "alice.new@example.com",
            "mfa_step_up_preference": "totp",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(stepup_time),
        },
    )
    db.session.refresh(user)
    client.post("/logout")
    new_username_login = login(client, identifier="alice02")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/profile")
    assert user.username == "alice02"
    assert user.email == "alice.new@example.com"
    assert new_username_login.status_code == 302
    assert new_username_login.headers["Location"].endswith("/mfa/verify")
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="profile_update", outcome="success").count() == 1

def test_profile_email_update_rejects_passkey_stepup_token(client):
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
            "mfa_step_up_preference": "totp",
            "stepup_token": mint_stepup_token(client, user, "profile_update"),
        },
    )
    db.session.refresh(user)
    with client.session_transaction() as sess:
        session_after_update = sess.sid

    assert response.status_code == 403
    assert session_after_update == session_before_update
    assert user.email == "alice@sit.singaporetech.edu.sg"
    assert b"Enter an authenticator code to verify this action" in response.data

def test_profile_email_update_accepts_totp_stepup_without_passkey(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice.mfa@example.com",
            "mfa_step_up_preference": "totp",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 302
    assert user.email == "alice.mfa@example.com"


def test_profile_preference_rejects_passkey_when_not_enrolled(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice@sit.singaporetech.edu.sg",
            "mfa_step_up_preference": "passkey",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.mfa_step_up_preference == "totp"
    assert b"Passkey verification preference is no longer available" in response.data


def test_legacy_passkey_does_not_unlock_profile_without_totp(client):
    register(client)
    login(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    add_security_keys_for_user(user)
    user.mfa_step_up_preference = "passkey"
    db.session.commit()

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice.passkey@example.com",
            "mfa_step_up_preference": "totp",
            "stepup_token": mint_stepup_token(client, user, "profile_update"),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mfa/setup")
    assert user.email == "alice@sit.singaporetech.edu.sg"
    assert user.mfa_step_up_preference == "passkey"


def test_profile_update_rejects_invalid_email(client):
    register(client)
    login(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    mark_recent_mfa(client, user)

    response = client.post(
        "/profile",
        data={"username": "alice01", "email": "not-an-email", "mfa_step_up_preference": "totp"},
    )
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.email == "alice@sit.singaporetech.edu.sg"

def test_profile_update_rejects_invalid_username(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()

    response = client.post(
        "/profile",
        data={"username": "bad user", "email": "alice@sit.singaporetech.edu.sg", "mfa_step_up_preference": "totp"},
    )
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.username == "alice01"

def test_profile_update_rejects_duplicate_username(client):
    register(client)
    register(client, username="bob02", email="bob@sit.singaporetech.edu.sg", full_name="Bob Test", phone_number="81234567")
    login(client)
    user, _secret = enable_mfa_for_user()

    response = client.post(
        "/profile",
        data={"username": "BOB02", "email": "alice@sit.singaporetech.edu.sg", "mfa_step_up_preference": "totp"},
    )
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.username == "alice01"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="profile_update", outcome="failure").count() == 1

def test_profile_update_rejects_duplicate_email(client):
    register(client)
    register(client, username="bob02", email="bob@sit.singaporetech.edu.sg", full_name="Bob Test", phone_number="81234567")
    login(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    mark_recent_mfa(client, user)

    response = client.post(
        "/profile",
        data={"username": "alice01", "email": "bob@sit.singaporetech.edu.sg", "mfa_step_up_preference": "totp"},
    )
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.email == "alice@sit.singaporetech.edu.sg"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="profile_update", outcome="failure").count() == 1

def test_profile_post_requires_csrf_when_enabled(app, client):
    register(client)
    login(client)
    original = app.config["WTF_CSRF_ENABLED"]
    app.config["WTF_CSRF_ENABLED"] = True

    try:
        response = client.post(
            "/profile",
            data={"username": "alice02", "email": "alice.new@example.com", "mfa_step_up_preference": "totp"},
        )
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
    register(client, username="bob02", email="bob@sit.singaporetech.edu.sg", full_name="Bob Test", phone_number="81234567")
    login(client)
    user, secret = enable_mfa_for_user()
    other_user = db.session.execute(db.select(User).where(User.username == "bob02")).scalar_one()
    original_password_hash = user.password_hash

    response = client.post(
        "/profile",
        data={
            "username": "alice02",
            "email": "alice.new@example.com",
            "mfa_step_up_preference": "totp",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
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
    assert other_user.email == "bob@sit.singaporetech.edu.sg"

def test_high_risk_stepup_token_is_rejected(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    token = mint_stepup_token(client, user, "profile_update")

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice.stepup@example.com",
            "mfa_step_up_preference": "totp",
            "stepup_token": token,
        },
    )
    db.session.refresh(user)

    assert response.status_code == 403
    assert user.email == "alice@sit.singaporetech.edu.sg"
    event = db.session.query(SecurityAuditEvent).filter_by(event_type="profile_update", outcome="failure").first()
    assert event is not None
    assert event.event_metadata["reason"] == "passkey_step_up_disabled"

def test_high_risk_action_without_passkey_accepts_totp_stepup(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice.needs-keys@example.com",
            "mfa_step_up_preference": "totp",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 302
    assert user.email == "alice.needs-keys@example.com"

def test_totp_user_without_passkeys_can_navigate_and_use_high_risk_forms(client):
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
    assert password_response.status_code == 200
    assert freeze_response.status_code == 200
    assert b"Security keys required" not in profile_response.data
    assert b"Security keys required" not in sessions_response.data
    assert b"Security keys required" not in freeze_response.data

def test_security_key_page_inline_totp_refresh_is_disabled(client, monkeypatch):
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
    assert b"Passkeys are unavailable" in stale_page.data
    assert b"Register passkey</button>" not in stale_page.data
    assert b"Register passkey</button>" not in fresh_page.data
    assert refresh_response.status_code == 302
    assert refresh_response.headers["Location"].endswith("/security-keys")
    assert session_after_refresh == session_before_refresh
    assert fresh_mfa_verified_at is None
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="webauthn_mfa_refresh", outcome="mfa_success").count() == 0

def test_security_key_inline_totp_refresh_does_not_run_risk_stepup(client):
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
    assert response.headers["Location"].endswith("/security-keys")
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="session_risk", outcome="step_up_required").count() == 0
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="webauthn_mfa_refresh", outcome="mfa_success").count() == 0

def test_session_risk_drift_requires_reauth_before_sensitive_action(client):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    with client.session_transaction() as sess:
        sess["risk_fingerprint"] = "tampered"

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice.drift@example.com",
            "mfa_step_up_preference": "totp",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 401
    assert b"Session verification required. Please sign in again." in response.data
    assert user.email == "alice@sit.singaporetech.edu.sg"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="session_risk", outcome="step_up_required").count() == 1
