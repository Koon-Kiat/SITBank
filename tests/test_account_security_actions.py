from __future__ import annotations

from _auth_flow_helpers import *


def proxy_edge_context(edge_ip: str, client_ip: str = "198.51.100.10") -> dict:
    return {
        "environ_overrides": {"REMOTE_ADDR": edge_ip},
        "headers": {
            "X-Forwarded-For": client_ip,
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "sitbank.pp.ua",
            "User-Agent": "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",
        },
    }


def test_account_freeze_is_durable_and_blocks_group_a_sensitive_actions(client):
    from app.auth.services import FrozenAccountError
    from app.banking.services import ensure_outbound_transfer_allowed
    from app.security.crypto import encrypt_mfa_secret
    from app.security.email import password_reset_outbox

    register(client)
    login(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    db.session.commit()

    response = client.post(
        "/account/freeze",
        data={
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 302
    assert user.is_frozen is True
    assert password_reset_outbox()[-1]["to"] == "alice@example.com"
    assert password_reset_outbox()[-1]["subject"] == "SITBank account frozen"
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
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="account_freeze_notification",
        outcome="queued",
        user_id=user.id,
    ).count() == 1

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
    assert keys_response.status_code == 404
    assert freeze_response.status_code == 302


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/auth/password-reset/mfa/webauthn/options"),
        ("post", "/auth/password-reset/mfa/webauthn/verify"),
        ("post", "/auth/webauthn/register/options"),
        ("post", "/auth/webauthn/register/verify"),
        ("post", "/auth/webauthn/authenticate/options"),
        ("post", "/auth/webauthn/authenticate/verify"),
        ("post", "/auth/webauthn/step-up/options"),
        ("post", "/auth/webauthn/step-up/verify"),
        ("get", "/auth/webauthn/credentials"),
        ("delete", "/auth/webauthn/credentials/credential-id"),
        ("get", "/security-keys"),
        ("post", "/security-keys/mfa/refresh"),
        ("post", "/security-keys/credential-id/revoke"),
    ],
)
def test_removed_browser_credential_routes_return_404(client, method, path):
    response = getattr(client, method)(path)

    assert response.status_code == 404


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
    assert b"91234567" in response.data
    assert 'name="username"' not in markup
    assert 'name="email"' in markup
    assert 'name="phone_number"' in markup
    assert "Update profile details" in markup
    assert "Verify and save" in markup
    assert "Authenticator MFA required" not in markup
    assert "Manage MFA" in markup
    assert "Change password" in markup
    assert 'aria-disabled="true">Change password' not in markup
    assert 'href="/password/change"' in markup
    assert "profile-status-copy" in markup
    assert "Use an authenticator app for login MFA." in markup
    assert 'class="badge warning"' not in markup
    assert "Preferred verification" not in markup

def test_profile_enables_change_password_action_after_mfa_setup(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()

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
    current_session_response = client.get("/auth/sessions")
    client.post("/logout")
    old_login = login(client)
    clear_failures("login", "127.0.0.1:alice01")
    new_login = login(client, password="new correct horse battery staple")
    revoked_response = second_client.get("/auth/sessions")

    assert response.status_code == 302
    assert current_session_response.status_code == 401
    assert user.password_hash != old_hash
    assert old_login.status_code == 401
    assert new_login.status_code == 302
    assert new_login.headers["Location"].endswith("/mfa/verify")
    assert revoked_response.status_code == 401
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="password_change", outcome="success").count() == 1

def test_password_change_accepts_totp_stepup(client, monkeypatch):
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


def test_password_change_rejects_recent_password_history(client, monkeypatch):
    register(client)
    user, secret = enable_mfa_for_user()
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    current_password = "correct horse battery staple"
    first_new_password = "new correct horse battery staple"
    second_new_password = "another correct horse battery staple"
    base_time = int(time.time())

    def mfa_login(password, timestamp):
        assert login(client, password=password).status_code == 302
        monkeypatch.setattr("app.auth.services.time.time", lambda: timestamp)
        response = client.post(
            "/auth/mfa/verify",
            json={"totp_code": totp.at(timestamp)},
        )
        assert response.status_code == 200

    def change_password_to(old_password, new_password, timestamp):
        monkeypatch.setattr("app.auth.services.time.time", lambda: timestamp)
        response = client.post(
            "/password/change",
            data={
                "current_password": old_password,
                "new_password": new_password,
                "confirm_new_password": new_password,
                "totp_code": totp.at(timestamp),
            },
        )
        assert response.status_code == 302

    mfa_login(current_password, base_time)
    change_password_to(current_password, first_new_password, base_time + 30)
    mfa_login(first_new_password, base_time + 60)
    change_password_to(first_new_password, second_new_password, base_time + 90)
    mfa_login(second_new_password, base_time + 120)
    monkeypatch.setattr("app.auth.services.time.time", lambda: base_time + 150)

    reused_response = client.post(
        "/password/change",
        data={
            "current_password": second_new_password,
            "new_password": current_password,
            "confirm_new_password": current_password,
            "totp_code": totp.at(base_time + 150),
        },
    )
    db.session.refresh(user)

    assert reused_response.status_code == 400
    assert verify_password(second_new_password, user.password_hash)


def test_forced_password_change_blocks_normal_routes_until_password_changed(client, monkeypatch):
    from app.security.password_history import require_forced_password_change

    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    require_forced_password_change(user, "compromised_password")
    db.session.commit()
    change_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: change_time)

    blocked_dashboard = client.get("/dashboard")
    password_page = client.get("/password/change")
    change_response = client.post(
        "/password/change",
        data={
            "current_password": "correct horse battery staple",
            "new_password": "new correct horse battery staple",
            "confirm_new_password": "new correct horse battery staple",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(change_time),
        },
    )
    db.session.refresh(user)

    assert blocked_dashboard.status_code == 403
    assert b"Password change required" in blocked_dashboard.data
    assert password_page.status_code == 200
    assert change_response.status_code == 302
    assert user.force_password_change is False
    assert user.force_password_change_reason is None

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
            "email": "alice@example.com",
            "phone_number": "92345678",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(stepup_time),
        },
    )
    db.session.refresh(user)
    client.post("/logout")
    original_username_login = login(client, identifier="alice01")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/profile")
    assert user.username == "alice01"
    assert user.email == "alice@example.com"
    assert user.phone_number == "92345678"
    assert original_username_login.status_code == 302
    assert original_username_login.headers["Location"].endswith("/mfa/verify")
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="profile_update", outcome="success").count() == 1


def test_profile_phone_update_succeeds_after_clean_password_totp_login(client, monkeypatch):
    register(client)
    user, secret = enable_mfa_for_user()
    password_response = login(client)
    login_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: login_time)
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(login_time)},
    )

    stepup_time = login_time + 31
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)
    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice@example.com",
            "phone_number": "92345678",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(stepup_time),
        },
    )
    db.session.refresh(user)

    assert password_response.status_code == 302
    assert mfa_response.status_code == 200
    assert response.status_code == 302
    assert user.phone_number == "92345678"
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk",
        outcome="reauth_required",
    ).count() == 0


def test_cloudflare_edge_change_keeps_sensitive_totp_actions_stable(monkeypatch):
    from app import create_app
    from app.security import passwords
    from conftest import TestConfig

    class ProxyTestConfig(TestConfig):
        TRUSTED_PROXY_COUNT = 1

    monkeypatch.setattr(
        passwords,
        "_is_password_pwned_by_hibp",
        lambda _password: False,
    )
    flask_app = create_app(ProxyTestConfig)
    with flask_app.app_context():
        db.create_all()
        try:
            proxy_client = flask_app.test_client()
            register(proxy_client)
            user, secret = enable_mfa_for_user()

            login_time = 1_800_000_000
            monkeypatch.setattr("app.auth.services.time.time", lambda: login_time)
            password_response = proxy_client.post(
                "/login",
                data={
                    "identifier": user.username,
                    "password": "correct horse battery staple",
                },
                **proxy_edge_context("173.245.48.10"),
            )
            mfa_response = proxy_client.post(
                "/auth/mfa/verify",
                json={
                    "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(
                        login_time
                    )
                },
                **proxy_edge_context("173.245.48.10"),
            )

            profile_time = login_time + 31
            monkeypatch.setattr("app.auth.services.time.time", lambda: profile_time)
            profile_response = proxy_client.post(
                "/profile",
                data={
                    "username": "alice01",
                    "email": "alice@example.com",
                    "phone_number": "92345678",
                    "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(
                        profile_time
                    ),
                },
                **proxy_edge_context("173.245.48.11"),
            )

            recovery_time = login_time + 62
            monkeypatch.setattr("app.auth.services.time.time", lambda: recovery_time)
            recovery_response = proxy_client.post(
                "/auth/mfa/recovery-codes/regenerate",
                json={
                    "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(
                        recovery_time
                    )
                },
                **proxy_edge_context("173.245.48.12"),
            )

            replace_time = login_time + 93
            monkeypatch.setattr("app.auth.services.time.time", lambda: replace_time)
            replace_response = proxy_client.post(
                "/auth/mfa/replace/start",
                json={
                    "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(
                        replace_time
                    )
                },
                **proxy_edge_context("173.245.48.13"),
            )
            db.session.refresh(user)

            assert password_response.status_code == 302
            assert mfa_response.status_code == 200
            assert profile_response.status_code == 302
            assert user.phone_number == "92345678"
            assert recovery_response.status_code == 200
            assert recovery_response.get_json()["recovery_codes"]
            assert replace_response.status_code == 200
            assert replace_response.get_json()["manual_entry_secret"]
            assert db.session.query(SecurityAuditEvent).filter_by(
                event_type="session_risk",
                outcome="reauth_required",
            ).count() == 0
            assert db.session.query(SecurityAuditEvent).filter_by(
                event_type="session_risk",
                outcome="step_up_required",
            ).count() == 0
        finally:
            db.session.remove()
            db.drop_all()
            db.engine.dispose()


def test_profile_email_update_requires_email_code_and_totp_stepup(client, monkeypatch):
    from app.security.email import password_reset_outbox

    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    request_time = int(time.time())
    commit_time = request_time + 30
    monkeypatch.setattr("app.auth.services.time.time", lambda: request_time)

    request_response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice.mfa@example.com",
            "phone_number": "91234567",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(request_time),
        },
    )
    db.session.refresh(user)

    body = password_reset_outbox()[-1]["body"]
    match = re.search(r"\b([0-9]{6})\b", body)
    assert match is not None
    assert request_response.status_code == 200
    assert user.email == "alice@example.com"

    monkeypatch.setattr("app.auth.services.time.time", lambda: commit_time)
    commit_response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice.mfa@example.com",
            "phone_number": "91234567",
            "email_verification_code": match.group(1),
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(commit_time),
        },
    )
    db.session.refresh(user)

    assert commit_response.status_code == 302
    assert user.email == "alice.mfa@example.com"


def test_profile_phone_update_succeeds_without_raw_phone_audit_metadata(client, monkeypatch):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    stepup_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice@example.com",
            "phone_number": "92345678",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(stepup_time),
        },
    )
    db.session.refresh(user)
    event = db.session.query(SecurityAuditEvent).filter_by(event_type="profile_update", outcome="success").one()

    assert response.status_code == 302
    assert user.phone_number == "92345678"
    assert event.event_metadata == {"updated_fields": "profile_phone"}
    assert "92345678" not in str(event.event_metadata)


def test_profile_phone_update_rejects_missing_context_even_with_matching_legacy_fingerprint(
    client,
    monkeypatch,
):
    from app.security.sessions import SESSION_RISK_CONTEXT_KEY, SESSION_RISK_FINGERPRINT_KEY

    register(client)
    user, secret = enable_mfa_for_user()
    password_response = login(client)
    login_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: login_time)
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(login_time)},
    )
    with client.session_transaction() as sess:
        assert sess.get(SESSION_RISK_FINGERPRINT_KEY)
        sess.pop(SESSION_RISK_CONTEXT_KEY)

    stepup_time = login_time + 1
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)
    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice@example.com",
            "phone_number": "92345678",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(stepup_time),
        },
    )
    db.session.refresh(user)

    assert password_response.status_code == 302
    assert mfa_response.status_code == 200
    assert response.status_code == 401
    assert user.phone_number == "91234567"
    assert db.session.query(SecurityAuditEvent).filter_by(
        event_type="session_risk",
        outcome="reauth_required",
    ).count() == 1


def test_profile_update_rejects_invalid_phone(client):
    register(client)
    login(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    mark_recent_mfa(client, user)

    response = client.post(
        "/profile",
        data={"username": "alice01", "email": "alice@example.com", "phone_number": "71234567"},
    )
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.phone_number == "91234567"


def test_profile_update_rejects_unicode_digit_lookalike_phone_in_service_layer(client):
    from app.auth.services import AuthError, _profile_update_values

    register(client)
    user = db.session.execute(
        db.select(User).where(User.username == "alice01")
    ).scalar_one()

    with client.application.test_request_context("/profile", method="POST"):
        with pytest.raises(AuthError):
            _profile_update_values(
                user,
                user.username,
                user.email,
                "9１２３４５６７",
            )

    db.session.refresh(user)
    assert user.phone_number == "91234567"


def test_profile_update_rejects_invalid_email(client):
    register(client)
    login(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    mark_recent_mfa(client, user)

    response = client.post(
        "/profile",
        data={"username": "alice01", "email": "not-an-email", "phone_number": "91234567"},
    )
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.email == "alice@example.com"


def test_profile_update_rejects_admin_domain_customer_email(client):
    register(client)
    login(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    mark_recent_mfa(client, user)

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice@sit.singaporetech.edu.sg",
            "phone_number": "91234567",
        },
    )
    db.session.refresh(user)
    event = (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="profile_update", outcome="blocked")
        .one()
    )

    assert response.status_code == 400
    assert user.email == "alice@example.com"
    assert event.event_metadata["reason"] == "admin_email_domain"


def test_profile_update_ignores_submitted_username(client, monkeypatch):
    register(client)
    register(client, username="bob02", email="bob@example.com", full_name="Bob Test", phone_number="81234567")
    login(client)
    user, secret = enable_mfa_for_user()
    stepup_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)

    response = client.post(
        "/profile",
        data={
            "username": "bob02",
            "email": "alice@example.com",
            "phone_number": "92345678",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(stepup_time),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 302
    assert user.username == "alice01"
    assert user.phone_number == "92345678"

def test_profile_update_rejects_duplicate_email(client):
    register(client)
    register(client, username="bob02", email="bob@example.com", full_name="Bob Test", phone_number="81234567")
    login(client)
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()
    mark_recent_mfa(client, user)

    response = client.post(
        "/profile",
        data={"username": "alice01", "email": "bob@example.com", "phone_number": "91234567"},
    )
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.email == "alice@example.com"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="profile_update", outcome="failure").count() == 1


def test_profile_update_rejects_duplicate_phone(client):
    register(client)
    register(client, username="bob02", email="bob@example.com", full_name="Bob Test", phone_number="81234567")
    login(client)
    user, secret = enable_mfa_for_user()

    response = client.post(
        "/profile",
        data={
            "username": "alice01",
            "email": "alice@example.com",
            "phone_number": "81234567",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 400
    assert user.phone_number == "91234567"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="profile_update", outcome="failure").count() == 1

def test_profile_post_requires_csrf_when_enabled(app, client):
    register(client)
    login(client)
    original = app.config["WTF_CSRF_ENABLED"]
    app.config["WTF_CSRF_ENABLED"] = True

    try:
        response = client.post(
            "/profile",
            data={"username": "alice02", "email": "alice.new@example.com", "phone_number": "91234567"},
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

def test_profile_submission_cannot_modify_privileged_fields(client, monkeypatch):
    register(client)
    register(client, username="bob02", email="bob@example.com", full_name="Bob Test", phone_number="81234567")
    login(client)
    user, secret = enable_mfa_for_user()
    other_user = db.session.execute(db.select(User).where(User.username == "bob02")).scalar_one()
    original_password_hash = user.password_hash
    stepup_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)

    response = client.post(
        "/profile",
        data={
            "username": "alice02",
            "email": "alice@example.com",
            "phone_number": "91234567",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(stepup_time),
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
    assert user.username == "alice01"
    assert user.email == "alice@example.com"
    assert user.mfa_enabled is True
    assert user.is_frozen is False
    assert user.password_hash == original_password_hash
    assert other_user.username == "bob02"
    assert other_user.email == "bob@example.com"

def test_high_risk_action_accepts_totp_stepup(client, monkeypatch):
    register(client)
    login(client)
    user, secret = enable_mfa_for_user()
    stepup_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: stepup_time)

    response = client.post(
        "/profile",
        data={
            "username": "alice02",
            "email": "alice@example.com",
            "phone_number": "92345678",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(stepup_time),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 302
    assert user.username == "alice01"
    assert user.phone_number == "92345678"

def test_totp_user_can_navigate_and_use_high_risk_forms(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    dashboard_response = client.get("/dashboard")
    profile_response = client.get("/profile")
    sessions_response = client.get("/sessions")
    password_response = client.get("/password/change")
    freeze_response = client.get("/account/freeze")

    assert dashboard_response.status_code == 200
    assert profile_response.status_code == 200
    assert sessions_response.status_code == 200
    assert password_response.status_code == 200
    assert freeze_response.status_code == 200
    assert b"Security keys required" not in profile_response.data
    assert b"Security keys required" not in sessions_response.data
    assert b"Security keys required" not in freeze_response.data

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
            "phone_number": "91234567",
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).now(),
        },
    )
    db.session.refresh(user)

    assert response.status_code == 401
    assert b"Session verification required. Please sign in again." in response.data
    assert user.email == "alice@example.com"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="session_risk", outcome="step_up_required").count() == 1
