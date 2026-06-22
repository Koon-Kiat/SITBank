from __future__ import annotations

from _auth_flow_helpers import *


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
    mfa_setup_page = client.get("/mfa/setup")
    client.post("/logout")
    login(client)
    reused = client.post("/auth/mfa/verify", json={"totp_code": recovery_codes[0]})

    assert login_response.status_code == 302
    assert verified.status_code == 200
    assert verified.get_json()["recovery_codes_remaining"] == 9
    assert dashboard.status_code == 200
    assert mfa_setup_page.status_code == 200
    assert "unused recovery codes remain" not in dashboard.data.decode("utf-8")
    assert "9 unused recovery codes remain." in mfa_setup_page.data.decode("utf-8")
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

def test_recovery_code_satisfies_totp_login_even_when_passkeys_are_registered(client):
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

    assert response.status_code == 200
    assert response.get_json()["message"] == "Login successful"
    assert db.session.query(RecoveryCode).filter_by(user_id=user.id).filter(RecoveryCode.used_at.is_not(None)).count() == 1

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

def test_mfa_setup_warns_when_recovery_codes_are_low_and_dashboard_stays_quiet(client):
    from app.auth.recovery_codes import generate_recovery_codes_for_user

    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    generate_recovery_codes_for_user(user, count=2)

    dashboard_response = client.get("/dashboard")
    mfa_response = client.get("/mfa/setup")
    dashboard_markup = dashboard_response.data.decode("utf-8")
    mfa_markup = mfa_response.data.decode("utf-8")

    assert dashboard_response.status_code == 200
    assert mfa_response.status_code == 200
    assert "unused recovery codes remain" not in dashboard_markup
    assert "Regenerate soon" not in dashboard_markup
    assert "2 unused recovery codes remain." in mfa_markup
    assert "Regenerate soon" in mfa_markup

def test_mfa_setup_generates_independent_user_secrets(app, client):
    second_client = app.test_client()
    register(client)
    register(second_client, username="bob02", email="bob@example.com", full_name="Bob Test", phone_number="81234567")
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
    register(second_client, username="bob02", email="bob@example.com", full_name="Bob Test", phone_number="81234567")
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
    assert "Verify replacement start" in markup
    assert "Disable MFA" not in markup
    assert "Remove MFA" not in markup

def test_mfa_replacement_start_requires_fresh_mfa_stepup(client):
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

    assert login_response.status_code == 302
    assert login_response.headers["Location"].endswith("/mfa/verify")

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
