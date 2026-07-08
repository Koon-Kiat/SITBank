from __future__ import annotations

from _auth_flow_helpers import *


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


def test_mfa_login_enforces_single_active_session_cap(app, client, monkeypatch):
    second_client = app.test_client()
    register(client)
    user, secret = enable_mfa_for_user()
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    base_time = int(time.time())

    assert login(client).status_code == 302
    monkeypatch.setattr("app.auth.services.time.time", lambda: base_time)
    first_mfa = client.post("/auth/mfa/verify", json={"totp_code": totp.at(base_time)})
    first_sessions = client.get("/auth/sessions").get_json()["sessions"]
    first_ref = next(item["session_ref"] for item in first_sessions if item["current"])

    assert login(second_client).status_code == 302
    monkeypatch.setattr("app.auth.services.time.time", lambda: base_time + 30)
    second_mfa = second_client.post(
        "/auth/mfa/verify",
        json={"totp_code": totp.at(base_time + 30)},
    )
    old_session_response = client.get("/auth/sessions")
    sessions_payload = second_client.get("/auth/sessions").get_json()

    assert first_mfa.status_code == 200
    assert second_mfa.status_code == 200
    assert old_session_response.status_code == 401
    assert len(sessions_payload["sessions"]) == 1
    assert any(
        item["session_ref"] == first_ref and item["ended_reason"] == "session_cap"
        for item in sessions_payload["past_sessions"]
    )


def test_failed_login_and_mfa_do_not_revoke_existing_active_session(app, client, monkeypatch):
    second_client = app.test_client()
    register(client)
    user, secret = enable_mfa_for_user()
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    base_time = int(time.time())

    assert login(client).status_code == 302
    monkeypatch.setattr("app.auth.services.time.time", lambda: base_time)
    first_mfa = client.post("/auth/mfa/verify", json={"totp_code": totp.at(base_time)})
    original_sessions = client.get("/auth/sessions").get_json()["sessions"]
    original_ref = next(item["session_ref"] for item in original_sessions if item["current"])

    failed_password_login = login(second_client, password="wrong password")
    original_after_failed_password = client.get("/auth/sessions")

    pending_login = login(second_client)
    failed_mfa_time = base_time + 30
    monkeypatch.setattr("app.auth.services.time.time", lambda: failed_mfa_time)
    valid_code = totp.at(failed_mfa_time)
    invalid_code = "000000" if valid_code != "000000" else "111111"
    failed_mfa = second_client.post("/auth/mfa/verify", json={"totp_code": invalid_code})
    original_after_failed_mfa = client.get("/auth/sessions")
    current_refs = {
        item["session_ref"]
        for item in original_after_failed_mfa.get_json()["sessions"]
        if item["current"]
    }

    assert first_mfa.status_code == 200
    assert failed_password_login.status_code in {200, 401}
    assert original_after_failed_password.status_code == 200
    assert pending_login.status_code == 302
    assert failed_mfa.status_code in {400, 401}
    assert original_after_failed_mfa.status_code == 200
    assert original_ref in current_refs


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
    assert f"/sessions/{current_ref}/terminate" not in markup
    assert "Current session" in markup
    assert "Current" in markup
    assert "/sessions/revoke-others" not in markup
    assert "Revoke all other sessions" not in markup
    assert 'id="session-revoke-totp-code"' not in markup

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
    old_browser_response = client.get("/auth/sessions")
    incognito_ref = next(
        item["session_ref"]
        for item in incognito_client.get("/auth/sessions").get_json()["sessions"]
        if item["current"]
    )

    incognito_logout = incognito_client.post("/logout")
    reauth_time = incognito_mfa_time + 30
    login_response = login(client)
    monkeypatch.setattr("app.auth.services.time.time", lambda: reauth_time)
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": totp.at(reauth_time)},
    )
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
    assert old_browser_response.status_code == 401
    assert incognito_logout.status_code == 302
    assert login_response.status_code == 302
    assert mfa_response.status_code == 200
    assert past_incognito["ended_reason"] == "logout"
    assert past_incognito["ended_reason_display"] == "Logged out"
    assert any(
        item["session_ref"] == normal_ref and item["ended_reason"] == "session_cap"
        for item in sessions_payload["past_sessions"]
    )
    assert incognito_ref in markup
    assert normal_ref in markup
    assert "Replaced by a new sign-in" in markup
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
    old_resolved = resolve_session_reference_for_user(user.id, old_reference)
    new_resolved = resolve_session_reference_for_user(user.id, new_reference)
    assert old_resolved is not None and old_resolved.startswith("lookup:")
    assert new_resolved is not None and new_resolved.startswith("lookup:")
    assert session_id not in {old_resolved, new_resolved}

def test_terminate_other_session_by_public_reference_revokes_it(app, client, monkeypatch):
    second_client = app.test_client()
    register(client)
    login(client)
    login_ignoring_session_cap(monkeypatch, second_client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    sessions = client.get("/auth/sessions").get_json()["sessions"]
    other_session = next(item for item in sessions if not item["current"])
    response = client.delete(f"/auth/sessions/{other_session['session_ref']}")
    revoked_response = second_client.get("/auth/sessions")

    assert response.status_code == 200
    assert revoked_response.status_code == 401
    assert revoked_response.get_json()["error"] in {"Session revoked", "Authentication required"}

def test_terminating_other_session_moves_it_to_past_sessions(app, client, monkeypatch):
    second_client = app.test_client()
    register(client)
    login(client)
    login_ignoring_session_cap(monkeypatch, second_client)
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


def test_sessions_page_keeps_review_controls_without_bulk_revoke_action(app, client, monkeypatch):
    second_client = app.test_client()
    register(client)
    login(client)
    login_ignoring_session_cap(monkeypatch, second_client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    sessions = client.get("/auth/sessions").get_json()["sessions"]
    current_ref = next(item["session_ref"] for item in sessions if item["current"])
    other_ref = next(item["session_ref"] for item in sessions if not item["current"])
    response = client.get("/sessions")
    markup = response.data.decode("utf-8")

    assert response.status_code == 200
    assert f"/sessions/{other_ref}/terminate" in markup
    assert f"/sessions/{current_ref}/terminate" not in markup
    assert "Current session" in markup
    assert "/sessions/revoke-others" not in markup
    assert "Revoke all other sessions" not in markup
    assert 'name="totp_code"' not in markup
    assert "Authenticator code" not in markup


def test_web_session_terminate_requires_csrf_when_enabled(app, client, monkeypatch):
    second_client = app.test_client()
    register(client)
    login(client)
    login_ignoring_session_cap(monkeypatch, second_client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    other_ref = next(
        item["session_ref"]
        for item in client.get("/auth/sessions").get_json()["sessions"]
        if not item["current"]
    )
    original = app.config["WTF_CSRF_ENABLED"]
    app.config["WTF_CSRF_ENABLED"] = True

    try:
        response = client.post(f"/sessions/{other_ref}/terminate")
    finally:
        app.config["WTF_CSRF_ENABLED"] = original

    assert response.status_code == 400


def test_web_revoke_other_sessions_requires_totp_stepup(app, client, monkeypatch):
    second_client = app.test_client()
    register(client)
    login(client)
    login_ignoring_session_cap(monkeypatch, second_client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    response = client.post("/sessions/revoke-others")
    other_session_response = second_client.get("/auth/sessions")

    assert response.status_code == 403
    assert other_session_response.status_code == 200

def test_past_sessions_are_scoped_to_current_user(app, client):
    second_client = app.test_client()
    register(client)
    login(client)
    alice, _alice_secret = enable_mfa_for_user()
    mark_recent_mfa(client, alice)

    register(second_client, username="bob02", email="bob@example.com", full_name="Bob Test", phone_number="81234567")
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

def test_revoke_other_sessions_accepts_totp_stepup_and_rotates_session(app, client, monkeypatch):
    second_client = app.test_client()
    register(client)
    login(client)
    login_ignoring_session_cap(monkeypatch, second_client)

    client.post("/mfa/setup", data={"action": "start"})
    user = db.session.execute(db.select(User).where(User.username == "alice01")).scalar_one()

    from app.security.crypto import decrypt_mfa_secret

    secret = decrypt_mfa_secret(user.mfa_secret_nonce, user.mfa_secret_ciphertext, user.id)
    setup_time = int(time.time())
    monkeypatch.setattr("app.auth.services.time.time", lambda: setup_time)
    code = pyotp.TOTP(secret, digits=6, interval=30).at(setup_time)

    setup_verify = client.post("/mfa/setup", data={"action": "verify", "totp_code": code})
    with client.session_transaction() as sess:
        session_after_setup = sess.sid

    api_without_stepup = client.post("/auth/sessions/revoke-others", json={})
    other_session_before_revoke = second_client.get("/auth/sessions")

    revoke_time = setup_time + 30
    monkeypatch.setattr("app.auth.services.time.time", lambda: revoke_time)
    api_revoke_response = client.post(
        "/auth/sessions/revoke-others",
        json={
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(revoke_time),
        },
    )
    with client.session_transaction() as sess:
        session_after_revoke = sess.sid
    revoked_response = second_client.get("/auth/sessions")

    assert setup_verify.status_code == 200
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

    response = client.delete("/auth/sessions/00000000000000000000000000000000")

    assert response.status_code == 404
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

def test_session_inactivity_expiry_revokes_session(client):
    register(client)
    login(client)

    with client.session_transaction() as sess:
        sess["last_activity_at"] = 1

    response = client.get("/auth/sessions")

    assert response.status_code == 401
    assert response.get_json()["error"] == "Session expired"


def test_expired_browser_session_redirects_to_login(client):
    register(client)
    login(client)

    with client.session_transaction() as sess:
        sess["last_activity_at"] = 1

    response = client.get("/dashboard")
    login_response = client.get("/login?session_expired=1")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login?session_expired=1")
    assert login_response.status_code == 200
    assert b"Your session expired due to inactivity" in login_response.data


def test_session_extension_endpoint_requires_authentication(client):
    response = client.post("/auth/session/extend")

    assert response.status_code == 401
    assert response.get_json() == {"error": "Authentication required"}


def test_session_extension_endpoint_extends_authenticated_session(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    response = client.post("/auth/session/extend")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["message"] == "Session extended"
    assert payload["timeout_seconds"] > 0


def test_session_extension_endpoint_requires_csrf_when_enabled(app, client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    original = app.config["WTF_CSRF_ENABLED"]
    app.config["WTF_CSRF_ENABLED"] = True

    try:
        token = client.get("/auth/csrf-token").get_json()["csrf_token"]
        missing_token = client.post("/auth/session/extend")
        valid_token = client.post("/auth/session/extend", headers={"X-CSRFToken": token})
    finally:
        app.config["WTF_CSRF_ENABLED"] = original

    assert missing_token.status_code == 400
    assert valid_token.status_code == 200


def test_session_timeout_ui_uses_explicit_extension_and_csp_safe_toggling(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    response = client.get("/dashboard")
    markup = response.data.decode("utf-8")
    script = Path("app/static/js/session-timeout.js").read_text(encoding="utf-8")

    assert response.status_code == 200
    assert 'meta name="session-timeout" content="900"' in markup
    assert '<dialog id="session-timeout-overlay"' in markup
    assert "showModal()" in script
    assert ".close()" in script
    assert 'style="' not in markup
    assert "style.display" not in script
    assert "/auth/session/extend" in script
    assert "/auth/csrf-token" not in script
    for passive_event in ("mousemove", "keydown", "scroll", "touchstart"):
        assert passive_event not in script


def test_session_timeout_ui_polls_status_and_declares_replaced_overlay(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    response = client.get("/dashboard")
    markup = response.data.decode("utf-8")
    script = Path("app/static/js/session-timeout.js").read_text(encoding="utf-8")

    assert response.status_code == 200
    assert '<dialog id="session-replaced-overlay"' in markup
    assert "/auth/session/status" in script
    assert "document.hidden" in script


def test_session_status_reports_active_for_valid_session(client):
    register(client)
    login(client)

    response = client.get("/auth/session/status")

    assert response.status_code == 200
    assert response.get_json() == {"status": "active"}


def test_session_status_reports_replaced_after_new_login_elsewhere(app, client):
    second_client = app.test_client()
    register(client)
    login(client)
    login(second_client)

    response = client.get("/auth/session/status")

    assert response.status_code == 401
    assert response.get_json() == {"status": "signed_out", "code": "replaced"}


def test_session_status_reports_ended_after_logout(client):
    register(client)
    login(client)
    client.post("/logout")

    response = client.get("/auth/session/status")

    assert response.status_code == 401
    assert response.get_json() == {"status": "signed_out", "code": "ended"}


def test_session_status_reports_ended_for_anonymous_client(app):
    anon_client = app.test_client()

    response = anon_client.get("/auth/session/status")

    assert response.status_code == 401
    assert response.get_json() == {"status": "signed_out", "code": "ended"}


def test_session_status_polling_does_not_extend_inactivity_window(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    stale_but_valid = int(time.time()) - 60

    with client.session_transaction() as sess:
        sess["last_activity_at"] = stale_but_valid

    status_response = client.get("/auth/session/status")
    with client.session_transaction() as sess:
        after_status_poll = sess.get("last_activity_at")

    other_response = client.get("/dashboard")
    with client.session_transaction() as sess:
        after_normal_request = sess.get("last_activity_at")

    assert status_response.status_code == 200
    assert after_status_poll == stale_but_valid
    assert other_response.status_code == 200
    assert after_normal_request > stale_but_valid


def test_security_warning_alerts_do_not_auto_dismiss():
    script = Path("app/static/js/theme.js").read_text(encoding="utf-8")

    # Warnings and errors carry security-relevant context (failed logins,
    # account freezes, MFA changes) and must stay until dismissed manually.
    assert "alert-warning" not in script
    assert "alert-error" not in script


def test_success_and_info_alerts_auto_dismiss():
    # Shared by both the customer and admin apps (admin/base.html only loads
    # theme.js, not account.js), so both surfaces auto-dismiss the same way.
    script = Path("app/static/js/theme.js").read_text(encoding="utf-8")

    # Low-stakes confirmations are allowed to auto-dismiss.
    assert "alert-success" in script
    assert "alert-info" in script
    assert "3000" in script
