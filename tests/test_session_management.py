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
    login(second_client)

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
