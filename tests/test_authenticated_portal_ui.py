from __future__ import annotations

from _auth_flow_helpers import *


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
    assert 'name="credential_kind"' not in keys_markup
    assert "Passkey type" not in keys_markup
    assert "browser and installed passkey provider decide which prompt appears" in keys_markup
    assert "Verify and revoke" in keys_markup
    assert 'class="button danger-button button-small key-revoke-button"' in keys_markup
    assert "Revoke is disabled because at least two approved security keys must stay registered" not in keys_markup
    assert "Active Sessions" in sessions_markup
    assert "Past Sessions" in sessions_markup
    assert 'class="button danger-button full"' in freeze_markup
    assert "Verify and freeze account" in freeze_markup
    assert "color: var(--button-primary-text);" in css
    assert "text-align: left;" in css
    assert "select {" in css
    assert "appearance: none;" in css
    assert "background-color: var(--input-bg);" in css
    assert "background-image:" in css

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
    assert 'aria-disabled="true">Change Password' not in markup
    assert 'href="/password/change"' in markup
    assert "Authenticator MFA" in markup
    assert "Active Sessions" in markup
    assert "Passkeys" in markup
    assert "Freeze Account" in markup
    assert "Log Out" in markup
    assert markup.index('href="/mfa/setup"') < markup.index('href="/security-keys"') < markup.index('href="/sessions"')
    assert "No passkeys are registered" not in markup
    assert "unused recovery codes remain" not in markup
    assert "Transaction-ready" not in markup

def test_dashboard_bank_card_masks_account_details_and_loads_toggle_script(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)
    db.session.refresh(user)
    formatted_account = f"{user.account_number[:3]}-{user.account_number[3:6]}-{user.account_number[6:]}"

    response = client.get("/dashboard")
    markup = response.data.decode("utf-8")

    assert response.status_code == 200
    assert "Alice Test" in markup
    assert f"•••-•••-{user.account_number[-3:]}" in markup
    assert f'id="card-acct-full" hidden>{formatted_account}</span>' in markup
    assert 'id="card-balance-full" hidden>0.00</span>' in markup
    assert 'aria-label="Show account number"' in markup
    assert 'aria-label="Show balance"' in markup
    assert '/static/js/dashboard.js' in markup

def test_security_key_page_redirects_unenrolled_users_to_mfa_setup(client):
    register(client)
    login(client)

    response = client.get("/security-keys")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mfa/setup")

def test_no_passkey_empty_state_lives_on_passkey_page_not_dashboard(client):
    register(client)
    login(client)
    user, _secret = enable_mfa_for_user()
    mark_recent_mfa(client, user)

    dashboard_response = client.get("/dashboard")
    keys_response = client.get("/security-keys")
    dashboard_markup = dashboard_response.data.decode("utf-8")
    keys_markup = keys_response.data.decode("utf-8")

    assert dashboard_response.status_code == 200
    assert keys_response.status_code == 200
    assert "No passkeys are registered" not in dashboard_markup
    assert "No passkeys registered" in keys_markup
    assert "Add one whenever you want optional passkey sign-in or step-up." in keys_markup

def test_public_layout_does_not_expose_authenticated_account_actions(client):
    response = client.get("/login")
    markup = response.data.decode("utf-8")

    assert response.status_code == 200
    assert "data-account-menu" not in markup
    assert "Edit Profile" not in markup
    assert "data-webauthn-login-form" in markup
    assert "Windows Hello" in markup
    assert 'href="/profile"' not in markup
    assert 'action="/logout"' not in markup

def test_authentication_pages_have_password_helpers_and_mfa_back_link(client):
    verify_registration_email(client, "helpers@sit.singaporetech.edu.sg")
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
    verify_registration_email(client, "flash@sit.singaporetech.edu.sg")
    response = client.post(
        "/register",
        data={
            "username": "flash01",
            "email": "flash@sit.singaporetech.edu.sg",
            "full_name": "Flash Test",
            "phone_number": "91234567",
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

def test_webauthn_browser_errors_are_sanitized_before_display():
    source = Path("app/static/js/webauthn.js").read_text(encoding="utf-8")

    assert "Security key verification was not completed. Try again." in source
    assert "showError(errorNode, error.message)" not in source
    assert "webAuthnErrorMessage(error)" in source
    assert "credential_kind" not in source
    assert 'querySelector(\'select[name="credential_kind"]' not in source

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
        "SECURITY_AUDIT_ANCHOR_PATH",
        "HIBP_CIRCUIT_FAILURE_THRESHOLD",
        "HIBP_CIRCUIT_OPEN_SECONDS",
        "SECURITY_ALERT_STATE_PATH",
    ):
        assert setting in required
        assert setting in readme
    assert "WEBAUTHN_APPROVED_AAGUIDS_PATH" not in required
    assert "WEBAUTHN_MDS_CACHE_PATH" not in required
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
