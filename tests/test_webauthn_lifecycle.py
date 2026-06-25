from __future__ import annotations

from pathlib import Path

import pytest

from _auth_flow_helpers import verify_registration_email
from app.auth.mfa_policy import has_enrolled_mfa_method
from app.auth.services import AuthError
from app.auth.webauthn_services import (
    PASSKEY_DISABLED_MESSAGE,
    begin_transaction_security_key_challenge,
    list_credentials_for_user,
    stage_transaction_security_key_context,
    verify_transaction_security_key_challenge,
    webauthn_credential_count,
)
from app.extensions import db
from app.models import User, WebAuthnCredential
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password


def _create_user(username: str = "legacykey", email: str = "legacykey@example.com") -> User:
    user = User(
        username=username,
        email=email,
        password_hash=hash_password("correct horse battery staple"),
        full_name="Legacy Key",
        phone_number="91234567",
        account_number="012345678",
    )
    db.session.add(user)
    db.session.commit()
    return user


def _add_legacy_credential(user: User, credential_id: bytes = b"legacy-credential-id") -> WebAuthnCredential:
    item = WebAuthnCredential(
        user_id=user.id,
        credential_id=credential_id,
        credential_public_key=b"legacy-public-key",
        sign_count=1,
        label="Legacy passkey",
        aaguid="00000000-0000-0000-0000-000000000000",
        attestation_format="packed",
        transports=["usb"],
        credential_device_type="single_device",
        credential_backed_up=False,
    )
    db.session.add(item)
    db.session.commit()
    return item


def _enable_totp(user: User) -> None:
    secret = "JBSWY3DPEHPK3PXP"
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    db.session.commit()


def _login_session(client, user: User) -> None:
    with client.session_transaction() as sess:
        sess["user_id"] = user.id
        sess["auth_context"] = "password+mfa_bootstrap"
        sess["mfa_verified_at"] = 1_800_000_000
        sess["fresh_mfa_verified_at"] = 1_800_000_000


def test_legacy_passkey_rows_do_not_satisfy_mfa_policy(client):
    user = _create_user()
    _add_legacy_credential(user)

    response = client.post(
        "/auth/login",
        json={"identifier": user.email, "password": "correct horse battery staple"},
    )

    assert response.status_code == 200
    assert response.get_json()["mfa_setup_required"] is True
    assert response.get_json()["legacy_passkey_migration_required"] is True
    assert webauthn_credential_count(user) == 1
    assert has_enrolled_mfa_method(user) is False


def test_legacy_credentials_are_read_only_inventory(client):
    user = _create_user()
    credential = _add_legacy_credential(user)

    public_credentials = list_credentials_for_user(user)

    assert len(public_credentials) == 1
    assert public_credentials[0]["id"]
    assert public_credentials[0]["label"] == credential.label
    assert public_credentials[0]["active"] is False
    assert public_credentials[0]["decommissioned"] is True


@pytest.mark.parametrize(
    ("method", "path", "json_payload"),
    [
        ("post", "/auth/webauthn/authenticate/options", {}),
        ("post", "/auth/webauthn/authenticate/verify", {"credential": {}}),
        ("post", "/auth/password-reset/mfa/webauthn/options", {}),
        ("post", "/auth/password-reset/mfa/webauthn/verify", {"credential": {}}),
    ],
)
def test_public_passkey_endpoints_fail_closed(client, method, path, json_payload):
    response = getattr(client, method)(path, json=json_payload)

    assert response.status_code == 410
    assert response.get_json() == {"error": PASSKEY_DISABLED_MESSAGE}


@pytest.mark.parametrize(
    ("method", "path", "json_payload"),
    [
        ("post", "/auth/webauthn/register/options", {"label": "Legacy"}),
        ("post", "/auth/webauthn/register/verify", {"credential": {}}),
        ("post", "/auth/webauthn/step-up/options", {"action": "profile_update"}),
        ("post", "/auth/webauthn/step-up/verify", {"action": "profile_update", "credential": {}}),
        ("get", "/auth/webauthn/credentials", None),
        ("delete", "/auth/webauthn/credentials/bGVnYWN5LWNyZWRlbnRpYWw", {}),
    ],
)
def test_authenticated_passkey_endpoints_fail_closed(client, method, path, json_payload):
    user = _create_user()
    _enable_totp(user)
    _login_session(client, user)

    kwargs = {"json": json_payload} if json_payload is not None else {}
    response = getattr(client, method)(path, **kwargs)

    assert response.status_code == 410
    assert response.get_json() == {"error": PASSKEY_DISABLED_MESSAGE}


def test_transaction_security_key_helpers_fail_closed(client):
    user = _create_user()

    with pytest.raises(AuthError, match="Passkey authentication is no longer available"):
        stage_transaction_security_key_context(user, {"amount": "10.00"})
    with pytest.raises(AuthError, match="Passkey authentication is no longer available"):
        begin_transaction_security_key_challenge(user, "transaction-ref")
    with pytest.raises(AuthError, match="Passkey authentication is no longer available"):
        verify_transaction_security_key_challenge(user, {"id": "credential"})


def test_passkey_ui_and_requirements_are_removed_from_active_surface(client):
    verify_registration_email(client)
    login_page = client.get("/login").get_data(as_text=True)
    mfa_page = client.get("/mfa/verify").get_data(as_text=True)
    requirements_in = Path("requirements.in").read_text(encoding="utf-8")
    requirements_lock = Path("requirements.lock").read_text(encoding="utf-8")

    assert "data-webauthn" not in login_page
    assert "Sign in with passkey" not in login_page
    assert "data-webauthn" not in mfa_page
    assert "webauthn==" not in requirements_in
    assert "webauthn==" not in requirements_lock
