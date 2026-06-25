from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pyotp
import pytest
from flask import current_app, session
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import AttestationFormat, CredentialDeviceType

from _auth_flow_helpers import verify_registration_email
from app.auth.mfa_policy import has_enrolled_mfa_method
from app.auth.webauthn_services import (
    begin_transaction_security_key_challenge,
    stage_transaction_security_key_context,
    webauthn_credential_count,
)
from app.extensions import db
from app.models import SecurityAuditEvent, User, WebAuthnCredential
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password


APPROVED_AAGUID = "11111111-1111-1111-1111-111111111111"
LEGACY_LEVEL1_AAGUID = "2fc0579f-8113-47ea-b116-bb5a8db9202a"
ORIGIN = {"Origin": "https://sitbank.duckdns.org"}


def register(client, username="alice01", email="alice@sit.singaporetech.edu.sg", password="correct horse battery staple",
             full_name="Alice Test", phone_number="91234567"):
    verify_registration_email(client, email)
    return client.post(
        "/register",
        data={
            "username": username,
            "email": email,
            "full_name": full_name,
            "phone_number": phone_number,
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=False,
    )


def login(client, identifier="alice01", password="correct horse battery staple"):
    return client.post(
        "/login",
        data={"identifier": identifier, "password": password},
        follow_redirects=False,
    )


def user_by_name(username="alice01"):
    return db.session.execute(db.select(User).where(User.username == username)).scalar_one()


def add_credential(user, credential_id=b"credential-one", label="Primary YubiKey", sign_count=10):
    item = WebAuthnCredential(
        user_id=user.id,
        credential_id=credential_id,
        credential_public_key=b"public-key",
        sign_count=sign_count,
        label=label,
        aaguid=APPROVED_AAGUID,
        attestation_format="packed",
        transports=["usb"],
        credential_device_type=CredentialDeviceType.SINGLE_DEVICE.value,
        credential_backed_up=False,
    )
    db.session.add(item)
    db.session.commit()
    return item


def enable_totp(user):
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    db.session.commit()
    return secret


def attestation_payload(credential_id=b"credential-one"):
    credential_ref = bytes_to_base64url(credential_id)
    return {
        "id": credential_ref,
        "rawId": credential_ref,
        "type": "public-key",
        "response": {
            "attestationObject": "AA",
            "clientDataJSON": "AA",
            "transports": ["internal"],
        },
    }


def assertion_payload(credential_id=b"credential-one"):
    credential_ref = bytes_to_base64url(credential_id)
    return {
        "id": credential_ref,
        "rawId": credential_ref,
        "type": "public-key",
        "response": {
            "authenticatorData": "AA",
            "clientDataJSON": "AA",
            "signature": "AA",
            "userHandle": None,
        },
    }


def authenticate_session(client, user, credential):
    with client.session_transaction() as sess:
        sess["user_id"] = user.id
        sess["auth_context"] = "webauthn"
        sess["webauthn_credential_id"] = bytes_to_base64url(credential.credential_id)
        sess["mfa_verified_at"] = int(datetime.now(timezone.utc).timestamp())
        sess["fresh_mfa_verified_at"] = int(datetime.now(timezone.utc).timestamp())


def mark_recent_mfa_session(client, user):
    if not user.mfa_enabled:
        enable_totp(user)
    with client.session_transaction() as sess:
        now = int(datetime.now(timezone.utc).timestamp())
        sess["user_id"] = user.id
        sess["auth_context"] = "password+mfa_bootstrap"
        sess["mfa_verified_at"] = now
        sess["fresh_mfa_verified_at"] = now
        sess.pop("risk_fingerprint", None)


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
                "issued_at": int(datetime.now(timezone.utc).timestamp()),
            }
        ),
        ex=current_app.config["WEBAUTHN_STEP_UP_TTL_SECONDS"],
    )
    return token


def test_registration_allows_first_passkey_after_password_bootstrap(client):
    register(client)
    login(client)

    response = client.post("/auth/webauthn/register/options", json={"label": "Primary YubiKey"}, headers=ORIGIN)
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["authenticatorSelection"]["residentKey"] == "required"
    assert payload["authenticatorSelection"]["requireResidentKey"] is True


def test_registration_rejects_first_passkey_without_authenticated_session(client):
    response = client.post(
        "/auth/webauthn/register/options",
        json={"label": "Primary passkey"},
        headers=ORIGIN,
    )

    assert response.status_code == 401
    assert response.get_json() == {"error": "Authentication required"}


def test_registration_rejects_first_passkey_without_password_bootstrap_context(client):
    register(client)
    user = user_by_name()
    with client.session_transaction() as sess:
        sess["user_id"] = user.id
        sess["auth_context"] = "legacy_authenticated"

    response = client.post(
        "/auth/webauthn/register/options",
        json={"label": "Primary passkey"},
        headers=ORIGIN,
    )

    assert response.status_code == 403
    assert response.get_json() == {
        "error": "Recent MFA verification is required before managing security keys"
    }


def test_registration_completes_first_passkey_as_customer_mfa_method(client, monkeypatch):
    register(client)
    login(client)
    user = user_by_name()
    options_response = client.post(
        "/auth/webauthn/register/options",
        json={"label": "Laptop passkey"},
        headers=ORIGIN,
    )

    def fake_verify_registration_response(**kwargs):
        assert kwargs["expected_rp_id"] == "sitbank.duckdns.org"
        assert kwargs["expected_origin"] == "https://sitbank.duckdns.org"
        assert kwargs["require_user_verification"] is True
        return SimpleNamespace(
            credential_id=b"first-passkey",
            credential_public_key=b"public-key",
            sign_count=0,
            aaguid="",
            fmt="none",
            credential_device_type=CredentialDeviceType.MULTI_DEVICE,
            credential_backed_up=True,
        )

    monkeypatch.setattr(
        "app.auth.webauthn_services.verify_registration_response",
        fake_verify_registration_response,
    )
    verify_response = client.post(
        "/auth/webauthn/register/verify",
        json={"credential": attestation_payload(b"first-passkey")},
        headers=ORIGIN,
    )
    db.session.refresh(user)
    dashboard_response = client.get("/dashboard")

    assert options_response.status_code == 200
    assert verify_response.status_code == 200
    assert user.mfa_enabled is False
    assert has_enrolled_mfa_method(user) is True
    assert webauthn_credential_count(user) == 1
    assert dashboard_response.status_code == 200


def test_registration_requires_fresh_mfa_for_additional_passkey(client):
    register(client)
    login(client)
    user = user_by_name()
    add_credential(user, credential_id=b"existing-passkey")

    response = client.post(
        "/auth/webauthn/register/options",
        json={"label": "Second passkey"},
        headers=ORIGIN,
    )

    assert response.status_code == 403
    assert response.get_json() == {
        "error": "Recent MFA verification is required before managing security keys"
    }


def test_mfa_policy_counts_totp_or_passkey_as_customer_enrollment(client):
    register(client)
    user = user_by_name()

    assert has_enrolled_mfa_method(user) is False

    enable_totp(user)
    db.session.refresh(user)
    assert has_enrolled_mfa_method(user) is True

    user.mfa_enabled = False
    user.mfa_secret_nonce = None
    user.mfa_secret_ciphertext = None
    db.session.commit()
    add_credential(user, credential_id=b"only-passkey")
    db.session.refresh(user)

    assert has_enrolled_mfa_method(user) is True


def test_webauthn_options_fail_closed_without_exact_origin(client):
    register(client)
    login(client)
    mark_recent_mfa_session(client, user_by_name())

    missing_origin = client.post("/auth/webauthn/register/options", json={"label": "Primary YubiKey"})
    wrong_origin = client.post(
        "/auth/webauthn/register/options",
        json={"label": "Primary YubiKey"},
        headers={"Origin": "https://evil.example"},
    )
    old_origin = client.post(
        "/auth/webauthn/register/options",
        json={"label": "Primary YubiKey"},
        headers={"Origin": "https://legacy.example.invalid"},
    )

    assert missing_origin.status_code == 403
    assert wrong_origin.status_code == 403
    assert old_origin.status_code == 403
    assert missing_origin.get_json()["error"] == "Invalid request origin"
    assert wrong_origin.get_json()["error"] == "Invalid request origin"
    assert old_origin.get_json()["error"] == "Invalid request origin"


def test_registration_options_are_generic_so_browser_can_choose_passkey_provider(client):
    register(client)
    login(client)
    mark_recent_mfa_session(client, user_by_name())

    response = client.post(
        "/auth/webauthn/register/options",
        json={"label": "Primary passkey"},
        headers=ORIGIN,
    )
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["rp"]["id"] == "sitbank.duckdns.org"
    assert payload["attestation"] == "none"
    assert "authenticatorAttachment" not in payload["authenticatorSelection"]
    assert "hints" not in payload
    assert payload["authenticatorSelection"]["userVerification"] == "required"
    assert payload["authenticatorSelection"]["residentKey"] == "required"
    assert payload["authenticatorSelection"]["requireResidentKey"] is True


def test_registration_allows_optional_passkey_without_mds_aaguid(client, monkeypatch):
    register(client)
    login(client)
    mark_recent_mfa_session(client, user_by_name())
    client.post("/auth/webauthn/register/options", json={"label": "Primary YubiKey"}, headers=ORIGIN)

    def fake_verify_registration_response(**_kwargs):
        return SimpleNamespace(
            credential_id=b"credential-one",
            credential_public_key=b"public-key",
            sign_count=1,
            aaguid="22222222-2222-2222-2222-222222222222",
            fmt=AttestationFormat.PACKED,
            credential_device_type=CredentialDeviceType.SINGLE_DEVICE,
            credential_backed_up=False,
        )

    monkeypatch.setattr(
        "app.auth.webauthn_services.verify_registration_response",
        fake_verify_registration_response,
    )

    response = client.post(
        "/auth/webauthn/register/verify",
        json={
            "credential": {
                "id": bytes_to_base64url(b"credential-one"),
                "rawId": bytes_to_base64url(b"credential-one"),
                "type": "public-key",
                "authenticatorAttachment": "cross-platform",
                "response": {
                    "attestationObject": "AA",
                    "clientDataJSON": "AA",
                    "transports": ["usb"],
                },
            }
        },
        headers=ORIGIN,
    )

    assert response.status_code == 200
    item = db.session.query(WebAuthnCredential).one()
    assert item.aaguid == "22222222-2222-2222-2222-222222222222"
    assert item.credential_kind == "security_key"
    assert response.get_json()["requires_backup_key"] is False


def test_registration_records_platform_kind_for_internal_passkey(client, monkeypatch):
    register(client)
    login(client)
    mark_recent_mfa_session(client, user_by_name())
    client.post(
        "/auth/webauthn/register/options",
        json={"label": "Windows Hello"},
        headers=ORIGIN,
    )

    def fake_verify_registration_response(**_kwargs):
        return SimpleNamespace(
            credential_id=b"windows-passkey",
            credential_public_key=b"public-key",
            sign_count=0,
            aaguid="",
            fmt="none",
            credential_device_type="multi_device",
            credential_backed_up=True,
        )

    monkeypatch.setattr(
        "app.auth.webauthn_services.verify_registration_response",
        fake_verify_registration_response,
    )

    response = client.post(
        "/auth/webauthn/register/verify",
        json={
            "credential": {
                "id": bytes_to_base64url(b"windows-passkey"),
                "rawId": bytes_to_base64url(b"windows-passkey"),
                "type": "public-key",
                "authenticatorAttachment": "platform",
                "response": {
                    "attestationObject": "AA",
                    "clientDataJSON": "AA",
                    "transports": ["internal"],
                },
            }
        },
        headers=ORIGIN,
    )

    assert response.status_code == 200
    item = db.session.query(WebAuthnCredential).one()
    assert item.attestation_format == "none"
    assert item.credential_device_type == "multi_device"
    assert item.credential_backed_up is True
    assert item.credential_kind == "platform"
    assert response.get_json()["credential"]["credential_kind"] == "platform"
    assert response.get_json()["credential"]["aaguid"] == "00000000-0000-0000-0000-000000000000"


def test_registration_records_generic_passkey_when_browser_metadata_is_opaque(client, monkeypatch):
    register(client)
    login(client)
    mark_recent_mfa_session(client, user_by_name())
    client.post("/auth/webauthn/register/options", json={"label": "Browser passkey"}, headers=ORIGIN)

    def fake_verify_registration_response(**_kwargs):
        return SimpleNamespace(
            credential_id=b"browser-passkey",
            credential_public_key=b"public-key",
            sign_count=0,
            aaguid="",
            fmt="none",
            credential_device_type="multi_device",
            credential_backed_up=True,
        )

    monkeypatch.setattr(
        "app.auth.webauthn_services.verify_registration_response",
        fake_verify_registration_response,
    )

    response = client.post(
        "/auth/webauthn/register/verify",
        json={
            "credential": {
                "id": bytes_to_base64url(b"browser-passkey"),
                "rawId": bytes_to_base64url(b"browser-passkey"),
                "type": "public-key",
                "response": {
                    "attestationObject": "AA",
                    "clientDataJSON": "AA",
                    "transports": [],
                },
            }
        },
        headers=ORIGIN,
    )

    assert response.status_code == 200
    item = db.session.query(WebAuthnCredential).one()
    assert item.credential_kind == "passkey"
    assert response.get_json()["credential"]["credential_kind_display"] == "Passkey"


def test_registration_verify_unexpected_error_returns_json(app, client, monkeypatch):
    register(client)
    login(client)
    mark_recent_mfa_session(client, user_by_name())
    client.post("/auth/webauthn/register/options", json={"label": "Primary YubiKey"}, headers=ORIGIN)
    app.config["PROPAGATE_EXCEPTIONS"] = False

    def fail_verify_registration(*_args, **_kwargs):
        raise RuntimeError("unexpected attestation parser failure")

    monkeypatch.setattr("app.auth.routes.verify_registration", fail_verify_registration)

    response = client.post(
        "/auth/webauthn/register/verify",
        json={
            "credential": {
                "id": bytes_to_base64url(b"credential-one"),
                "rawId": bytes_to_base64url(b"credential-one"),
                "type": "public-key",
                "authenticatorAttachment": "cross-platform",
                "response": {
                    "attestationObject": "AA",
                    "clientDataJSON": "AA",
                    "transports": ["usb"],
                },
            }
        },
        headers=ORIGIN,
    )

    assert response.status_code == 500
    assert response.content_type.startswith("application/json")
    assert response.get_json() == {"error": "Server error. Please try again later."}


def test_unreadable_fido_metadata_file_is_controlled_error(app, monkeypatch):
    from pathlib import Path

    from app.security.fido_mds import FidoMetadataError, _read_json

    def deny_read_text(self, *_args, **_kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", deny_read_text)

    with app.app_context():
        with pytest.raises(FidoMetadataError, match="not readable"):
            _read_json(Path("/etc/sitbank/fido-mds-cache.json"))


def test_invalid_fido_metadata_root_certificate_is_controlled_error(app):
    from app.security.fido_mds import FidoMetadataError, _base64_der_to_pem

    with app.app_context():
        with pytest.raises(FidoMetadataError, match="invalid attestation root certificate"):
            _base64_der_to_pem("<base64 DER attestation root certificate>")


def test_password_login_allowed_after_security_key_enrollment(client):
    register(client)
    user = user_by_name()
    add_credential(user)

    response = client.post("/auth/login", json={"identifier": "alice01", "password": "correct horse battery staple"})

    assert response.status_code == 200
    assert response.get_json()["message"] == "Passkey verification required"
    assert response.get_json()["mfa_required"] is True
    assert response.get_json()["webauthn_required"] is True


def test_password_totp_login_allowed_after_security_key_enrollment(client):
    register(client)
    user = user_by_name()
    secret = enable_totp(user)
    add_credential(user)

    password_response = client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "correct horse battery staple"},
    )
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).now()},
    )

    assert password_response.status_code == 200
    assert password_response.get_json()["mfa_required"] is True
    assert mfa_response.status_code == 200
    assert mfa_response.get_json()["message"] == "Login successful"


def test_public_passkey_options_ignore_identifiers_and_do_not_query_users(client, monkeypatch):
    register(client)
    user = user_by_name()
    add_credential(user, credential_id=b"alice-passkey")
    client.post("/logout")

    def fail_execute(*_args, **_kwargs):
        raise AssertionError("public passkey options must not look up users or credentials")

    monkeypatch.setattr("app.auth.webauthn_services.db.session.execute", fail_execute)
    anonymous_response = client.post("/auth/webauthn/authenticate/options", json={}, headers=ORIGIN)
    identifier_response = client.post(
        "/auth/webauthn/authenticate/options",
        json={
            "identifier": "alice01",
            "email": "alice@sit.singaporetech.edu.sg",
            "account_number": user.account_number,
        },
        headers=ORIGIN,
    )

    assert anonymous_response.status_code == 200
    assert identifier_response.status_code == 200
    for payload in (anonymous_response.get_json(), identifier_response.get_json()):
        assert payload["rpId"] == "sitbank.duckdns.org"
        assert payload["userVerification"] == "required"
        assert payload["timeout"] > 0
        assert "challenge" in payload
        assert "allowCredentials" not in payload


def test_unknown_public_passkey_assertion_fails_generically(client):
    register(client)
    client.post("/auth/webauthn/authenticate/options", json={}, headers=ORIGIN)

    response = client.post(
        "/auth/webauthn/authenticate/verify",
        json={"credential": assertion_payload(b"unknown-passkey")},
        headers=ORIGIN,
    )

    assert response.status_code == 401
    assert response.get_json() == {"error": "Security key verification failed"}


def test_fully_enrolled_user_can_still_use_password_totp_login(client):
    register(client)
    user = user_by_name()
    secret = enable_totp(user)
    add_credential(user, credential_id=b"credential-one", label="Primary YubiKey")
    add_credential(user, credential_id=b"credential-two", label="Backup YubiKey")

    password_response = client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "correct horse battery staple"},
    )
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).now()},
    )

    assert password_response.status_code == 200
    assert password_response.get_json()["mfa_required"] is True
    assert mfa_response.status_code == 200
    assert mfa_response.get_json()["message"] == "Login successful"


def test_authentication_updates_specific_credential_counter_and_last_used(client, monkeypatch):
    register(client)
    user = user_by_name()
    item = add_credential(user, credential_id=b"credential-one", sign_count=10)
    add_credential(user, credential_id=b"credential-two", label="Backup Key", sign_count=20)
    credential_ref = bytes_to_base64url(item.credential_id)

    options_response = client.post("/auth/webauthn/authenticate/options", json={}, headers=ORIGIN)

    def fake_verify_authentication_response(**_kwargs):
        return SimpleNamespace(
            credential_id=item.credential_id,
            new_sign_count=11,
            credential_device_type="single_device",
            credential_backed_up=False,
            user_verified=True,
        )

    monkeypatch.setattr(
        "app.auth.webauthn_services.verify_authentication_response",
        fake_verify_authentication_response,
    )
    response = client.post(
        "/auth/webauthn/authenticate/verify",
        json={
            "credential": {
                "id": credential_ref,
                "rawId": credential_ref,
                "type": "public-key",
                "response": {
                    "authenticatorData": "AA",
                    "clientDataJSON": "AA",
                    "signature": "AA",
                    "userHandle": None,
                },
            }
        },
        headers=ORIGIN,
    )
    db.session.refresh(item)

    assert options_response.status_code == 200
    assert "allowCredentials" not in options_response.get_json()
    assert response.status_code == 200
    assert item.sign_count == 11
    assert item.credential_device_type == "single_device"
    assert item.last_used_at is not None
    assert response.get_json()["requires_backup_key"] is False


def test_passkey_login_accepts_one_registered_credential(client, monkeypatch):
    register(client)
    user = user_by_name()
    item = add_credential(user, credential_id=b"credential-one", sign_count=10)
    credential_ref = bytes_to_base64url(item.credential_id)

    options_response = client.post("/auth/webauthn/authenticate/options", json={}, headers=ORIGIN)

    def fake_verify_authentication_response(**_kwargs):
        return SimpleNamespace(
            credential_id=item.credential_id,
            new_sign_count=11,
            credential_device_type=CredentialDeviceType.SINGLE_DEVICE,
            credential_backed_up=False,
            user_verified=True,
        )

    monkeypatch.setattr(
        "app.auth.webauthn_services.verify_authentication_response",
        fake_verify_authentication_response,
    )
    response = client.post(
        "/auth/webauthn/authenticate/verify",
        json={
            "credential": {
                "id": credential_ref,
                "rawId": credential_ref,
                "type": "public-key",
                "response": {
                    "authenticatorData": "AA",
                    "clientDataJSON": "AA",
                    "signature": "AA",
                    "userHandle": None,
                },
            }
        },
        headers=ORIGIN,
    )

    assert options_response.status_code == 200
    assert "allowCredentials" not in options_response.get_json()
    assert response.status_code == 200
    assert response.get_json()["message"] == "Login successful"
    assert db.session.get(WebAuthnCredential, item.id) is not None


def test_signature_counter_anomaly_locks_user_and_audits(client, monkeypatch):
    register(client)
    user = user_by_name()
    item = add_credential(user, credential_id=b"credential-one", sign_count=10)
    add_credential(user, credential_id=b"credential-two", label="Backup Key", sign_count=20)
    credential_ref = bytes_to_base64url(item.credential_id)
    client.post("/auth/webauthn/authenticate/options", json={}, headers=ORIGIN)

    def fake_verify_authentication_response(**_kwargs):
        return SimpleNamespace(
            credential_id=item.credential_id,
            new_sign_count=10,
            credential_device_type=CredentialDeviceType.SINGLE_DEVICE,
            credential_backed_up=False,
            user_verified=True,
        )

    monkeypatch.setattr(
        "app.auth.webauthn_services.verify_authentication_response",
        fake_verify_authentication_response,
    )
    response = client.post(
        "/auth/webauthn/authenticate/verify",
        json={
            "credential": {
                "id": credential_ref,
                "rawId": credential_ref,
                "type": "public-key",
                "response": {
                    "authenticatorData": "AA",
                    "clientDataJSON": "AA",
                    "signature": "AA",
                    "userHandle": None,
                },
            }
        },
        headers=ORIGIN,
    )
    db.session.refresh(user)

    assert response.status_code == 403
    assert user.is_frozen is True
    assert user.security_lock_reason == "webauthn_signature_counter_anomaly"
    assert db.session.query(SecurityAuditEvent).filter_by(event_type="webauthn_clone_detected", outcome="locked").count() == 1


def test_revoke_credential_deletes_only_owned_key_and_allows_last_passkey_when_totp_enabled(client, monkeypatch):
    user = User(
        username="alice01",
        email="alice@example.com",
        password_hash=hash_password("correct horse battery staple"),
        full_name="Alice Test",
        phone_number="91234567",
        account_number="012" + "".join(str(secrets.randbelow(10)) for _ in range(6)),
    )
    other = User(
        username="bob02",
        email="bob@example.com",
        password_hash=hash_password("correct horse battery staple"),
        full_name="Bob Test",
        phone_number="81234567",
        account_number="012" + "".join(str(secrets.randbelow(10)) for _ in range(6)),
    )
    db.session.add_all([user, other])
    db.session.commit()
    current = add_credential(user, credential_id=b"credential-one", label="Primary YubiKey")
    lost = add_credential(user, credential_id=b"credential-two", label="Backup Key")
    spare = add_credential(user, credential_id=b"credential-three", label="Spare Key")
    other_key = add_credential(other, credential_id=b"credential-four", label="Other Key")
    secret = enable_totp(user)
    authenticate_session(client, user, current)

    def payload(timestamp, action="webauthn_revoke"):
        monkeypatch.setattr("app.auth.services.time.time", lambda: timestamp)
        return {
            "totp_code": pyotp.TOTP(secret, digits=6, interval=30).at(timestamp),
            "stepup_token": mint_stepup_token(client, user, action),
        }

    unowned = client.delete(
        f"/auth/webauthn/credentials/{bytes_to_base64url(other_key.credential_id)}",
        json=payload(1_700_000_010),
    )
    revoked = client.delete(
        f"/auth/webauthn/credentials/{bytes_to_base64url(lost.credential_id)}",
        json=payload(1_700_000_050),
    )
    last_key = client.delete(
        f"/auth/webauthn/credentials/{bytes_to_base64url(current.credential_id)}",
        json=payload(1_700_000_090),
    )

    assert unowned.status_code == 404
    assert revoked.status_code == 200
    assert db.session.get(WebAuthnCredential, lost.id) is None
    assert last_key.status_code == 200
    assert db.session.get(WebAuthnCredential, current.id) is None
    assert db.session.get(WebAuthnCredential, spare.id) is not None


def test_key_setup_does_not_gate_dashboard_access(app, client):
    app.config["WEBAUTHN_ENFORCE_KEY_SETUP"] = True
    register(client)
    login(client)
    mark_recent_mfa_session(client, user_by_name())

    response = client.get("/dashboard")

    assert response.status_code == 200


def test_transaction_security_key_challenge_binds_context(app):
    user = User(
        username="alice01",
        email="alice@example.com",
        password_hash=hash_password("correct horse battery staple"),
        full_name="Alice Test",
        phone_number="91234567",
        account_number="012" + "".join(str(secrets.randbelow(10)) for _ in range(6)),
    )
    db.session.add(user)
    db.session.commit()
    add_credential(user)

    with app.test_request_context("/", headers={"Origin": "https://sitbank.duckdns.org"}):
        session["user_id"] = user.id
        reference = stage_transaction_security_key_context(
            user,
            {
                "amount": "125.00",
                "currency": "SGD",
                "payee_account": "PAYEE-001",
                "transaction_reference": "TXN-001",
                "expiry": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            },
        )
        payload = begin_transaction_security_key_challenge(user, reference)

        assert payload["rpId"] == "sitbank.duckdns.org"
        assert payload["userVerification"] == "required"
        assert payload["transaction_reference"] == "TXN-001"
        assert "transaction" not in payload
        assert session["webauthn_transaction_user_id"] == user.id

    events = (
        db.session.query(SecurityAuditEvent)
        .filter(
            SecurityAuditEvent.event_type.in_(
                [
                    "webauthn_transaction_stage",
                    "webauthn_transaction_options",
                    "banking_transaction_authorization",
                ]
            )
        )
        .all()
    )
    serialized = json.dumps([event.event_metadata for event in events], sort_keys=True)
    webauthn_stage = next(event for event in events if event.event_type == "webauthn_transaction_stage")
    banking_stage = next(
        event
        for event in events
        if event.event_type == "banking_transaction_authorization" and event.outcome == "staged"
    )

    assert len(webauthn_stage.event_metadata["transaction_ref"]) == 32
    assert len(webauthn_stage.event_metadata["transaction_payee_account_ref"]) == 32
    assert len(banking_stage.event_metadata["transaction_ref"]) == 32
    assert len(banking_stage.event_metadata["payee_account_ref"]) == 32
    assert "transaction_reference" not in webauthn_stage.event_metadata
    assert "transaction_payee_account" not in webauthn_stage.event_metadata
    assert "TXN-001" not in serialized
    assert "PAYEE-001" not in serialized


def test_transaction_security_key_challenge_rejects_client_supplied_context(app):
    user = User(
        username="alice01",
        email="alice@example.com",
        password_hash=hash_password("correct horse battery staple"),
        full_name="Alice Test",
        phone_number="91234567",
        account_number="012" + "".join(str(secrets.randbelow(10)) for _ in range(6)),
    )
    db.session.add(user)
    db.session.commit()
    add_credential(user)

    with app.test_request_context("/", headers=ORIGIN):
        session["user_id"] = user.id
        response_context = {
            "amount": "125.00",
            "currency": "SGD",
            "payee_account": "PAYEE-001",
            "transaction_reference": "TXN-001",
            "expiry": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        }
        try:
            begin_transaction_security_key_challenge(user, response_context)
        except Exception as exc:
            assert "Transaction reference is required" in str(exc)
