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

from app.auth.webauthn_services import begin_transaction_security_key_challenge, stage_transaction_security_key_context
from app.extensions import db
from app.models import SecurityAuditEvent, User, WebAuthnCredential
from app.security.crypto import encrypt_mfa_secret
from app.security.passwords import hash_password


APPROVED_AAGUID = "11111111-1111-1111-1111-111111111111"
LEGACY_LEVEL1_AAGUID = "2fc0579f-8113-47ea-b116-bb5a8db9202a"
ORIGIN = {"Origin": "https://sitbank.duckdns.org"}


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
    current_app.extensions["redis"].setex(
        _step_up_token_cache_key(token),
        current_app.config["WEBAUTHN_STEP_UP_TTL_SECONDS"],
        json.dumps(
            {
                "user_id": user.id,
                "session_id": session_id,
                "action": action,
                "issued_at": int(datetime.now(timezone.utc).timestamp()),
            }
        ),
    )
    return token


def test_registration_requires_recent_mfa_before_first_key(client):
    register(client)
    login(client)

    response = client.post("/auth/webauthn/register/options", json={"label": "Primary YubiKey"}, headers=ORIGIN)

    assert response.status_code == 403
    assert response.get_json()["error"] == "Authenticator MFA setup required"


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


def test_registration_options_enforce_direct_cross_platform_uv_policy(client):
    register(client)
    login(client)
    mark_recent_mfa_session(client, user_by_name())

    response = client.post("/auth/webauthn/register/options", json={"label": "Primary YubiKey"}, headers=ORIGIN)
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["rp"]["id"] == "sitbank.duckdns.org"
    assert payload["attestation"] == "direct"
    assert payload["authenticatorSelection"]["authenticatorAttachment"] == "cross-platform"
    assert payload["authenticatorSelection"]["userVerification"] == "required"
    assert payload["hints"] == ["security-key"]


def test_registration_rejects_unknown_mds_aaguid(client, monkeypatch):
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

    assert response.status_code == 401
    assert db.session.query(WebAuthnCredential).count() == 0
    event = (
        db.session.query(SecurityAuditEvent)
        .filter_by(event_type="webauthn_register", outcome="failure")
        .order_by(SecurityAuditEvent.id.desc())
        .first()
    )
    assert event is not None
    assert event.event_metadata["failure_stage"] == "metadata_policy"
    assert event.event_metadata["reason"] == "FidoMetadataError"
    assert event.event_metadata["failure_detail"] == "Authenticator AAGUID is not approved"
    assert event.event_metadata["aaguid"] == "22222222-2222-2222-2222-222222222222"
    assert event.event_metadata["attestation_format"] == "packed"
    assert event.event_metadata["credential_device_type"] == "single_device"


def test_registration_allows_explicit_legacy_level1_aaguid_missing_from_mds(app, client, monkeypatch, tmp_path):
    policy_path = tmp_path / "fido-approved-aaguids.json"
    policy_path.write_text(
        json.dumps(
            {
                "approved_aaguids": [],
                "legacy_level1_approved_aaguids": [LEGACY_LEVEL1_AAGUID],
            }
        ),
        encoding="utf-8",
    )
    app.config["WEBAUTHN_APPROVED_AAGUIDS_PATH"] = str(policy_path)
    register(client)
    login(client)
    mark_recent_mfa_session(client, user_by_name())
    client.post("/auth/webauthn/register/options", json={"label": "Primary YubiKey"}, headers=ORIGIN)

    def fake_verify_registration_response(**_kwargs):
        return SimpleNamespace(
            credential_id=b"legacy-yubikey",
            credential_public_key=b"public-key",
            sign_count=1,
            aaguid=LEGACY_LEVEL1_AAGUID,
            fmt="packed",
            credential_device_type="single_device",
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
                "id": bytes_to_base64url(b"legacy-yubikey"),
                "rawId": bytes_to_base64url(b"legacy-yubikey"),
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
    assert item.attestation_format == "packed"
    assert item.credential_device_type == "single_device"
    assert response.get_json()["credential"]["aaguid"] == LEGACY_LEVEL1_AAGUID


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
    assert response.get_json()["message"] == "MFA setup required"
    assert response.get_json()["mfa_setup_required"] is True


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


def test_fully_enrolled_user_cannot_downgrade_to_password_totp_login(client):
    register(client)
    user = user_by_name()
    enable_totp(user)
    add_credential(user, credential_id=b"credential-one", label="Primary YubiKey")
    add_credential(user, credential_id=b"credential-two", label="Backup YubiKey")

    password_response = client.post(
        "/auth/login",
        json={"identifier": "alice01", "password": "correct horse battery staple"},
    )
    mfa_response = client.post("/auth/mfa/verify", json={"totp_code": "000000"})

    assert password_response.status_code == 403
    assert password_response.get_json()["error"] == "Security key sign-in required for this account"
    assert mfa_response.status_code == 401
    assert mfa_response.get_json()["error"] == "No pending MFA challenge"


def test_authentication_updates_specific_credential_counter_and_last_used(client, monkeypatch):
    register(client)
    user = user_by_name()
    item = add_credential(user, credential_id=b"credential-one", sign_count=10)
    add_credential(user, credential_id=b"credential-two", label="Backup Key", sign_count=20)
    credential_ref = bytes_to_base64url(item.credential_id)

    options_response = client.post("/auth/webauthn/authenticate/options", json={"identifier": "alice01"}, headers=ORIGIN)

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
    assert response.status_code == 200
    assert item.sign_count == 11
    assert item.credential_device_type == "single_device"
    assert item.last_used_at is not None
    assert response.get_json()["requires_backup_key"] is False


def test_security_key_login_requires_two_registered_keys(client):
    register(client)
    user = user_by_name()
    item = add_credential(user, credential_id=b"credential-one", sign_count=10)
    credential_ref = bytes_to_base64url(item.credential_id)

    options_response = client.post("/auth/webauthn/authenticate/options", json={"identifier": "alice01"}, headers=ORIGIN)
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
    assert options_response.get_json()["allowCredentials"] == []
    assert response.status_code == 401
    assert response.get_json()["error"] == "Security key verification failed"
    assert db.session.get(WebAuthnCredential, item.id) is not None


def test_signature_counter_anomaly_locks_user_and_audits(client, monkeypatch):
    register(client)
    user = user_by_name()
    item = add_credential(user, credential_id=b"credential-one", sign_count=10)
    add_credential(user, credential_id=b"credential-two", label="Backup Key", sign_count=20)
    credential_ref = bytes_to_base64url(item.credential_id)
    client.post("/auth/webauthn/authenticate/options", json={"identifier": "alice01"}, headers=ORIGIN)

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


def test_revoke_credential_deletes_only_owned_key_and_blocks_last_key(client, monkeypatch):
    user = User(
        username="alice01",
        email="alice@example.com",
        password_hash=hash_password("correct horse battery staple"),
    )
    other = User(
        username="bob02",
        email="bob@example.com",
        password_hash=hash_password("correct horse battery staple"),
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
    assert last_key.status_code == 409
    assert db.session.get(WebAuthnCredential, current.id) is not None
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


def test_transaction_security_key_challenge_rejects_client_supplied_context(app):
    user = User(
        username="alice01",
        email="alice@example.com",
        password_hash=hash_password("correct horse battery staple"),
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
