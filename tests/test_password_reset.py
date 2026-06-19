from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlparse

import pyotp
from sqlalchemy import func

from app.auth.password_reset import generate_recovery_codes_for_user
from app.extensions import db
from app.models import ManualRecoveryRequest, PasswordResetToken, RecoveryCode, SecurityAuditEvent, User, WebAuthnCredential
from app.security.crypto import encrypt_mfa_secret
from app.security.email import password_reset_outbox
from app.security.passwords import hash_password, verify_password


VALID_PASSWORD = "Correct-Horse-Battery-Staple-2026!"
NEW_PASSWORD = "Reset-Correct-Horse-Battery-Staple-2026!"


def _create_user(username: str, email: str, password: str = VALID_PASSWORD) -> User:
    user = User(username=username, email=email, password_hash=hash_password(password))
    db.session.add(user)
    db.session.commit()
    return user


def _create_totp_user(username: str, email: str) -> tuple[User, str]:
    user = _create_user(username, email)
    secret = pyotp.random_base32(length=32)
    nonce, ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_secret_nonce = nonce
    user.mfa_secret_ciphertext = ciphertext
    user.mfa_enabled = True
    db.session.commit()
    return user, secret


def _add_webauthn_credential(user: User) -> None:
    db.session.add(
        WebAuthnCredential(
            user_id=user.id,
            credential_id=b"credential-id-0001",
            credential_public_key=b"credential-public-key",
            sign_count=1,
            label="Primary key",
            aaguid="00000000-0000-0000-0000-000000000000",
            attestation_format="packed",
            transports=["usb"],
            credential_device_type="single_device",
            credential_backed_up=False,
        )
    )
    db.session.commit()


def _request_reset(client, email: str):
    return client.post("/auth/password-reset/request", json={"email": email})


def _reset_token(app) -> str:
    with app.app_context():
        outbox = password_reset_outbox()
        assert len(outbox) == 1
        match = re.search(r"https://[^\s]+/reset-password\?token=([A-Za-z0-9_.-]+)", outbox[0]["body"])
        assert match
        return parse_qs(urlparse(f"https://example.test/?token={match.group(1)}").query)["token"][0]


def _exchange(client, token: str):
    return client.post("/auth/password-reset/exchange", json={"token": token})


def test_forgot_password_response_is_generic_and_token_is_hashed(app, client):
    with app.app_context():
        _create_user("reset01", "reset01@example.com")

    known = _request_reset(client, "reset01@example.com")
    unknown = _request_reset(client, "missing@example.com")

    assert known.status_code == 200
    assert unknown.status_code == 200
    assert known.get_json() == unknown.get_json()
    assert known.get_json()["message"] == "If an account exists for that email, a reset link has been sent."

    token = _reset_token(app)
    selector, verifier = token.split(".", 1)
    with app.app_context():
        reset_token = db.session.execute(
            db.select(PasswordResetToken).where(PasswordResetToken.selector == selector)
        ).scalar_one()
        assert reset_token.verifier_hmac
        assert reset_token.verifier_hmac != verifier
        audit_text = json.dumps(
            [
                {
                    "event_type": event.event_type,
                    "metadata": event.event_metadata,
                }
                for event in db.session.execute(db.select(SecurityAuditEvent)).scalars()
            ],
            sort_keys=True,
        )
        assert token not in audit_text
        assert verifier not in audit_text


def test_reset_token_exchanges_once_into_tokenless_transaction(app, client):
    with app.app_context():
        _create_user("reset02", "reset02@example.com")

    _request_reset(client, "reset02@example.com")
    token = _reset_token(app)

    exchanged = _exchange(client, token)
    replay = _exchange(client, token)
    dashboard = client.get("/dashboard", follow_redirects=False)
    transaction = client.get("/auth/password-reset/transaction")

    assert exchanged.status_code == 200
    assert exchanged.get_json()["mfa_required"] == "none"
    assert replay.status_code == 401
    assert dashboard.status_code == 302
    assert dashboard.headers["Location"].endswith("/login")
    assert transaction.status_code == 200
    assert "token" not in transaction.get_data(as_text=True).casefold()


def test_no_mfa_password_reset_does_not_auto_login_and_forces_mfa_on_next_login(app, client):
    with app.app_context():
        user = _create_user("reset03", "reset03@example.com")
        old_hash = user.password_hash

    _request_reset(client, "reset03@example.com")
    token = _reset_token(app)
    assert _exchange(client, token).status_code == 200

    completed = client.post(
        "/auth/password-reset/complete",
        json={"new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD},
    )
    dashboard = client.get("/dashboard", follow_redirects=False)
    login = client.post("/auth/login", json={"identifier": "reset03", "password": NEW_PASSWORD})

    assert completed.status_code == 200
    assert dashboard.status_code == 302
    assert dashboard.headers["Location"].endswith("/login")
    assert login.status_code == 200
    assert login.get_json()["mfa_setup_required"] is True
    with app.app_context():
        user = db.session.get(User, user.id)
        assert user is not None
        assert user.password_hash != old_hash
        assert verify_password(NEW_PASSWORD, user.password_hash)


def test_totp_user_must_verify_totp_before_password_reset(app, client):
    with app.app_context():
        _user, secret = _create_totp_user("reset04", "reset04@example.com")

    _request_reset(client, "reset04@example.com")
    token = _reset_token(app)
    exchanged = _exchange(client, token)
    blocked = client.post(
        "/auth/password-reset/complete",
        json={"new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD},
    )
    verified = client.post(
        "/auth/password-reset/mfa/totp",
        json={"totp_code": pyotp.TOTP(secret).now()},
    )
    completed = client.post(
        "/auth/password-reset/complete",
        json={"new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD},
    )

    assert exchanged.status_code == 200
    assert exchanged.get_json()["mfa_required"] == "totp"
    assert blocked.status_code == 403
    assert verified.status_code == 200
    assert verified.get_json()["mfa_verified"] is True
    assert completed.status_code == 200


def test_webauthn_user_cannot_fall_back_to_email_only_reset(app, client):
    with app.app_context():
        user = _create_user("reset05", "reset05@example.com")
        _add_webauthn_credential(user)

    _request_reset(client, "reset05@example.com")
    token = _reset_token(app)
    exchanged = _exchange(client, token)
    totp_attempt = client.post("/auth/password-reset/mfa/totp", json={"totp_code": "123456"})
    completed = client.post(
        "/auth/password-reset/complete",
        json={"new_password": NEW_PASSWORD, "confirm_new_password": NEW_PASSWORD},
    )

    assert exchanged.status_code == 200
    assert exchanged.get_json()["mfa_required"] == "webauthn"
    assert totp_attempt.status_code == 400
    assert completed.status_code == 403


def test_admin_like_customer_domain_reset_fails_closed(app, client):
    with app.app_context():
        _create_user("admin", "admin@example.com")

    response = _request_reset(client, "admin@example.com")

    assert response.status_code == 200
    with app.app_context():
        assert password_reset_outbox() == []
        assert db.session.execute(db.select(PasswordResetToken)).first() is None


def test_manual_recovery_request_does_not_freeze_or_unlock_account(app, client):
    with app.app_context():
        user = _create_user("reset06", "reset06@example.com")
        user_id = user.id

    response = client.post("/auth/account-recovery", json={"identifier": "reset06@example.com"})

    assert response.status_code == 200
    with app.app_context():
        user = db.session.get(User, user_id)
        request_record = db.session.execute(db.select(ManualRecoveryRequest)).scalar_one()
        assert user is not None
        assert user.is_frozen is False
        assert user.security_locked_at is None
        assert request_record.user_id == user.id
        assert request_record.status == "pending"


def test_recovery_codes_are_hashed_single_use_reset_factors(app, client):
    with app.app_context():
        user, _secret = _create_totp_user("reset07", "reset07@example.com")
        with app.test_request_context("/"):
            codes = generate_recovery_codes_for_user(user, count=2)
        stored_codes = list(db.session.execute(db.select(RecoveryCode)).scalars())
        assert len(stored_codes) == 2
        assert all(item.code_hmac not in codes for item in stored_codes)

    _request_reset(client, "reset07@example.com")
    token = _reset_token(app)
    assert _exchange(client, token).status_code == 200
    verified = client.post("/auth/password-reset/mfa/recovery-code", json={"recovery_code": codes[0]})
    reused = client.post("/auth/password-reset/mfa/recovery-code", json={"recovery_code": codes[0]})

    assert verified.status_code == 200
    assert verified.get_json()["recovery_code_verified"] is True
    assert reused.status_code == 401
    with app.app_context():
        used_count = db.session.execute(
            db.select(func.count(RecoveryCode.id)).where(RecoveryCode.used_at.is_not(None))
        ).scalar_one()
        assert used_count == 1
