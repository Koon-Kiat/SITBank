from __future__ import annotations

import re
import json
import secrets
import time
from datetime import datetime, timedelta, timezone

import pytest
import pyotp
from flask import current_app
from pathlib import Path
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.orm import Session
from webauthn.helpers.structs import CredentialDeviceType

from app.extensions import db
from app.models import RecoveryCode, SecurityAuditEvent, User, WebAuthnCredential
from app.security.passwords import (
    PASSWORD_MAX_CHARS,
    PASSWORD_MIN_LENGTH,
    PASSWORD_RECOMMENDED_MIN_LENGTH,
    PBKDF2_PREFIX,
    hash_password,
    verify_password,
)


def register(client, username="alice01", email="alice@example.com", password="correct horse battery staple",
             full_name="Alice Test", phone_number="91234567"):
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


def password_inputs(response):
    return re.findall(rb"<input(?=[^>]*type=\"password\")[^>]*>", response.data)


def log_payloads(caplog, message):
    payloads = []
    for record in caplog.records:
        try:
            payload = json.loads(record.getMessage())
        except json.JSONDecodeError:
            continue
        if payload.get("message") == message:
            payloads.append(payload)
    return payloads


def api_login_from_ip(client, remote_addr, identifier="alice01", password="correct horse battery staple"):
    return client.post(
        "/auth/login",
        json={"identifier": identifier, "password": password},
        environ_overrides={"REMOTE_ADDR": remote_addr},
    )


def mark_recent_mfa(client, user):
    user.mfa_enabled = True
    db.session.commit()
    now = int(time.time())
    with client.session_transaction() as sess:
        sess["auth_context"] = "password+mfa_bootstrap"
        sess["mfa_verified_at"] = now
        sess["fresh_mfa_verified_at"] = now
        sess.pop("risk_fingerprint", None)


def decrypt_test_mfa_secret(user):
    from app.security.crypto import decrypt_mfa_secret

    return decrypt_mfa_secret(user.mfa_secret_nonce, user.mfa_secret_ciphertext, user.id)


def enable_mfa_for_user(username="alice01"):
    from app.security.crypto import encrypt_mfa_secret

    user = db.session.execute(db.select(User).where(User.username == username)).scalar_one()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(secret, user.id)
    user.mfa_enabled = True
    db.session.commit()
    return user, secret


def add_security_keys_for_user(user, count=2):
    for index in range(count):
        credential_id = f"credential-{user.id}-{index}".encode("utf-8")
        db.session.add(
            WebAuthnCredential(
                user_id=user.id,
                credential_id=credential_id,
                credential_public_key=b"public-key",
                sign_count=10 + index,
                label=f"Security Key {index + 1}",
                aaguid="11111111-1111-1111-1111-111111111111",
                attestation_format="packed",
                transports=["usb"],
                credential_device_type=CredentialDeviceType.SINGLE_DEVICE.value,
                credential_backed_up=False,
            )
        )
    db.session.commit()


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
                "credential_id": f"credential-{user.id}-0",
                "issued_at": int(time.time()),
            }
        ),
        ex=current_app.config["WEBAUTHN_STEP_UP_TTL_SECONDS"],
    )
    return token


def complete_mfa_login(client, secret):
    login_response = login(client)
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"totp_code": pyotp.TOTP(secret, digits=6, interval=30).now()},
    )
    return login_response, mfa_response
