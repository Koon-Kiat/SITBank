from __future__ import annotations

import base64
import json

import pyotp
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.auth.services import _mfa_secret_for_user
from app.extensions import db
from app.models import SecurityAuditEvent, User
from app.security.crypto import (
    ENVELOPE_NONCE_MARKER,
    MFASecretEnvelopeError,
    decrypt_mfa_secret,
    encrypt_mfa_secret,
    is_enveloped_mfa_secret,
    mfa_envelope_kek_id,
    rewrap_mfa_dek,
)
from app.security.passwords import hash_password
from config import _required_keyring


def _user(username: str = "alice01") -> User:
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash=hash_password("correct horse battery staple"),
    )
    db.session.add(user)
    db.session.commit()
    return user


def _legacy_encrypt(secret: str, user_id: int, key: bytes = b"0" * 32) -> tuple[bytes, bytes]:
    nonce = b"legacy000001"
    ciphertext = AESGCM(key).encrypt(
        nonce,
        secret.encode("utf-8"),
        f"osp-bank:mfa-secret:user:{user_id}".encode("utf-8"),
    )
    return nonce, ciphertext


def _envelope(ciphertext: bytes) -> dict[str, str | int]:
    payload = json.loads(ciphertext.decode("utf-8"))
    assert isinstance(payload, dict)
    return payload


def _tamper_b64(payload: dict[str, str | int], field: str) -> bytes:
    raw = bytearray(base64.b64decode(str(payload[field]), validate=True))
    raw[-1] ^= 1
    payload[field] = base64.b64encode(bytes(raw)).decode("ascii")
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def test_mfa_secret_envelope_hides_plaintext_and_uses_active_kek(app):
    user = _user()
    secret = pyotp.random_base32(length=32)

    nonce, ciphertext = encrypt_mfa_secret(secret, user.id)
    payload = _envelope(ciphertext)

    assert nonce == ENVELOPE_NONCE_MARKER
    assert is_enveloped_mfa_secret(nonce, ciphertext)
    assert payload["kek_id"] == "test-mfa-current"
    assert secret.encode("utf-8") not in ciphertext
    assert b"44444444444444444444444444444444" not in ciphertext
    assert decrypt_mfa_secret(nonce, ciphertext, user.id) == secret


def test_mfa_secret_envelope_is_bound_to_user_kek_and_ciphertext(app):
    user = _user()
    secret = pyotp.random_base32(length=32)
    nonce, ciphertext = encrypt_mfa_secret(secret, user.id)
    payload = _envelope(ciphertext)

    with pytest.raises(InvalidTag):
        decrypt_mfa_secret(nonce, ciphertext, user.id + 1)

    with pytest.raises(InvalidTag):
        decrypt_mfa_secret(nonce, _tamper_b64(dict(payload), "secret_ciphertext"), user.id)

    with pytest.raises(InvalidTag):
        decrypt_mfa_secret(nonce, _tamper_b64(dict(payload), "dek_wrapped"), user.id)

    original_keys = dict(app.config["MFA_KEK_KEYS"])
    try:
        app.config["MFA_KEK_KEYS"] = {}
        with pytest.raises(MFASecretEnvelopeError):
            decrypt_mfa_secret(nonce, ciphertext, user.id)
    finally:
        app.config["MFA_KEK_KEYS"] = original_keys


def test_old_kek_records_decrypt_and_new_records_use_active_kek(app):
    user = _user()
    old_secret = pyotp.random_base32(length=32)
    new_secret = pyotp.random_base32(length=32)

    old_nonce, old_ciphertext = encrypt_mfa_secret(
        old_secret,
        user.id,
        kek_id="test-mfa-previous",
    )
    new_nonce, new_ciphertext = encrypt_mfa_secret(new_secret, user.id)

    assert mfa_envelope_kek_id(old_nonce, old_ciphertext) == "test-mfa-previous"
    assert mfa_envelope_kek_id(new_nonce, new_ciphertext) == "test-mfa-current"
    assert decrypt_mfa_secret(old_nonce, old_ciphertext, user.id) == old_secret
    assert decrypt_mfa_secret(new_nonce, new_ciphertext, user.id) == new_secret


def test_rewrap_changes_only_kek_wrapper_and_preserves_secret(app):
    user = _user()
    secret = pyotp.random_base32(length=32)
    nonce, ciphertext = encrypt_mfa_secret(secret, user.id, kek_id="test-mfa-previous")
    before = _envelope(ciphertext)

    rewrapped_nonce, rewrapped_ciphertext = rewrap_mfa_dek(
        nonce,
        ciphertext,
        user.id,
        from_kek_id="test-mfa-previous",
        to_kek_id="test-mfa-current",
    )
    after = _envelope(rewrapped_ciphertext)

    assert rewrapped_nonce == ENVELOPE_NONCE_MARKER
    assert after["kek_id"] == "test-mfa-current"
    assert after["secret_ciphertext"] == before["secret_ciphertext"]
    assert after["secret_nonce"] == before["secret_nonce"]
    assert after["dek_wrapped"] != before["dek_wrapped"]
    assert decrypt_mfa_secret(rewrapped_nonce, rewrapped_ciphertext, user.id) == secret


def test_legacy_mfa_secret_is_lazy_migrated_on_use(app):
    user = _user()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = _legacy_encrypt(secret, user.id)
    db.session.commit()

    with app.test_request_context("/mfa"):
        assert _mfa_secret_for_user(user) == secret

    db.session.refresh(user)
    assert user.mfa_secret_nonce == ENVELOPE_NONCE_MARKER
    assert decrypt_mfa_secret(user.mfa_secret_nonce, user.mfa_secret_ciphertext, user.id) == secret
    event = db.session.execute(
        db.select(SecurityAuditEvent).where(
            SecurityAuditEvent.event_type == "mfa_secret_reencrypted"
        )
    ).scalar_one()
    assert secret not in json.dumps(event.event_metadata)


def test_rotate_mfa_encryption_command_reencrypts_legacy_records(app):
    user = _user()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = _legacy_encrypt(secret, user.id)
    db.session.commit()

    result = app.test_cli_runner().invoke(
        args=["rotate-mfa-encryption", "--to-kek-id", "test-mfa-previous"]
    )

    assert result.exit_code == 0, result.output
    db.session.refresh(user)
    assert mfa_envelope_kek_id(user.mfa_secret_nonce, user.mfa_secret_ciphertext) == "test-mfa-previous"
    assert decrypt_mfa_secret(user.mfa_secret_nonce, user.mfa_secret_ciphertext, user.id) == secret
    events = db.session.execute(
        db.select(SecurityAuditEvent).where(
            SecurityAuditEvent.event_type == "mfa_encryption_rotation"
        )
    ).scalars().all()
    assert {event.outcome for event in events} == {"started", "success"}
    assert secret not in json.dumps([event.event_metadata for event in events])


def test_rewrap_mfa_deks_command_updates_matching_envelopes(app):
    user = _user()
    other = _user("bob02")
    secret = pyotp.random_base32(length=32)
    other_secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(
        secret,
        user.id,
        kek_id="test-mfa-previous",
    )
    other.mfa_secret_nonce, other.mfa_secret_ciphertext = encrypt_mfa_secret(other_secret, other.id)
    db.session.commit()

    result = app.test_cli_runner().invoke(
        args=[
            "rewrap-mfa-deks",
            "--from-kek-id",
            "test-mfa-previous",
            "--to-kek-id",
            "test-mfa-current",
        ]
    )

    assert result.exit_code == 0, result.output
    db.session.refresh(user)
    db.session.refresh(other)
    assert mfa_envelope_kek_id(user.mfa_secret_nonce, user.mfa_secret_ciphertext) == "test-mfa-current"
    assert mfa_envelope_kek_id(other.mfa_secret_nonce, other.mfa_secret_ciphertext) == "test-mfa-current"
    assert decrypt_mfa_secret(user.mfa_secret_nonce, user.mfa_secret_ciphertext, user.id) == secret
    assert decrypt_mfa_secret(other.mfa_secret_nonce, other.mfa_secret_ciphertext, other.id) == other_secret


def test_mfa_keyring_config_fails_closed(monkeypatch):
    monkeypatch.setenv(
        "BAD_MFA_KEYS_JSON",
        '{"old":"NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU="}',
    )
    with pytest.raises(RuntimeError, match="ACTIVE"):
        _required_keyring(
            "BAD_MFA_KEYS_JSON",
            active_key_id="missing",
            active_label="ACTIVE",
        )

    monkeypatch.setenv("BAD_MFA_KEYS_JSON", '{"bad":"short"}')
    with pytest.raises(RuntimeError, match="valid base64"):
        _required_keyring(
            "BAD_MFA_KEYS_JSON",
            active_key_id="bad",
            active_label="ACTIVE",
        )

    monkeypatch.setenv("BAD_MFA_KEYS_JSON", '{"bad":"c2hvcnQ="}')
    with pytest.raises(RuntimeError, match="exactly 32 bytes"):
        _required_keyring(
            "BAD_MFA_KEYS_JSON",
            active_key_id="bad",
            active_label="ACTIVE",
        )
