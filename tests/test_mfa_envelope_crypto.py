from __future__ import annotations

import base64
import json
import secrets

import pyotp
import pytest
from cryptography.exceptions import InvalidTag

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
from config import _required_keyring, _required_session_hmac_keys


def _user(username: str = "alice01", full_name: str = "Alice User", phone_number: str = "91234567") -> User:
    account_number = "012" + "".join(str(secrets.randbelow(10)) for _ in range(6))
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        full_name=full_name,
        phone_number=phone_number,
        account_number=account_number,
    )
    db.session.add(user)
    db.session.commit()
    return user


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


def test_test_config_active_key_ids_exist_in_keyrings(app):
    assert app.config["MFA_KEK_ACTIVE_ID"] in app.config["MFA_KEK_KEYS"]
    assert app.config["SESSION_HMAC_ACTIVE_KEY_ID"] in app.config["SESSION_HMAC_KEYS"]


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


def test_non_envelope_mfa_secret_fails_closed(app):
    user = _user()

    with pytest.raises(MFASecretEnvelopeError, match="envelope"):
        decrypt_mfa_secret(b"legacy000001", b"not-an-envelope", user.id)


def test_rewrap_mfa_deks_command_updates_matching_envelopes(app):
    user = _user()
    other = _user("bob02", full_name="Bob Test", phone_number="81234567")
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


def test_rewrap_mfa_deks_preflight_requires_configured_target_kek(app):
    result = app.test_cli_runner().invoke(
        args=[
            "rewrap-mfa-deks",
            "--from-kek-id",
            "test-mfa-previous",
            "--to-kek-id",
            "missing-target",
            "--dry-run",
        ]
    )
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="mfa_dek_rewrap",
        outcome="failure",
    ).one()

    assert result.exit_code != 0
    assert "Target MFA KEK id is not configured" in result.output
    assert "add the new KEK id to MFA_KEK_KEYS_JSON" in result.output
    assert event.event_metadata["stage"] == "preflight"
    assert event.event_metadata["reason"] == "missing_target_kek"
    assert event.event_metadata["dry_run"] is True
    assert "missing-target" in str(event.event_metadata)
    assert "44444444444444444444444444444444" not in str(event.event_metadata)


def test_rewrap_mfa_deks_dry_run_reports_without_writing(app):
    user = _user()
    secret = pyotp.random_base32(length=32)
    user.mfa_secret_nonce, user.mfa_secret_ciphertext = encrypt_mfa_secret(
        secret,
        user.id,
        kek_id="test-mfa-previous",
    )
    original_ciphertext = user.mfa_secret_ciphertext
    db.session.commit()

    result = app.test_cli_runner().invoke(
        args=[
            "rewrap-mfa-deks",
            "--from-kek-id",
            "test-mfa-previous",
            "--to-kek-id",
            "test-mfa-current",
            "--dry-run",
        ]
    )

    assert result.exit_code == 0, result.output
    assert "scanned=1 updated=1" in result.output
    assert "failures=0 dry_run=True" in result.output
    db.session.refresh(user)
    assert user.mfa_secret_ciphertext == original_ciphertext
    assert mfa_envelope_kek_id(user.mfa_secret_nonce, user.mfa_secret_ciphertext) == "test-mfa-previous"
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="mfa_dek_rewrap",
        outcome="success",
    ).order_by(SecurityAuditEvent.id.desc()).first()
    assert event is not None
    assert event.event_metadata["dry_run"] is True
    assert event.event_metadata["scanned"] == 1
    assert event.event_metadata["updated"] == 1
    assert "secret_ciphertext" not in str(event.event_metadata)


def test_rewrap_mfa_deks_rolls_back_all_user_rows_on_failure(app, monkeypatch):
    from app.ops import commands

    first = _user()
    second = _user("bob02", full_name="Bob Test", phone_number="81234567")
    first_secret = pyotp.random_base32(length=32)
    second_secret = pyotp.random_base32(length=32)
    first.mfa_secret_nonce, first.mfa_secret_ciphertext = encrypt_mfa_secret(
        first_secret,
        first.id,
        kek_id="test-mfa-previous",
    )
    second.mfa_secret_nonce, second.mfa_secret_ciphertext = encrypt_mfa_secret(
        second_secret,
        second.id,
        kek_id="test-mfa-previous",
    )
    db.session.commit()
    real_rewrap = commands.rewrap_mfa_dek
    calls: list[int] = []

    def fail_after_first_user(*args, **kwargs):
        calls.append(args[2])
        if len(calls) == 2:
            raise RuntimeError("simulated rewrap failure")
        return real_rewrap(*args, **kwargs)

    monkeypatch.setattr(commands, "rewrap_mfa_dek", fail_after_first_user)

    result = app.test_cli_runner().invoke(
        args=[
            "rewrap-mfa-deks",
            "--from-kek-id",
            "test-mfa-previous",
            "--to-kek-id",
            "test-mfa-current",
        ]
    )

    assert result.exit_code != 0
    assert "MFA DEK rewrap failed; no changes were committed" in result.output
    db.session.refresh(first)
    db.session.refresh(second)
    assert mfa_envelope_kek_id(first.mfa_secret_nonce, first.mfa_secret_ciphertext) == "test-mfa-previous"
    assert mfa_envelope_kek_id(second.mfa_secret_nonce, second.mfa_secret_ciphertext) == "test-mfa-previous"
    assert decrypt_mfa_secret(first.mfa_secret_nonce, first.mfa_secret_ciphertext, first.id) == first_secret
    assert decrypt_mfa_secret(second.mfa_secret_nonce, second.mfa_secret_ciphertext, second.id) == second_secret
    event = db.session.query(SecurityAuditEvent).filter_by(
        event_type="mfa_dek_rewrap",
        outcome="failure",
    ).order_by(SecurityAuditEvent.id.desc()).first()
    assert event is not None
    assert event.event_metadata["scanned"] == 2
    assert event.event_metadata["updated"] == 1
    assert event.event_metadata["failures"] == 1
    assert event.event_metadata["reason"] == "ClickException"


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


def test_keyring_config_rejects_duplicate_normalized_identifiers(monkeypatch):
    key = base64.b64encode(b"6" * 32).decode("ascii")
    monkeypatch.setenv(
        "BAD_MFA_KEYS_JSON",
        json.dumps({"dup": key, " dup ": key}),
    )
    with pytest.raises(RuntimeError, match="duplicate key identifiers"):
        _required_keyring(
            "BAD_MFA_KEYS_JSON",
            active_key_id="dup",
            active_label="ACTIVE",
        )

    monkeypatch.setenv(
        "BAD_SESSION_KEYS_JSON",
        json.dumps({"dup": key, " dup ": key}),
    )
    with pytest.raises(RuntimeError, match="duplicate key identifiers"):
        _required_session_hmac_keys(
            "BAD_SESSION_KEYS_JSON",
            active_key_id="dup",
        )
