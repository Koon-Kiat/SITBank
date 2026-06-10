from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterator

from flask import current_app


def active_hmac_hex(message: str, *, length: int) -> str:
    return _digest(_active_key(), message, length)


def candidate_hmac_hex(message: str, *, length: int) -> Iterator[str]:
    for key in _configured_keys():
        yield _digest(key, message, length)


def matches_hmac(expected: str, message: str, *, length: int) -> bool:
    return any(
        hmac.compare_digest(str(expected), candidate)
        for candidate in candidate_hmac_hex(message, length=length)
    )


def validate_session_hmac_config() -> int:
    keyring = current_app.config.get("SESSION_HMAC_KEYS")
    active_key_id = str(current_app.config.get("SESSION_HMAC_ACTIVE_KEY_ID") or "")
    if not isinstance(keyring, dict) or not keyring:
        raise RuntimeError("At least one session HMAC key is required")
    if active_key_id not in keyring:
        raise RuntimeError("The active session HMAC key is not configured")
    for key_id, key in keyring.items():
        if not str(key_id).strip() or len(bytes(key)) != 32:
            raise RuntimeError("Every session HMAC key must have an identifier and be 32 bytes")
    return len(keyring)


def _active_key() -> bytes:
    active_key_id = str(current_app.config["SESSION_HMAC_ACTIVE_KEY_ID"])
    keyring = current_app.config["SESSION_HMAC_KEYS"]
    return bytes(keyring[active_key_id])


def _configured_keys() -> Iterator[bytes]:
    keyring = current_app.config["SESSION_HMAC_KEYS"]
    active_key_id = str(current_app.config["SESSION_HMAC_ACTIVE_KEY_ID"])
    yield bytes(keyring[active_key_id])
    for key_id, key in keyring.items():
        if str(key_id) != active_key_id:
            yield bytes(key)


def _digest(key: bytes, message: str, length: int) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()[:length]
