from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Iterator

from flask import current_app


SESSION_PAYLOAD_FORMAT_VERSION = 2


class SessionPayloadIntegrityError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


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


def sign_session_payload(payload: bytes, *, binding_context: str) -> bytes:
    context = _binding_context(binding_context)
    active_key_id = str(current_app.config["SESSION_HMAC_ACTIVE_KEY_ID"])
    encoded_payload = base64.b64encode(payload).decode("ascii")
    signature = _payload_signature(active_key_id, encoded_payload, context)
    envelope = {
        "v": SESSION_PAYLOAD_FORMAT_VERSION,
        "kid": active_key_id,
        "payload": encoded_payload,
        "sig": signature,
    }
    return json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")


def verify_session_payload(envelope_bytes: bytes, *, binding_context: str) -> bytes:
    context = _binding_context(binding_context)
    try:
        envelope = json.loads(envelope_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SessionPayloadIntegrityError("unsupported_format") from exc

    if not isinstance(envelope, dict):
        raise SessionPayloadIntegrityError("unsupported_format")
    if envelope.get("v") != SESSION_PAYLOAD_FORMAT_VERSION:
        raise SessionPayloadIntegrityError("stale_or_unsupported_format")

    key_id = envelope.get("kid")
    encoded_payload = envelope.get("payload")
    signature = envelope.get("sig")
    if not isinstance(key_id, str) or not isinstance(encoded_payload, str):
        raise SessionPayloadIntegrityError("malformed_payload")
    if not isinstance(signature, str) or not signature:
        raise SessionPayloadIntegrityError("missing_signature")

    keyring = current_app.config["SESSION_HMAC_KEYS"]
    if key_id not in keyring:
        raise SessionPayloadIntegrityError("unknown_key_id")

    expected_signature = _payload_signature(key_id, encoded_payload, context)
    if not hmac.compare_digest(signature, expected_signature):
        raise SessionPayloadIntegrityError("invalid_signature")

    try:
        return base64.b64decode(encoded_payload, validate=True)
    except Exception as exc:
        raise SessionPayloadIntegrityError("malformed_payload") from exc


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
    # HMAC-SHA256 authenticates session payloads and keyed references.
    # lgtm[py/weak-sensitive-data-hashing]
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()[:length]


def _binding_context(binding_context: str) -> str:
    if not isinstance(binding_context, str) or not binding_context:
        raise SessionPayloadIntegrityError("missing_binding_context")
    return binding_context


def _payload_signature(key_id: str, encoded_payload: str, binding_context: str) -> str:
    keyring = current_app.config["SESSION_HMAC_KEYS"]
    signing_input = json.dumps(
        {
            "ctx": binding_context,
            "kid": key_id,
            "payload": encoded_payload,
            "v": SESSION_PAYLOAD_FORMAT_VERSION,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hmac.new(
        bytes(keyring[key_id]),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
