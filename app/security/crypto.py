from __future__ import annotations

import base64
import binascii
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app


ENVELOPE_NONCE_MARKER = b"SITMFAENV001"
ENVELOPE_VERSION = 1
ENVELOPE_ALGORITHM = "AES-256-GCM"


class MFASecretEnvelopeError(ValueError):
    """Raised when an MFA secret envelope is malformed or cannot decrypt."""


def _associated_data(user_id: int, kek_id: str, part: str) -> bytes:
    if part == "secret":
        return (
            f"sitbank:mfa-secret:v{ENVELOPE_VERSION}:user:{user_id}:"
            "part:secret"
        ).encode("utf-8")
    return (
        f"sitbank:mfa-secret:v{ENVELOPE_VERSION}:user:{user_id}:"
        f"kek:{kek_id}:part:{part}"
    ).encode("utf-8")


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise MFASecretEnvelopeError(f"{field} must be base64 text")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise MFASecretEnvelopeError(f"{field} must be valid base64") from exc


def _kek(kek_id: str) -> bytes:
    keys = current_app.config["MFA_KEK_KEYS"]
    try:
        return keys[kek_id]
    except KeyError as exc:
        _audit_mfa_crypto("decrypt", "failure", metadata={"reason": "unknown_kek_id", "kek_id": kek_id})
        raise MFASecretEnvelopeError("Unknown MFA KEK identifier") from exc


def _active_kek() -> tuple[str, bytes]:
    kek_id = current_app.config["MFA_KEK_ACTIVE_ID"]
    return kek_id, _kek(kek_id)


def is_enveloped_mfa_secret(nonce: bytes | None, ciphertext: bytes | None) -> bool:
    return nonce == ENVELOPE_NONCE_MARKER and bool(ciphertext)


def mfa_envelope_kek_id(nonce: bytes, ciphertext: bytes) -> str | None:
    if not is_enveloped_mfa_secret(nonce, ciphertext):
        return None
    envelope = _load_envelope(ciphertext)
    return str(envelope["kek_id"])


def encrypt_mfa_secret(
    secret: str,
    user_id: int,
    *,
    kek_id: str | None = None,
) -> tuple[bytes, bytes]:
    selected_kek_id, kek = _active_kek() if kek_id is None else (kek_id, _kek(kek_id))
    dek = os.urandom(32)
    dek_nonce = os.urandom(12)
    secret_nonce = os.urandom(12)

    secret_ciphertext = AESGCM(dek).encrypt(
        secret_nonce,
        secret.encode("utf-8"),
        _associated_data(user_id, selected_kek_id, "secret"),
    )
    wrapped_dek = AESGCM(kek).encrypt(
        dek_nonce,
        dek,
        _associated_data(user_id, selected_kek_id, "dek"),
    )
    envelope = {
        "v": ENVELOPE_VERSION,
        "alg": ENVELOPE_ALGORITHM,
        "kek_id": selected_kek_id,
        "dek_wrapped": _b64encode(wrapped_dek),
        "dek_nonce": _b64encode(dek_nonce),
        "secret_ciphertext": _b64encode(secret_ciphertext),
        "secret_nonce": _b64encode(secret_nonce),
    }
    _audit_mfa_crypto("encrypt", "success", user_id=user_id, metadata={"kek_id": selected_kek_id})
    return ENVELOPE_NONCE_MARKER, json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")


def decrypt_mfa_secret(nonce: bytes, ciphertext: bytes, user_id: int) -> str:
    if is_enveloped_mfa_secret(nonce, ciphertext):
        return _decrypt_envelope(ciphertext, user_id)
    _audit_mfa_crypto("decrypt", "failure", user_id=user_id, metadata={"reason": "unsupported_format"})
    raise MFASecretEnvelopeError("MFA secret envelope is required")


def rewrap_mfa_dek(
    nonce: bytes,
    ciphertext: bytes,
    user_id: int,
    *,
    to_kek_id: str,
    from_kek_id: str | None = None,
) -> tuple[bytes, bytes]:
    if not is_enveloped_mfa_secret(nonce, ciphertext):
        raise MFASecretEnvelopeError("Legacy MFA secret must be re-encrypted, not rewrapped")
    envelope = _load_envelope(ciphertext)
    current_kek_id = str(envelope["kek_id"])
    if from_kek_id is not None and current_kek_id != from_kek_id:
        raise MFASecretEnvelopeError("Envelope KEK identifier does not match from_kek_id")
    if current_kek_id == to_kek_id:
        return nonce, ciphertext

    dek = _unwrap_dek(envelope, user_id)
    new_dek_nonce = os.urandom(12)
    wrapped_dek = AESGCM(_kek(to_kek_id)).encrypt(
        new_dek_nonce,
        dek,
        _associated_data(user_id, to_kek_id, "dek"),
    )
    envelope["kek_id"] = to_kek_id
    envelope["dek_nonce"] = _b64encode(new_dek_nonce)
    envelope["dek_wrapped"] = _b64encode(wrapped_dek)
    _audit_mfa_crypto(
        "rewrap",
        "success",
        user_id=user_id,
        metadata={"from_kek_id": current_kek_id, "to_kek_id": to_kek_id},
    )
    return ENVELOPE_NONCE_MARKER, json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")

def _decrypt_envelope(ciphertext: bytes, user_id: int) -> str:
    envelope = _load_envelope(ciphertext)
    kek_id = str(envelope["kek_id"])
    try:
        dek = _unwrap_dek(envelope, user_id)
        secret_plaintext = AESGCM(dek).decrypt(
            _b64decode(envelope["secret_nonce"], "secret_nonce"),
            _b64decode(envelope["secret_ciphertext"], "secret_ciphertext"),
            _associated_data(user_id, kek_id, "secret"),
        )
    except (InvalidTag, MFASecretEnvelopeError, KeyError) as exc:
        _audit_mfa_crypto("decrypt", "failure", user_id=user_id, metadata={"reason": type(exc).__name__, "kek_id": kek_id})
        raise
    return secret_plaintext.decode("utf-8")


def _unwrap_dek(envelope: dict[str, Any], user_id: int) -> bytes:
    kek_id = str(envelope["kek_id"])
    try:
        return AESGCM(_kek(kek_id)).decrypt(
            _b64decode(envelope["dek_nonce"], "dek_nonce"),
            _b64decode(envelope["dek_wrapped"], "dek_wrapped"),
            _associated_data(user_id, kek_id, "dek"),
        )
    except InvalidTag:
        _audit_mfa_crypto("decrypt", "failure", user_id=user_id, metadata={"reason": "dek_invalid_tag", "kek_id": kek_id})
        raise


def _load_envelope(ciphertext: bytes) -> dict[str, Any]:
    try:
        envelope = json.loads(ciphertext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MFASecretEnvelopeError("MFA envelope must be valid JSON") from exc
    if not isinstance(envelope, dict):
        raise MFASecretEnvelopeError("MFA envelope must be a JSON object")
    required = {
        "v",
        "alg",
        "kek_id",
        "dek_wrapped",
        "dek_nonce",
        "secret_ciphertext",
        "secret_nonce",
    }
    if set(envelope) != required:
        raise MFASecretEnvelopeError("MFA envelope fields are invalid")
    if envelope["v"] != ENVELOPE_VERSION or envelope["alg"] != ENVELOPE_ALGORITHM:
        raise MFASecretEnvelopeError("MFA envelope version or algorithm is unsupported")
    if not isinstance(envelope["kek_id"], str) or not envelope["kek_id"]:
        raise MFASecretEnvelopeError("MFA envelope KEK identifier is invalid")
    return envelope


def _audit_mfa_crypto(
    action: str,
    outcome: str,
    *,
    user_id: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    try:
        from app.security.audit import audit_event

        audit_event(f"mfa_secret_{action}", outcome, user_id=user_id, metadata=metadata or {})
    except Exception:
        pass
