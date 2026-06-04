from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app


def _mfa_key() -> bytes:
    encoded = current_app.config["MFA_AES256_GCM_KEY_B64"]
    key = base64.b64decode(encoded, validate=True)
    if len(key) != 32:
        raise RuntimeError("MFA_AES256_GCM_KEY_B64 must decode to exactly 32 bytes")
    return key


def _associated_data(user_id: int) -> bytes:
    return f"osp-bank:mfa-secret:user:{user_id}".encode("utf-8")


def encrypt_mfa_secret(secret: str, user_id: int) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(_mfa_key())
    ciphertext = aesgcm.encrypt(
        nonce,
        secret.encode("utf-8"),
        _associated_data(user_id),
    )
    return nonce, ciphertext


def decrypt_mfa_secret(nonce: bytes, ciphertext: bytes, user_id: int) -> str:
    aesgcm = AESGCM(_mfa_key())
    plaintext = aesgcm.decrypt(nonce, ciphertext, _associated_data(user_id))
    return plaintext.decode("utf-8")
