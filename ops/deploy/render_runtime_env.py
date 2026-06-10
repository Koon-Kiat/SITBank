from __future__ import annotations

import base64
import binascii
import json
import os
import re
import sys


FIXED_VALUES = {
    "APP_ENV": "production",
    "COMMON_PASSWORDS_MIN_ENTRIES": "100000",
    "HIBP_CIRCUIT_FAILURE_THRESHOLD": "3",
    "HIBP_CIRCUIT_OPEN_SECONDS": "300",
    "HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS": "2.0",
    "TRUSTED_PROXY_COUNT": "1",
    "WEBAUTHN_RP_ORIGIN": "https://{PROD_PUBLIC_HOST}",
    "WEBAUTHN_RP_ID": "{PROD_PUBLIC_HOST}",
}

REQUIRED_ENVIRONMENT_VALUES = (
    "COMMON_PASSWORDS_PATH",
    "DATABASE_URL",
    "MFA_AES256_GCM_KEY_B64",
    "MFA_ISSUER_NAME",
    "PASSWORD_PBKDF2_ITERATIONS",
    "PASSWORD_PEPPER_B64",
    "PROD_PUBLIC_HOST",
    "REDIS_URL",
    "SECRET_KEY",
    "SESSION_HMAC_ACTIVE_KEY_B64",
    "SESSION_HMAC_ACTIVE_KEY_ID",
    "WEBAUTHN_APPROVED_AAGUIDS_PATH",
    "WEBAUTHN_MDS_CACHE_PATH",
    "WTF_CSRF_SECRET_KEY",
)


def _environment_value(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing deployment value: {name}")
    if "\n" in value or "\r" in value or "\x00" in value:
        raise RuntimeError(f"Deployment value contains unsupported control characters: {name}")
    return value


def _quote_environment_file_value(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _validate_hmac_key(name: str, value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise RuntimeError(f"{name} must be valid base64") from exc
    if len(decoded) != 32:
        raise RuntimeError(f"{name} must decode to exactly 32 bytes")
    return value


def render_runtime_environment() -> str:
    values = {name: _environment_value(name) for name in REQUIRED_ENVIRONMENT_VALUES}
    public_host = values.pop("PROD_PUBLIC_HOST")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", public_host):
        raise RuntimeError("PROD_PUBLIC_HOST must be a bare hostname")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", values["SESSION_HMAC_ACTIVE_KEY_ID"]):
        raise RuntimeError("SESSION_HMAC_ACTIVE_KEY_ID is invalid")

    active_key = _validate_hmac_key(
        "SESSION_HMAC_ACTIVE_KEY_B64",
        values.pop("SESSION_HMAC_ACTIVE_KEY_B64"),
    )
    keyring = {values["SESSION_HMAC_ACTIVE_KEY_ID"]: active_key}
    previous_key_id = os.environ.get("SESSION_HMAC_PREVIOUS_KEY_ID", "").strip()
    previous_key = os.environ.get("SESSION_HMAC_PREVIOUS_KEY_B64", "").strip()
    if bool(previous_key_id) != bool(previous_key):
        raise RuntimeError(
            "SESSION_HMAC_PREVIOUS_KEY_ID and SESSION_HMAC_PREVIOUS_KEY_B64 "
            "must be configured together"
        )
    if previous_key_id:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", previous_key_id):
            raise RuntimeError("SESSION_HMAC_PREVIOUS_KEY_ID is invalid")
        if previous_key_id in keyring:
            raise RuntimeError("Session HMAC key identifiers must be unique")
        keyring[previous_key_id] = _validate_hmac_key(
            "SESSION_HMAC_PREVIOUS_KEY_B64",
            previous_key,
        )
    values["SESSION_HMAC_KEYS_JSON"] = json.dumps(
        keyring,
        separators=(",", ":"),
        sort_keys=True,
    )

    for name, value in FIXED_VALUES.items():
        values[name] = value.format(PROD_PUBLIC_HOST=public_host)
    return "\n".join(
        f"{name}={_quote_environment_file_value(values[name])}"
        for name in sorted(values)
    ) + "\n"


if __name__ == "__main__":
    try:
        sys.stdout.write(render_runtime_environment())
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
