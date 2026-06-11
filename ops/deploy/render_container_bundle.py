from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import stat
from pathlib import Path


SECRET_INPUTS = {
    "DATABASE_URL": "database_url",
    "MFA_AES256_GCM_KEY_B64": "mfa_aes256_gcm_key_b64",
    "PASSWORD_PEPPER_B64": "password_pepper_b64",
    "REDIS_URL": "redis_url",
    "SECRET_KEY": "secret_key",
    "WTF_CSRF_SECRET_KEY": "wtf_csrf_secret_key",
}

NON_SECRET_DEFAULTS = {
    "COMMON_PASSWORDS_MIN_ENTRIES": "100000",
    "HIBP_CIRCUIT_FAILURE_THRESHOLD": "3",
    "HIBP_CIRCUIT_OPEN_SECONDS": "300",
    "HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS": "2.0",
    "PASSWORD_PBKDF2_ITERATIONS": "600000",
    "TRUSTED_PROXY_COUNT": "1",
}

DEPLOYMENT_PREFIXES = {"PROD", "STAGING"}


def _value(name: str, *, default: str | None = None) -> str:
    value = os.environ.get(name, default or "")
    if not value:
        raise RuntimeError(f"Missing deployment value: {name}")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise RuntimeError(f"Deployment value contains control characters: {name}")
    return value


def _validate_prefix(prefix: str) -> None:
    if prefix not in DEPLOYMENT_PREFIXES:
        raise RuntimeError("Deployment prefix must be PROD or STAGING")


def _prefixed(prefix: str, name: str) -> str:
    _validate_prefix(prefix)
    return f"{prefix}_{name}"


def _validate_b64_key(name: str, value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise RuntimeError(f"{name} must be valid base64") from exc
    if len(decoded) != 32:
        raise RuntimeError(f"{name} must decode to exactly 32 bytes")
    return value


def _quote_environment_value(name: str, value: str) -> str:
    if "'" in value:
        raise RuntimeError(f"{name} contains an unsupported single quote")
    return f"'{value}'"


def _active_key_id(prefix: str) -> str:
    active_id_name = _prefixed(prefix, "SESSION_HMAC_ACTIVE_KEY_ID")
    active_id = _value(active_id_name)
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", active_id):
        raise RuntimeError(f"{active_id_name} is invalid")
    return active_id


def _session_keyring(prefix: str) -> tuple[str, str]:
    active_id = _active_key_id(prefix)
    active_key_name = _prefixed(prefix, "SESSION_HMAC_ACTIVE_KEY_B64")
    active_key = _validate_b64_key(
        active_key_name,
        _value(active_key_name),
    )
    keyring = {active_id: active_key}

    previous_id_name = _prefixed(prefix, "SESSION_HMAC_PREVIOUS_KEY_ID")
    previous_key_name = _prefixed(prefix, "SESSION_HMAC_PREVIOUS_KEY_B64")
    previous_id = os.environ.get(previous_id_name, "").strip()
    previous_key = os.environ.get(previous_key_name, "").strip()
    if bool(previous_id) != bool(previous_key):
        raise RuntimeError(
            f"{previous_id_name} and {previous_key_name} must be configured together"
        )
    if previous_id:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", previous_id):
            raise RuntimeError(f"{previous_id_name} is invalid")
        if previous_id == active_id:
            raise RuntimeError("Session HMAC key identifiers must be unique")
        keyring[previous_id] = _validate_b64_key(
            previous_key_name,
            previous_key,
        )
    return active_id, json.dumps(keyring, separators=(",", ":"), sort_keys=True)


def build_container_environment(prefix: str = "PROD") -> dict[str, str]:
    public_host_name = _prefixed(prefix, "PUBLIC_HOST")
    public_host = _value(public_host_name)
    if not re.fullmatch(r"[A-Za-z0-9.-]+", public_host):
        raise RuntimeError(f"{public_host_name} must be a bare hostname")

    environment = {
        "APP_ENV": "production",
        "COMMON_PASSWORDS_PATH": "/run/config/common-passwords.txt",
        "MFA_ISSUER_NAME": _value(_prefixed(prefix, "MFA_ISSUER_NAME"), default="SITBank"),
        "SESSION_HMAC_ACTIVE_KEY_ID": _active_key_id(prefix),
        "WEBAUTHN_APPROVED_AAGUIDS_PATH": "/run/config/fido-approved-aaguids.json",
        "WEBAUTHN_MDS_CACHE_PATH": "/run/config/fido-mds-cache.json",
        "WEBAUTHN_RP_ID": public_host,
        "WEBAUTHN_RP_ORIGIN": f"https://{public_host}",
    }
    for name, default in NON_SECRET_DEFAULTS.items():
        environment[name] = _value(_prefixed(prefix, name), default=default)
    return environment


def build_container_bundle(
    prefix: str = "PROD",
) -> tuple[dict[str, str], dict[str, str]]:
    environment = build_container_environment(prefix)
    active_key_id, keyring = _session_keyring(prefix)
    if environment["SESSION_HMAC_ACTIVE_KEY_ID"] != active_key_id:
        raise RuntimeError("Session HMAC active key identifiers do not match")

    secrets = {
        target: _value(_prefixed(prefix, source))
        for source, target in SECRET_INPUTS.items()
    }
    _validate_b64_key(
        _prefixed(prefix, "MFA_AES256_GCM_KEY_B64"),
        secrets["mfa_aes256_gcm_key_b64"],
    )
    _validate_b64_key(
        _prefixed(prefix, "PASSWORD_PEPPER_B64"),
        secrets["password_pepper_b64"],
    )
    secrets["session_hmac_keys_json"] = keyring
    return environment, secrets


def write_container_bundle(
    output_dir: Path,
    prefix: str = "PROD",
    *,
    include_secrets: bool = True,
) -> None:
    if include_secrets:
        environment, secrets = build_container_bundle(prefix)
    else:
        environment = build_container_environment(prefix)
        secrets = {}

    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)

    environment_text = "".join(
        f"{name}={_quote_environment_value(name, value)}\n"
        for name, value in sorted(environment.items())
    )
    environment_path = output_dir / "container.env"
    environment_path.write_text(environment_text, encoding="utf-8", newline="\n")
    environment_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    if secrets:
        secret_dir = output_dir / "secrets"
        secret_dir.mkdir(mode=0o700)
        for name, value in secrets.items():
            path = secret_dir / name
            path.write_text(value, encoding="utf-8", newline="")
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prefix", choices=sorted(DEPLOYMENT_PREFIXES), default="PROD")
    parser.add_argument(
        "--environment-only",
        action="store_true",
        help="write only non-secret container configuration",
    )
    args = parser.parse_args()
    write_container_bundle(
        args.output,
        prefix=args.prefix,
        include_secrets=not args.environment_only,
    )


if __name__ == "__main__":
    main()
