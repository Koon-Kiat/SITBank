from __future__ import annotations

import argparse
import os
import re
import stat
from pathlib import Path

from dotenv import dotenv_values


SECRET_NAMES = {
    "DATABASE_URL": "database_url",
    "MFA_AES256_GCM_KEY_B64": "mfa_aes256_gcm_key_b64",
    "PASSWORD_PEPPER_B64": "password_pepper_b64",
    "REDIS_URL": "redis_url",
    "SECRET_KEY": "secret_key",
    "SESSION_HMAC_KEYS_JSON": "session_hmac_keys_json",
    "MFA_KEK_KEYS_JSON": "mfa_kek_keys_json",
    "WTF_CSRF_SECRET_KEY": "wtf_csrf_secret_key",
}


def _required(values: dict[str, str | None], name: str, default: str | None = None) -> str:
    value = values.get(name) or default or ""
    if not value:
        raise RuntimeError(f"Legacy environment is missing {name}")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise RuntimeError(f"Legacy environment value contains control characters: {name}")
    return value


def _quoted(name: str, value: str) -> str:
    if "'" in value:
        raise RuntimeError(f"Legacy environment value contains a single quote: {name}")
    return f"'{value}'"


def import_legacy_environment(source: Path, destination: Path, public_host: str) -> None:
    if not source.is_absolute() or not source.is_file() or source.is_symlink():
        raise RuntimeError("Legacy environment must be an absolute regular non-symlink file")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", public_host):
        raise RuntimeError("Public host must be a bare hostname")
    if destination.exists() and any(destination.iterdir()):
        raise RuntimeError("Destination is not empty; refusing to overwrite runtime secrets")

    values = dotenv_values(source)
    secrets = {
        target: _required(values, source_name)
        for source_name, target in SECRET_NAMES.items()
    }
    environment = {
        "APP_ENV": "production",
        "COMMON_PASSWORDS_MIN_ENTRIES": _required(
            values,
            "COMMON_PASSWORDS_MIN_ENTRIES",
            "100000",
        ),
        "COMMON_PASSWORDS_PATH": "/run/config/common-passwords.txt",
        "HIBP_CIRCUIT_FAILURE_THRESHOLD": _required(
            values,
            "HIBP_CIRCUIT_FAILURE_THRESHOLD",
            "3",
        ),
        "HIBP_CIRCUIT_OPEN_SECONDS": _required(
            values,
            "HIBP_CIRCUIT_OPEN_SECONDS",
            "300",
        ),
        "HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS": _required(
            values,
            "HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS",
            "2.0",
        ),
        "MFA_ISSUER_NAME": _required(values, "MFA_ISSUER_NAME", "SITBank"),
        "MFA_KEK_ACTIVE_ID": _required(values, "MFA_KEK_ACTIVE_ID"),
        "PASSWORD_PBKDF2_ITERATIONS": _required(
            values,
            "PASSWORD_PBKDF2_ITERATIONS",
            "600000",
        ),
        "SESSION_HMAC_ACTIVE_KEY_ID": _required(
            values,
            "SESSION_HMAC_ACTIVE_KEY_ID",
        ),
        "TRUSTED_PROXY_COUNT": "1",
        "WEBAUTHN_APPROVED_AAGUIDS_PATH": "/run/config/fido-approved-aaguids.json",
        "WEBAUTHN_MDS_CACHE_PATH": "/run/config/fido-mds-cache.json",
        "WEBAUTHN_RP_ID": public_host,
        "WEBAUTHN_RP_ORIGIN": f"https://{public_host}",
    }

    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret_dir = destination / "secrets"
    secret_dir.mkdir(mode=0o700)
    for name, value in secrets.items():
        path = secret_dir / name
        path.write_text(value, encoding="utf-8", newline="")
        path.chmod(stat.S_IRUSR)

    environment_path = destination / "container.env"
    environment_path.write_text(
        "".join(
            f"{name}={_quoted(name, value)}\n"
            for name, value in sorted(environment.items())
        ),
        encoding="utf-8",
        newline="\n",
    )
    environment_path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--public-host", required=True)
    args = parser.parse_args()
    import_legacy_environment(args.source, args.destination, args.public_host)


if __name__ == "__main__":
    main()
