from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import stat
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ops.runtime_contract import (
    ADMIN_APP_SECRET_INPUTS,
    CUSTOMER_APP_SECRET_INPUTS,
    DEPLOYMENT_SECRET_INPUTS,
    NON_SECRET_DEFAULTS as RUNTIME_NON_SECRET_DEFAULTS,
    PRODUCTION_SECRET_INPUTS,
)

SECRET_INPUTS = dict(PRODUCTION_SECRET_INPUTS)
NON_SECRET_DEFAULTS = dict(RUNTIME_NON_SECRET_DEFAULTS)
CUSTOMER_SECRET_INPUTS = dict(CUSTOMER_APP_SECRET_INPUTS)
ADMIN_SECRET_INPUTS = dict(ADMIN_APP_SECRET_INPUTS)

DEPLOYMENT_PREFIXES = {"PROD", "STAGING"}

DEPLOYMENT_PROFILES = {
    "PROD": {
        "ADMIN_APP_BIND_HOST": "127.0.0.1",
        "ADMIN_APP_BIND_PORT": "5002",
        "ADMIN_APP_CONTAINER_NAME": "sitbank-admin",
        "ADMIN_PUBLIC_HOST": "admin-sitbank.duckdns.org",
        "APP_BIND_HOST": "127.0.0.1",
        "APP_BIND_PORT": "5000",
        "APP_CONTAINER_NAME": "sitbank-app",
        "COMPOSE_DIR": "/opt/sitbank",
        "COMPOSE_FILE": "/opt/sitbank/compose.yml",
        "COMPOSE_PROJECT_NAME": "sitbank",
        "CONFIG_ROOT": "/etc/sitbank",
        "DEPLOYMENT_TARGET": "production",
        "POSTGRES_CONTAINER_NAME": "none",
        "POSTGRES_VOLUME_NAME": "none",
        "REDIS_CONTAINER_NAME": "none",
        "REDIS_VOLUME_NAME": "none",
        "SECRET_ROOT": "/etc/sitbank/secrets",
        "STATE_DIR": "/var/lib/sitbank-container",
        "SYSTEMD_SERVICE": "sitbank-container.service",
    },
    "STAGING": {
        "APP_BIND_HOST": "127.0.0.1",
        "APP_BIND_PORT": "5001",
        "APP_CONTAINER_NAME": "sitbank-staging-app",
        "COMPOSE_DIR": "/opt/sitbank-staging",
        "COMPOSE_FILE": "/opt/sitbank-staging/compose.yml",
        "COMPOSE_PROJECT_NAME": "sitbank-staging",
        "CONFIG_ROOT": "/etc/sitbank-staging",
        "DEPLOYMENT_TARGET": "staging",
        "POSTGRES_CONTAINER_NAME": "sitbank-staging-postgres",
        "POSTGRES_VOLUME_NAME": "sitbank-staging-postgres-data",
        "REDIS_CONTAINER_NAME": "sitbank-staging-redis",
        "REDIS_VOLUME_NAME": "sitbank-staging-redis-data",
        "SECRET_ROOT": "/etc/sitbank-staging/secrets",
        "STATE_DIR": "/var/lib/sitbank-staging-container",
        "SYSTEMD_SERVICE": "sitbank-staging-container.service",
    },
}


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


def _validate_key_id(name: str, value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", value):
        raise RuntimeError(f"{name} is invalid")
    return value


def _validate_keyring(name: str, value: str, *, active_key_id: str) -> str:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{name} must be a JSON object") from exc
    if not isinstance(payload, dict) or not payload:
        raise RuntimeError(f"{name} must contain at least one key")
    normalized_key_ids: set[str] = set()
    for key_id, encoded_key in payload.items():
        normalized_key_id = _validate_key_id(f"{name} key identifier", str(key_id).strip())
        if normalized_key_id in normalized_key_ids:
            raise RuntimeError(f"{name} contains duplicate key identifiers after normalization")
        normalized_key_ids.add(normalized_key_id)
        _validate_b64_key(f"{name} key {normalized_key_id}", str(encoded_key))
    if active_key_id not in normalized_key_ids:
        raise RuntimeError(f"{name} must contain the active key id")
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


def _admin_active_key_id(prefix: str) -> str:
    active_id_name = _prefixed(prefix, "ADMIN_SESSION_HMAC_ACTIVE_KEY_ID")
    active_id = _value(active_id_name)
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", active_id):
        raise RuntimeError(f"{active_id_name} is invalid")
    return active_id


def _admin_session_keyring(prefix: str) -> tuple[str, str]:
    active_id = _admin_active_key_id(prefix)
    active_key_name = _prefixed(prefix, "ADMIN_SESSION_HMAC_ACTIVE_KEY_B64")
    active_key = _validate_b64_key(
        active_key_name,
        _value(active_key_name),
    )
    keyring = {active_id: active_key}

    previous_id_name = _prefixed(prefix, "ADMIN_SESSION_HMAC_PREVIOUS_KEY_ID")
    previous_key_name = _prefixed(prefix, "ADMIN_SESSION_HMAC_PREVIOUS_KEY_B64")
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
            raise RuntimeError("Admin session HMAC key identifiers must be unique")
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
        "MFA_KEK_ACTIVE_ID": _validate_key_id(
            _prefixed(prefix, "MFA_KEK_ACTIVE_ID"),
            _value(_prefixed(prefix, "MFA_KEK_ACTIVE_ID")),
        ),
        "MFA_ISSUER_NAME": _value(_prefixed(prefix, "MFA_ISSUER_NAME"), default="SITBank"),
        "PASSWORD_RESET_BASE_URL": f"https://{public_host}",
        "PASSWORD_RESET_EMAIL_FROM": _value(_prefixed(prefix, "PASSWORD_RESET_EMAIL_FROM")),
        "SESSION_HMAC_ACTIVE_KEY_ID": _active_key_id(prefix),
        "SMTP_HOST": _value(_prefixed(prefix, "SMTP_HOST")),
    }
    for name, default in NON_SECRET_DEFAULTS.items():
        if prefix == "PROD" and name == "SECURITY_AUDIT_ANCHOR_PATH":
            default = "/var/lib/sitbank/security-audit.anchor"
        environment[name] = _value(_prefixed(prefix, name), default=default)
    environment["ADMIN_SESSION_HMAC_ACTIVE_KEY_ID"] = _admin_active_key_id(prefix)
    if prefix == "PROD":
        environment["ADMIN_SESSION_KEY_PREFIX"] = _value(
            _prefixed(prefix, "ADMIN_SESSION_KEY_PREFIX"),
            default="admin-session:",
        )
        environment["ADMIN_RATELIMIT_KEY_PREFIX"] = _value(
            _prefixed(prefix, "ADMIN_RATELIMIT_KEY_PREFIX"),
            default="ospbank:admin:ratelimit:",
        )
    return environment


def build_deployment_environment(prefix: str = "PROD") -> dict[str, str]:
    _validate_prefix(prefix)
    environment = dict(DEPLOYMENT_PROFILES[prefix])
    environment["PUBLIC_HOST"] = _value(_prefixed(prefix, "PUBLIC_HOST"))
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
        for source, target in DEPLOYMENT_SECRET_INPUTS.items()
        if source in CUSTOMER_SECRET_INPUTS or source in {"DATABASE_MIGRATION_URL"}
    }
    _validate_keyring(
        _prefixed(prefix, "MFA_KEK_KEYS_JSON"),
        secrets["mfa_kek_keys_json"],
        active_key_id=environment["MFA_KEK_ACTIVE_ID"],
    )
    _validate_b64_key(
        _prefixed(prefix, "PASSWORD_PEPPER_B64"),
        secrets["password_pepper_b64"],
    )
    secrets["session_hmac_keys_json"] = keyring
    if prefix == "PROD":
        admin_active_key_id, admin_keyring = _admin_session_keyring(prefix)
        if environment["ADMIN_SESSION_HMAC_ACTIVE_KEY_ID"] != admin_active_key_id:
            raise RuntimeError("Admin session HMAC active key identifiers do not match")
        for source, target in ADMIN_SECRET_INPUTS.items():
            if source == "ADMIN_SESSION_HMAC_KEYS_JSON":
                continue
            secrets[target] = _value(_prefixed(prefix, source))
        _validate_b64_key(
            _prefixed(prefix, "ADMIN_PASSWORD_PEPPER_B64"),
            secrets["admin_password_pepper_b64"],
        )
        secrets["admin_session_hmac_keys_json"] = admin_keyring
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

    deployment_text = "".join(
        f"{name}={_quote_environment_value(name, value)}\n"
        for name, value in sorted(build_deployment_environment(prefix).items())
    )
    deployment_path = output_dir / "deployment.env"
    deployment_path.write_text(deployment_text, encoding="utf-8", newline="\n")
    deployment_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

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
