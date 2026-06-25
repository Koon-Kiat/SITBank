from __future__ import annotations

import json
import os
import re
import stat
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv


APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
if APP_ENV != "production":
    load_dotenv()


PLACEHOLDER_TOKENS = {
    "changeme",
    "change_me",
    "example",
    "fake",
    "placeholder",
    "replace_me",
    "test",
    "test-secret",
}

CUSTOMER_RUNTIME_SECRET_ENV_NAMES = {
    "SECRET_KEY": "SECRET_KEY",
    "WTF_CSRF_SECRET_KEY": "WTF_CSRF_SECRET_KEY",
    "SESSION_HMAC_KEYS": "SESSION_HMAC_KEYS_JSON",
    "SESSION_LOOKUP_HMAC_KEY": "SESSION_LOOKUP_HMAC_KEY",
    "SQLALCHEMY_DATABASE_URI": "DATABASE_URL",
    "MFA_KEK_KEYS": "MFA_KEK_KEYS_JSON",
    "PASSWORD_PEPPER_B64": "PASSWORD_PEPPER_B64",
    "SECURITY_AUDIT_HMAC_KEY": "SECURITY_AUDIT_HMAC_KEY",
}

ADMIN_RUNTIME_SECRET_ENV_NAMES = {
    "SECRET_KEY": "ADMIN_SECRET_KEY",
    "WTF_CSRF_SECRET_KEY": "ADMIN_WTF_CSRF_SECRET_KEY",
    "SESSION_HMAC_KEYS": "ADMIN_SESSION_HMAC_KEYS_JSON",
    "SESSION_LOOKUP_HMAC_KEY": "ADMIN_SESSION_LOOKUP_HMAC_KEY",
    "SQLALCHEMY_DATABASE_URI": "ADMIN_DATABASE_URL",
    "PASSWORD_PEPPER_B64": "ADMIN_PASSWORD_PEPPER_B64",
    "SECURITY_AUDIT_HMAC_KEY": "SECURITY_AUDIT_HMAC_KEY",
}

RUNTIME_SECRET_ENV_NAMES_BY_MODE = {
    "customer": CUSTOMER_RUNTIME_SECRET_ENV_NAMES,
    "admin": ADMIN_RUNTIME_SECRET_ENV_NAMES,
}


def _looks_placeholder(value: str) -> bool:
    normalized = value.strip().casefold()
    return normalized in PLACEHOLDER_TOKENS or "replace_me" in normalized


def _read_secret_file(name: str, path_value: str) -> str:
    path = Path(path_value)
    if not path.is_absolute():
        raise RuntimeError(f"{name}_FILE must be an absolute path")
    if path.is_symlink():
        raise RuntimeError(f"{name}_FILE must not be a symlink")

    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f"{name}_FILE could not be read") from exc
    if not resolved.is_file():
        raise RuntimeError(f"{name}_FILE must identify a regular file")

    if APP_ENV == "production":
        secret_root = Path("/run/secrets").resolve()
        try:
            resolved.relative_to(secret_root)
        except ValueError as exc:
            raise RuntimeError(
                f"{name}_FILE must resolve beneath /run/secrets in production"
            ) from exc

    try:
        value = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"{name}_FILE could not be read as UTF-8") from exc
    if value.endswith("\n"):
        value = value[:-1]
    if not value:
        raise RuntimeError(f"{name}_FILE is empty")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise RuntimeError(f"{name}_FILE contains unsupported control characters")
    return value


def _required_env_or_file(name: str) -> str:
    direct_value = os.getenv(name)
    file_value = os.getenv(f"{name}_FILE")
    if direct_value and file_value:
        raise RuntimeError(f"Configure either {name} or {name}_FILE, not both")
    if file_value:
        value = _read_secret_file(name, file_value)
    else:
        value = direct_value
    if not value:
        raise RuntimeError(f"Missing required configuration: {name} or {name}_FILE")
    if _looks_placeholder(value):
        raise RuntimeError(f"{name} contains a placeholder value")
    return value


def _optional_env_or_file(name: str) -> str | None:
    direct_value = os.getenv(name)
    file_value = os.getenv(f"{name}_FILE")
    if direct_value and file_value:
        raise RuntimeError(f"Configure either {name} or {name}_FILE, not both")
    if file_value:
        value = _read_secret_file(name, file_value)
    else:
        value = direct_value
    if not value:
        return None
    if _looks_placeholder(value):
        raise RuntimeError(f"{name} contains a placeholder value")
    return value


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    if _looks_placeholder(value):
        raise RuntimeError(f"{name} contains a placeholder value")
    return value


def _required_secret(name: str, *, min_length: int) -> str:
    value = _required_env_or_file(name)
    if len(value) < min_length:
        raise RuntimeError(f"{name} must be at least {min_length} characters")
    return value


def _configured_secret(
    name: str,
    *,
    min_length: int,
    development_default: str,
) -> str:
    if APP_ENV == "production":
        return _required_secret(name, min_length=min_length)
    value = _optional_env_or_file(name) or development_default
    if len(value) < min_length:
        raise RuntimeError(f"{name} must be at least {min_length} characters")
    return value


def _configured_audit_anchor_path(name: str = "SECURITY_AUDIT_ANCHOR_PATH") -> str | None:
    value = os.getenv(name)
    if APP_ENV == "production" and not value:
        raise RuntimeError(f"Missing required configuration: {name}")
    if not value:
        return None
    return _validate_audit_anchor_path(name, value)


def _validate_audit_anchor_path(
    name: str,
    value: str,
    *,
    database_url: str | None = None,
) -> str:
    text = str(value or "").strip()
    if not text:
        raise RuntimeError(f"{name} must not be empty")
    if "\x00" in text or "\r" in text or "\n" in text:
        raise RuntimeError(f"{name} contains unsupported control characters")

    path = Path(text)
    if not path.is_absolute():
        raise RuntimeError(f"{name} must be an absolute path")
    if path.is_symlink():
        raise RuntimeError(f"{name} must not be a symlink")

    try:
        resolved = path.resolve(strict=path.exists())
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f"{name} could not be resolved") from exc
    if path.exists() and not path.is_file():
        raise RuntimeError(f"{name} must identify a regular file")

    parent = path.parent
    if parent.is_symlink():
        raise RuntimeError(f"{name} parent directory must not be a symlink")
    try:
        resolved_parent = parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f"{name} parent directory must exist") from exc
    if not resolved_parent.is_dir():
        raise RuntimeError(f"{name} parent must be a directory")

    _reject_unsafe_audit_anchor_location(name, resolved, database_url=database_url)
    _reject_world_writable_path(name, resolved_parent, "parent directory")
    if path.exists():
        _reject_world_writable_path(name, resolved, "file")
        if not os.access(resolved, os.R_OK | os.W_OK):
            raise RuntimeError(f"{name} must be readable and writable by the runtime")
    elif not os.access(resolved_parent, os.W_OK | os.X_OK):
        raise RuntimeError(f"{name} parent directory must be writable by the runtime")
    return str(resolved)


def _reject_world_writable_path(name: str, path: Path, label: str) -> None:
    if os.name == "nt":
        return
    if path.stat().st_mode & stat.S_IWOTH:
        raise RuntimeError(f"{name} {label} must not be world-writable")


def _reject_unsafe_audit_anchor_location(
    name: str,
    anchor_path: Path,
    *,
    database_url: str | None,
) -> None:
    repo_root = Path(__file__).resolve().parent
    unsafe_roots = [repo_root, Path("/var/lib/postgresql"), Path("/var/lib/mysql")]
    sqlite_root = _sqlite_database_directory(database_url or os.getenv("DATABASE_URL", ""))
    if sqlite_root is not None:
        unsafe_roots.append(sqlite_root)
    for root in unsafe_roots:
        try:
            anchor_path.relative_to(root.resolve(strict=root.exists()))
        except ValueError:
            continue
        raise RuntimeError(f"{name} must be outside the application and database directories")


def _sqlite_database_directory(database_url: str) -> Path | None:
    if database_url.startswith("sqlite+pysqlite:///"):
        database_path = database_url.removeprefix("sqlite+pysqlite:///")
    elif database_url.startswith("sqlite:///"):
        database_path = database_url.removeprefix("sqlite:///")
    else:
        return None
    if database_path in {"", "/", ":memory:"}:
        return None
    return Path(database_path).resolve().parent


def _required_url(name: str, *, schemes: set[str], require_password: bool) -> str:
    value = _required_env_or_file(name)
    return _validate_url(name, value, schemes=schemes, require_password=require_password)


def _optional_url(name: str, *, schemes: set[str], require_password: bool) -> str | None:
    direct_value = os.getenv(name)
    file_value = os.getenv(f"{name}_FILE")
    if direct_value and file_value:
        raise RuntimeError(f"Configure either {name} or {name}_FILE, not both")
    if file_value:
        value = _read_secret_file(name, file_value)
    else:
        value = direct_value
    if not value:
        return None
    if _looks_placeholder(value):
        raise RuntimeError(f"{name} contains a placeholder value")
    return _validate_url(name, value, schemes=schemes, require_password=require_password)


def _optional_bool(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be a boolean value")


def _choice_env(name: str, *, default: str, choices: set[str]) -> str:
    value = os.getenv(name, default).strip().casefold()
    if value not in choices:
        allowed = ", ".join(sorted(choices))
        raise RuntimeError(f"{name} must be one of: {allowed}")
    return value


def _validate_password_reset_email_config(
    *,
    app_env: str,
    password_reset_enabled: bool,
    email_backend: str,
    email_from: str,
    smtp_host: str,
    smtp_use_tls: bool,
    smtp_username: str | None,
    smtp_password: str | None,
) -> None:
    if not password_reset_enabled or app_env != "production":
        return

    if email_backend == "console":
        raise RuntimeError("PASSWORD_RESET_EMAIL_BACKEND=console is not allowed in production")
    if not email_from:
        raise RuntimeError("PASSWORD_RESET_EMAIL_FROM is required when password reset is enabled")
    if email_backend == "smtp":
        if not smtp_host:
            raise RuntimeError("SMTP_HOST is required when production password reset uses SMTP")
        if not smtp_use_tls:
            raise RuntimeError(
                "SMTP_USE_TLS=true is required when production password reset uses SMTP"
            )
        if not smtp_username:
            raise RuntimeError("SMTP_USERNAME or SMTP_USERNAME_FILE is required in production")
        if not smtp_password:
            raise RuntimeError("SMTP_PASSWORD or SMTP_PASSWORD_FILE is required in production")


def _float_env(name: str, *, default: str, minimum: float, maximum: float) -> float:
    raw_value = os.getenv(name, default)
    try:
        value = float(raw_value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} must be a number") from exc
    if value < minimum or value > maximum:
        raise RuntimeError(f"{name} must be between {minimum:g} and {maximum:g}")
    return value


def _int_env(name: str, *, default: str, minimum: int, maximum: int) -> int:
    raw_value = os.getenv(name, default)
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def _validate_url(name: str, value: str, *, schemes: set[str], require_password: bool) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in schemes:
        allowed = ", ".join(sorted(schemes))
        raise RuntimeError(f"{name} must use one of these schemes: {allowed}")
    if not parsed.hostname:
        raise RuntimeError(f"{name} must include a real host")
    if require_password and not parsed.password:
        raise RuntimeError(f"{name} must include credentials")
    if name in {"DATABASE_URL", "DATABASE_MIGRATION_URL"} and (
        not parsed.username or parsed.path in {"", "/"}
    ):
        raise RuntimeError(f"{name} must include username and database name")
    return value


def _password_reset_base_url(name: str, *, default: str | None) -> str | None:
    raw_value = os.getenv(name)
    if raw_value is None:
        if default is None:
            return None
        raw_value = default
    value = raw_value.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError(f"{name} must be an HTTP or HTTPS URL with a host")
    if parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise RuntimeError(f"{name} must not include credentials, query, or fragment")
    if APP_ENV == "production" and parsed.scheme != "https":
        raise RuntimeError(f"{name} must use HTTPS in production")
    return value


def _required_b64_32_bytes(name: str) -> str:
    import base64

    value = _required_env_or_file(name)
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise RuntimeError(f"{name} must be valid base64") from exc
    if len(decoded) != 32:
        raise RuntimeError(f"{name} must decode to exactly 32 bytes")
    return value


def _required_b64_32_bytes_decoded(name: str) -> bytes:
    import base64

    value = _required_b64_32_bytes(name)
    return base64.b64decode(value, validate=True)


def _required_session_hmac_keys(name: str, *, active_key_id: str) -> dict[str, bytes]:
    import base64

    raw_value = _required_env_or_file(name)
    try:
        payload = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{name} must be a JSON object") from exc
    if not isinstance(payload, dict) or not payload:
        raise RuntimeError(f"{name} must contain at least one key")

    keys: dict[str, bytes] = {}
    for key_id, encoded_key in payload.items():
        normalized_key_id = str(key_id).strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", normalized_key_id):
            raise RuntimeError(f"{name} contains an invalid key identifier")
        if normalized_key_id in keys:
            raise RuntimeError(f"{name} contains duplicate key identifiers after normalization")
        try:
            decoded_key = base64.b64decode(str(encoded_key), validate=True)
        except Exception as exc:
            raise RuntimeError(f"{name} key {normalized_key_id} must be valid base64") from exc
        if len(decoded_key) != 32:
            raise RuntimeError(f"{name} key {normalized_key_id} must decode to exactly 32 bytes")
        keys[normalized_key_id] = decoded_key

    if active_key_id not in keys:
        raise RuntimeError("SESSION_HMAC_ACTIVE_KEY_ID must identify a configured session HMAC key")
    return keys


def _configured_value(config: dict, key: str, loader) -> object:
    value = config.get(key)
    if value is not None and value != "":
        return value
    return loader()


def _customer_runtime_overrides(config: dict) -> dict[str, object]:
    session_hmac_active_key_id = str(
        _configured_value(
            config,
            "SESSION_HMAC_ACTIVE_KEY_ID",
            lambda: _required_env("SESSION_HMAC_ACTIVE_KEY_ID"),
        )
    )
    mfa_kek_active_id = str(
        _configured_value(
            config,
            "MFA_KEK_ACTIVE_ID",
            lambda: _required_env("MFA_KEK_ACTIVE_ID"),
        )
    )
    return {
        "APP_MODE": "customer",
        "SECRET_ENV_NAMES": CUSTOMER_RUNTIME_SECRET_ENV_NAMES,
        "SECRET_KEY": _configured_value(
            config,
            "SECRET_KEY",
            lambda: _required_secret("SECRET_KEY", min_length=32),
        ),
        "WTF_CSRF_SECRET_KEY": _configured_value(
            config,
            "WTF_CSRF_SECRET_KEY",
            lambda: _required_secret("WTF_CSRF_SECRET_KEY", min_length=32),
        ),
        "SESSION_HMAC_ACTIVE_KEY_ID": session_hmac_active_key_id,
        "SESSION_HMAC_KEYS": _configured_value(
            config,
            "SESSION_HMAC_KEYS",
            lambda: _required_session_hmac_keys(
                "SESSION_HMAC_KEYS_JSON",
                active_key_id=session_hmac_active_key_id,
            ),
        ),
        "SESSION_LOOKUP_HMAC_KEY": _configured_value(
            config,
            "SESSION_LOOKUP_HMAC_KEY",
            lambda: _required_b64_32_bytes_decoded("SESSION_LOOKUP_HMAC_KEY"),
        ),
        "SQLALCHEMY_DATABASE_URI": _configured_value(
            config,
            "SQLALCHEMY_DATABASE_URI",
            lambda: _required_url(
                "DATABASE_URL",
                schemes={"postgresql", "postgresql+psycopg2"},
                require_password=True,
            ),
        ),
        "SQLALCHEMY_MIGRATION_DATABASE_URI": _configured_value(
            config,
            "SQLALCHEMY_MIGRATION_DATABASE_URI",
            lambda: _optional_url(
                "DATABASE_MIGRATION_URL",
                schemes={"postgresql", "postgresql+psycopg2"},
                require_password=True,
            ),
        ),
        "MFA_KEK_ACTIVE_ID": mfa_kek_active_id,
        "MFA_KEK_KEYS": _configured_value(
            config,
            "MFA_KEK_KEYS",
            lambda: _required_keyring(
                "MFA_KEK_KEYS_JSON",
                active_key_id=mfa_kek_active_id,
                active_label="MFA_KEK_ACTIVE_ID",
            ),
        ),
        "PASSWORD_PEPPER_B64": _configured_value(
            config,
            "PASSWORD_PEPPER_B64",
            lambda: _required_b64_32_bytes("PASSWORD_PEPPER_B64"),
        ),
        "PASSWORD_RESET_BASE_URL": _configured_value(
            config,
            "PASSWORD_RESET_BASE_URL",
            lambda: _password_reset_base_url(
                "PASSWORD_RESET_BASE_URL",
                default=None,
            ),
        ),
        "SESSION_KEY_PREFIX": config.get("SESSION_KEY_PREFIX") or "session:",
        "SESSION_COOKIE_NAME": config.get("SESSION_COOKIE_NAME") or "__Host-sitbank_session",
        "PERMANENT_SESSION_LIFETIME": config.get("PERMANENT_SESSION_LIFETIME") or timedelta(minutes=5),
        "SESSION_INACTIVITY_SECONDS": config.get("SESSION_INACTIVITY_SECONDS") or 5 * 60,
        "AUTH_FAILURE_KEY_PREFIX": config.get("AUTH_FAILURE_KEY_PREFIX") or "ospbank:authfail:",
        "RATELIMIT_STORAGE_URI": config.get("RATELIMIT_STORAGE_URI") or "memory://",
        "RATELIMIT_KEY_PREFIX": config.get("RATELIMIT_KEY_PREFIX") or "ospbank:ratelimit:",
        "ADMIN_AUTH_ENABLED": False,
    }


def _admin_runtime_overrides(config: dict) -> dict[str, object]:
    session_hmac_active_key_id = str(
        _configured_value(
            config,
            "ADMIN_SESSION_HMAC_ACTIVE_KEY_ID",
            lambda: _required_env("ADMIN_SESSION_HMAC_ACTIVE_KEY_ID"),
        )
    )
    return {
        "APP_MODE": "admin",
        "SECRET_ENV_NAMES": ADMIN_RUNTIME_SECRET_ENV_NAMES,
        "SECRET_KEY": _configured_value(
            config,
            "ADMIN_SECRET_KEY",
            lambda: _required_secret("ADMIN_SECRET_KEY", min_length=32),
        ),
        "WTF_CSRF_SECRET_KEY": _configured_value(
            config,
            "ADMIN_WTF_CSRF_SECRET_KEY",
            lambda: _required_secret("ADMIN_WTF_CSRF_SECRET_KEY", min_length=32),
        ),
        "SESSION_HMAC_ACTIVE_KEY_ID": session_hmac_active_key_id,
        "SESSION_HMAC_KEYS": _configured_value(
            config,
            "ADMIN_SESSION_HMAC_KEYS",
            lambda: _required_session_hmac_keys(
                "ADMIN_SESSION_HMAC_KEYS_JSON",
                active_key_id=session_hmac_active_key_id,
            ),
        ),
        "SESSION_LOOKUP_HMAC_KEY": _configured_value(
            config,
            "ADMIN_SESSION_LOOKUP_HMAC_KEY",
            lambda: _required_b64_32_bytes_decoded("ADMIN_SESSION_LOOKUP_HMAC_KEY"),
        ),
        "SQLALCHEMY_DATABASE_URI": _configured_value(
            config,
            "ADMIN_SQLALCHEMY_DATABASE_URI",
            lambda: _required_url(
                "ADMIN_DATABASE_URL",
                schemes={"postgresql", "postgresql+psycopg2"},
                require_password=True,
            ),
        ),
        "SQLALCHEMY_MIGRATION_DATABASE_URI": None,
        "PASSWORD_PEPPER_B64": _configured_value(
            config,
            "ADMIN_PASSWORD_PEPPER_B64",
            lambda: _required_b64_32_bytes("ADMIN_PASSWORD_PEPPER_B64"),
        ),
        "SESSION_KEY_PREFIX": config.get("ADMIN_SESSION_KEY_PREFIX")
        or os.getenv("ADMIN_SESSION_KEY_PREFIX", "admin-session:"),
        "SESSION_COOKIE_NAME": config.get("ADMIN_SESSION_COOKIE_NAME") or "__Host-sitbank_admin_session",
        "PERMANENT_SESSION_LIFETIME": config.get("ADMIN_PERMANENT_SESSION_LIFETIME") or timedelta(minutes=5),
        "SESSION_INACTIVITY_SECONDS": config.get("ADMIN_SESSION_INACTIVITY_SECONDS") or 5 * 60,
        "PENDING_MFA_MAX_AGE_SECONDS": config.get("ADMIN_PENDING_MFA_MAX_AGE_SECONDS") or 60,
        "AUTH_FAILURE_KEY_PREFIX": config.get("ADMIN_AUTH_FAILURE_KEY_PREFIX") or "ospbank:admin:authfail:",
        "RATELIMIT_STORAGE_URI": config.get("ADMIN_RATELIMIT_STORAGE_URI") or "memory://",
        "RATELIMIT_KEY_PREFIX": config.get("ADMIN_RATELIMIT_KEY_PREFIX")
        or os.getenv("ADMIN_RATELIMIT_KEY_PREFIX", "ospbank:admin:ratelimit:"),
        "ADMIN_AUTH_ENABLED": False,
        "ADMIN_WEBAUTHN_PHASE": "phase_2",
        "ADMIN_STEP_UP_PHASE": "phase_2",
    }


def apply_runtime_mode_config(config: dict, app_mode: str) -> None:
    normalized_mode = str(app_mode or "").strip().casefold()
    if normalized_mode == "customer":
        config.update(_customer_runtime_overrides(config))
        return
    if normalized_mode == "admin":
        config.update(_admin_runtime_overrides(config))
        return
    raise RuntimeError("app_mode must be 'customer' or 'admin'")


def _required_keyring(name: str, *, active_key_id: str, active_label: str) -> dict[str, bytes]:
    import base64

    raw_value = _required_env_or_file(name)
    try:
        payload = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{name} must be a JSON object") from exc
    if not isinstance(payload, dict) or not payload:
        raise RuntimeError(f"{name} must contain at least one key")

    keys: dict[str, bytes] = {}
    for key_id, encoded_key in payload.items():
        normalized_key_id = str(key_id).strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", normalized_key_id):
            raise RuntimeError(f"{name} contains an invalid key identifier")
        if normalized_key_id in keys:
            raise RuntimeError(f"{name} contains duplicate key identifiers after normalization")
        try:
            decoded_key = base64.b64decode(str(encoded_key), validate=True)
        except Exception as exc:
            raise RuntimeError(f"{name} key {normalized_key_id} must be valid base64") from exc
        if len(decoded_key) != 32:
            raise RuntimeError(f"{name} key {normalized_key_id} must decode to exactly 32 bytes")
        keys[normalized_key_id] = decoded_key

    if active_key_id not in keys:
        raise RuntimeError(f"{active_label} must identify a configured key in {name}")
    return keys


class Config:
    APP_ENV = APP_ENV
    SECRET_KEY = None
    WTF_CSRF_SECRET_KEY = None
    SESSION_HMAC_ACTIVE_KEY_ID = None
    SESSION_HMAC_KEYS = None
    SESSION_LOOKUP_HMAC_KEY = None
    SQLALCHEMY_DATABASE_URI = None
    SQLALCHEMY_MIGRATION_DATABASE_URI = None
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MFA_KEK_ACTIVE_ID = None
    MFA_KEK_KEYS = None
    PASSWORD_PEPPER_B64 = None
    PASSWORD_PBKDF2_ITERATIONS = int(os.getenv("PASSWORD_PBKDF2_ITERATIONS", "600000"))
    if PASSWORD_PBKDF2_ITERATIONS < 600000:
        raise RuntimeError("PASSWORD_PBKDF2_ITERATIONS must be 600000 or higher")
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_RECOMMENDED_MIN_LENGTH = 15
    PASSWORD_MAX_CHARS = int(os.getenv("PASSWORD_MAX_CHARS", "256"))
    if PASSWORD_MAX_CHARS < 64 or PASSWORD_MAX_CHARS > 1024:
        raise RuntimeError("PASSWORD_MAX_CHARS must be between 64 and 1024")
    MFA_ISSUER_NAME = os.getenv("MFA_ISSUER_NAME", "SITBank")

    COMMON_PASSWORDS_PATH = _required_env("COMMON_PASSWORDS_PATH")
    COMMON_PASSWORDS_MIN_ENTRIES = int(os.getenv("COMMON_PASSWORDS_MIN_ENTRIES", "100000"))
    if COMMON_PASSWORDS_MIN_ENTRIES < 100000:
        raise RuntimeError("COMMON_PASSWORDS_MIN_ENTRIES must be 100000 or higher")

    HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS = float(
        os.getenv("HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS", "2.0")
    )
    if HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS <= 0 or HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS > 5:
        raise RuntimeError("HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS must be between 0 and 5")
    HIBP_CIRCUIT_FAILURE_THRESHOLD = int(os.getenv("HIBP_CIRCUIT_FAILURE_THRESHOLD", "3"))
    if HIBP_CIRCUIT_FAILURE_THRESHOLD < 1 or HIBP_CIRCUIT_FAILURE_THRESHOLD > 10:
        raise RuntimeError("HIBP_CIRCUIT_FAILURE_THRESHOLD must be between 1 and 10")
    HIBP_CIRCUIT_OPEN_SECONDS = int(os.getenv("HIBP_CIRCUIT_OPEN_SECONDS", "300"))
    if HIBP_CIRCUIT_OPEN_SECONDS < 30 or HIBP_CIRCUIT_OPEN_SECONDS > 3600:
        raise RuntimeError("HIBP_CIRCUIT_OPEN_SECONDS must be between 30 and 3600")

    PASSWORD_RESET_ENABLED = _optional_bool("PASSWORD_RESET_ENABLED", default=True)
    PASSWORD_RESET_TOKEN_TTL_SECONDS = _int_env(
        "PASSWORD_RESET_TOKEN_TTL_SECONDS",
        default="1800",
        minimum=300,
        maximum=1800,
    )
    PASSWORD_RESET_TRANSACTION_TTL_SECONDS = _int_env(
        "PASSWORD_RESET_TRANSACTION_TTL_SECONDS",
        default="900",
        minimum=300,
        maximum=1800,
    )
    MANUAL_RECOVERY_REQUEST_TTL_SECONDS = _int_env(
        "MANUAL_RECOVERY_REQUEST_TTL_SECONDS",
        default=str(7 * 24 * 60 * 60),
        minimum=3600,
        maximum=30 * 24 * 60 * 60,
    )
    PASSWORD_RESET_EMAIL_BACKEND = _choice_env(
        "PASSWORD_RESET_EMAIL_BACKEND",
        default="smtp" if APP_ENV == "production" else "console",
        choices={"console", "smtp"},
    )
    PASSWORD_RESET_EMAIL_FROM = os.getenv("PASSWORD_RESET_EMAIL_FROM", "security@sitbank.local").strip()
    PASSWORD_RESET_BASE_URL = _password_reset_base_url(
        "PASSWORD_RESET_BASE_URL",
        default=None,
    )
    SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
    SMTP_PORT = _int_env("SMTP_PORT", default="587", minimum=1, maximum=65535)
    SMTP_USE_TLS = _optional_bool("SMTP_USE_TLS", default=True)
    SMTP_USERNAME = _optional_env_or_file("SMTP_USERNAME")
    SMTP_PASSWORD = _optional_env_or_file("SMTP_PASSWORD")
    _validate_password_reset_email_config(
        app_env=APP_ENV,
        password_reset_enabled=PASSWORD_RESET_ENABLED,
        email_backend=PASSWORD_RESET_EMAIL_BACKEND,
        email_from=PASSWORD_RESET_EMAIL_FROM,
        smtp_host=SMTP_HOST,
        smtp_use_tls=SMTP_USE_TLS,
        smtp_username=SMTP_USERNAME,
        smtp_password=SMTP_PASSWORD,
    )

    SECURITY_ALERT_ENABLED = _optional_bool(
        "SECURITY_ALERT_ENABLED",
        default=APP_ENV == "production",
    )
    SECURITY_ALERT_WEBHOOK_URL_FILE = os.getenv("SECURITY_ALERT_WEBHOOK_URL_FILE")
    SECURITY_ALERT_WEBHOOK_URL = _optional_url(
        "SECURITY_ALERT_WEBHOOK_URL",
        schemes={"https"},
        require_password=False,
    )
    SECURITY_ALERT_MIN_SEVERITY = _choice_env(
        "SECURITY_ALERT_MIN_SEVERITY",
        default="high",
        choices={"low", "medium", "high", "critical"},
    )
    SECURITY_ALERT_TIMEOUT_SECONDS = _float_env(
        "SECURITY_ALERT_TIMEOUT_SECONDS",
        default="5.0",
        minimum=1.0,
        maximum=30.0,
    )
    SECURITY_ALERT_DEDUPE_TTL_SECONDS = _int_env(
        "SECURITY_ALERT_DEDUPE_TTL_SECONDS",
        default="300",
        minimum=60,
        maximum=86400,
    )
    SECURITY_ALERT_STATE_PATH = os.getenv("SECURITY_ALERT_STATE_PATH")
    SECURITY_AUDIT_ANCHOR_PATH = _configured_audit_anchor_path()
    SECURITY_AUDIT_HMAC_KEY = _configured_secret(
        "SECURITY_AUDIT_HMAC_KEY",
        min_length=32,
        development_default="development-audit-hmac-key-change-before-production",
    )

    SESSION_TYPE = "database"
    SESSION_KEY_PREFIX = None
    SESSION_COOKIE_NAME = "__Host-sitbank_session"
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
    SESSION_INACTIVITY_SECONDS = 5 * 60
    SESSION_HISTORY_LIMIT = int(os.getenv("SESSION_HISTORY_LIMIT", "20"))
    if SESSION_HISTORY_LIMIT < 1 or SESSION_HISTORY_LIMIT > 100:
        raise RuntimeError("SESSION_HISTORY_LIMIT must be between 1 and 100")
    PENDING_MFA_MAX_AGE_SECONDS = int(os.getenv("PENDING_MFA_MAX_AGE_SECONDS", "300"))
    if PENDING_MFA_MAX_AGE_SECONDS < 60 or PENDING_MFA_MAX_AGE_SECONDS > SESSION_INACTIVITY_SECONDS:
        raise RuntimeError("PENDING_MFA_MAX_AGE_SECONDS must be between 60 and SESSION_INACTIVITY_SECONDS")

    WTF_CSRF_TIME_LIMIT = 15 * 60
    WTF_CSRF_SSL_STRICT = True
    WTF_CSRF_CHECK_DEFAULT = True
    WTF_CSRF_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(1024 * 1024)))
    if MAX_CONTENT_LENGTH < 64 * 1024 or MAX_CONTENT_LENGTH > 5 * 1024 * 1024:
        raise RuntimeError("MAX_CONTENT_LENGTH must be between 64 KiB and 5 MiB")

    SESSION_METADATA_KEY_PREFIX = None
    USER_SESSIONS_KEY_PREFIX = None
    PAST_SESSIONS_KEY_PREFIX = None
    REVOKED_SESSION_KEY_PREFIX = None
    AUTH_FAILURE_KEY_PREFIX = None
    SECURITY_STATE_CLEANUP_BATCH_SIZE = int(os.getenv("SECURITY_STATE_CLEANUP_BATCH_SIZE", "500"))
    if SECURITY_STATE_CLEANUP_BATCH_SIZE < 1 or SECURITY_STATE_CLEANUP_BATCH_SIZE > 5000:
        raise RuntimeError("SECURITY_STATE_CLEANUP_BATCH_SIZE must be between 1 and 5000")
    SECURITY_STATE_RETENTION_DAYS = int(os.getenv("SECURITY_STATE_RETENTION_DAYS", "30"))
    if SECURITY_STATE_RETENTION_DAYS < 1 or SECURITY_STATE_RETENTION_DAYS > 365:
        raise RuntimeError("SECURITY_STATE_RETENTION_DAYS must be between 1 and 365")

    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_KEY_PREFIX = None

    FRESH_MFA_SECONDS = 5 * 60
    TOTP_LOGIN_VALID_WINDOW = int(os.getenv("TOTP_LOGIN_VALID_WINDOW", "1"))
    if TOTP_LOGIN_VALID_WINDOW < 0 or TOTP_LOGIN_VALID_WINDOW > 1:
        raise RuntimeError("TOTP_LOGIN_VALID_WINDOW must be 0 or 1")
    TOTP_HIGH_RISK_VALID_WINDOW = int(os.getenv("TOTP_HIGH_RISK_VALID_WINDOW", "0"))
    if TOTP_HIGH_RISK_VALID_WINDOW != 0:
        raise RuntimeError("TOTP_HIGH_RISK_VALID_WINDOW must be 0")
    TALISMAN_FORCE_HTTPS = True
    TALISMAN_CONTENT_SECURITY_POLICY = {
        "default-src": "'self'",
        "base-uri": "'self'",
        "object-src": "'none'",
        "frame-ancestors": "'none'",
        "form-action": "'self'",
        "img-src": ["'self'", "data:"],
        "script-src": "'self'",
        "script-src-attr": "'none'",
        "style-src": "'self'",
        "style-src-attr": "'none'",
        "connect-src": "'self'",
        "font-src": "'self'",
        "manifest-src": "'self'",
    }

    TRUSTED_PROXY_COUNT = int(os.getenv("TRUSTED_PROXY_COUNT", "1"))
    if TRUSTED_PROXY_COUNT < 0 or TRUSTED_PROXY_COUNT > 2:
        raise RuntimeError("TRUSTED_PROXY_COUNT must be between 0 and 2")

    # 60 seconds (1 min) for testing — change to 43200 for 12h in production
    PAYEE_COOLDOWN_SECONDS = int(os.getenv("PAYEE_COOLDOWN_SECONDS", "60"))


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
