from __future__ import annotations

import json
import os
import re
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
    "SQLALCHEMY_DATABASE_URI": "DATABASE_URL",
    "REDIS_URL": "REDIS_URL",
    "MFA_KEK_KEYS": "MFA_KEK_KEYS_JSON",
    "PASSWORD_PEPPER_B64": "PASSWORD_PEPPER_B64",
    "SECURITY_AUDIT_HMAC_KEY": "SECURITY_AUDIT_HMAC_KEY",
}

ADMIN_RUNTIME_SECRET_ENV_NAMES = {
    "SECRET_KEY": "ADMIN_SECRET_KEY",
    "WTF_CSRF_SECRET_KEY": "ADMIN_WTF_CSRF_SECRET_KEY",
    "SESSION_HMAC_KEYS": "ADMIN_SESSION_HMAC_KEYS_JSON",
    "SQLALCHEMY_DATABASE_URI": "ADMIN_DATABASE_URL",
    "REDIS_URL": "ADMIN_REDIS_URL",
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
    if name in {"REDIS_URL", "ADMIN_REDIS_URL"} and (parsed.query or parsed.fragment):
        raise RuntimeError(
            f"{name} must not include query parameters or a fragment; "
            "connection behavior is configured by the application"
        )
    return value


def _required_webauthn_rp_id(name: str) -> str:
    value = _required_env(name).strip().lower()
    parsed = urlparse(f"//{value}")
    if parsed.hostname != value or parsed.port or parsed.username or parsed.password:
        raise RuntimeError(f"{name} must be a bare hostname without scheme, path, port, or credentials")
    return value


def _required_webauthn_origin(name: str, *, rp_id: str) -> str:
    value = _required_env(name).strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme != "https":
        raise RuntimeError(f"{name} must use HTTPS")
    if parsed.hostname != rp_id:
        raise RuntimeError(f"{name} hostname must match WEBAUTHN_RP_ID")
    if parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise RuntimeError(f"{name} must not include credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise RuntimeError(f"{name} must not include a path")
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
    webauthn_rp_id = str(
        _configured_value(
            config,
            "WEBAUTHN_RP_ID",
            lambda: _required_webauthn_rp_id("WEBAUTHN_RP_ID"),
        )
    )
    redis_url = str(
        _configured_value(
            config,
            "REDIS_URL",
            lambda: _required_url("REDIS_URL", schemes={"redis", "rediss"}, require_password=True),
        )
    )
    webauthn_rp_origin = str(
        _configured_value(
            config,
            "WEBAUTHN_RP_ORIGIN",
            lambda: _required_webauthn_origin("WEBAUTHN_RP_ORIGIN", rp_id=webauthn_rp_id),
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
        "REDIS_URL": redis_url,
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
        "WEBAUTHN_RP_ID": webauthn_rp_id,
        "WEBAUTHN_RP_ORIGIN": webauthn_rp_origin,
        "PASSWORD_RESET_BASE_URL": _configured_value(
            config,
            "PASSWORD_RESET_BASE_URL",
            lambda: _password_reset_base_url(
                "PASSWORD_RESET_BASE_URL",
                default=webauthn_rp_origin,
            ),
        ),
        "SESSION_KEY_PREFIX": config.get("SESSION_KEY_PREFIX") or "session:",
        "SESSION_COOKIE_NAME": config.get("SESSION_COOKIE_NAME") or "__Host-sitbank_session",
        "PERMANENT_SESSION_LIFETIME": config.get("PERMANENT_SESSION_LIFETIME") or timedelta(minutes=5),
        "SESSION_INACTIVITY_SECONDS": config.get("SESSION_INACTIVITY_SECONDS") or 5 * 60,
        "SESSION_METADATA_KEY_PREFIX": config.get("SESSION_METADATA_KEY_PREFIX") or "ospbank:session_meta:",
        "USER_SESSIONS_KEY_PREFIX": config.get("USER_SESSIONS_KEY_PREFIX") or "ospbank:user_sessions:",
        "PAST_SESSIONS_KEY_PREFIX": config.get("PAST_SESSIONS_KEY_PREFIX") or "ospbank:past_sessions:",
        "REVOKED_SESSION_KEY_PREFIX": config.get("REVOKED_SESSION_KEY_PREFIX") or "ospbank:revoked_session:",
        "AUTH_FAILURE_KEY_PREFIX": config.get("AUTH_FAILURE_KEY_PREFIX") or "ospbank:authfail:",
        "RATELIMIT_STORAGE_URI": config.get("RATELIMIT_STORAGE_URI") or redis_url,
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
    redis_url = str(
        _configured_value(
            config,
            "ADMIN_REDIS_URL",
            lambda: _required_url("ADMIN_REDIS_URL", schemes={"redis", "rediss"}, require_password=True),
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
        "REDIS_URL": redis_url,
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
        "SESSION_METADATA_KEY_PREFIX": config.get("ADMIN_SESSION_METADATA_KEY_PREFIX") or "ospbank:admin:session_meta:",
        "USER_SESSIONS_KEY_PREFIX": config.get("ADMIN_USER_SESSIONS_KEY_PREFIX") or "ospbank:admin:user_sessions:",
        "PAST_SESSIONS_KEY_PREFIX": config.get("ADMIN_PAST_SESSIONS_KEY_PREFIX") or "ospbank:admin:past_sessions:",
        "REVOKED_SESSION_KEY_PREFIX": config.get("ADMIN_REVOKED_SESSION_KEY_PREFIX") or "ospbank:admin:revoked_session:",
        "AUTH_FAILURE_KEY_PREFIX": config.get("ADMIN_AUTH_FAILURE_KEY_PREFIX") or "ospbank:admin:authfail:",
        "RATELIMIT_STORAGE_URI": config.get("ADMIN_RATELIMIT_STORAGE_URI") or redis_url,
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
    SQLALCHEMY_DATABASE_URI = None
    SQLALCHEMY_MIGRATION_DATABASE_URI = None
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    REDIS_URL = None
    REDIS_PROTOCOL = 2
    REDIS_LEGACY_RESPONSES = True
    REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS = 2.0
    REDIS_SOCKET_TIMEOUT_SECONDS = 5.0
    REDIS_HEALTH_CHECK_INTERVAL_SECONDS = 30
    REDIS_MAX_CONNECTIONS = 100
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

    WEBAUTHN_RP_ID = None
    WEBAUTHN_RP_ORIGIN = None
    WEBAUTHN_RP_NAME = "SITBank"
    WEBAUTHN_TIMEOUT_MS = 60_000
    WEBAUTHN_REQUIRED_CREDENTIALS = 1
    WEBAUTHN_ENFORCE_KEY_SETUP = False
    WEBAUTHN_MDS_CACHE_PATH = os.getenv(
        "WEBAUTHN_MDS_CACHE_PATH",
        str(Path(__file__).resolve().parent / "ops" / "fido-mds-cache.json"),
    )
    WEBAUTHN_APPROVED_AAGUIDS_PATH = os.getenv(
        "WEBAUTHN_APPROVED_AAGUIDS_PATH",
        str(Path(__file__).resolve().parent / "ops" / "fido-approved-aaguids.json"),
    )

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
    PASSWORD_RESET_EMAIL_BACKEND = _choice_env(
        "PASSWORD_RESET_EMAIL_BACKEND",
        default="smtp" if APP_ENV == "production" else "console",
        choices={"console", "smtp"},
    )
    PASSWORD_RESET_EMAIL_FROM = os.getenv("PASSWORD_RESET_EMAIL_FROM", "security@sitbank.local").strip()
    PASSWORD_RESET_BASE_URL = _password_reset_base_url(
        "PASSWORD_RESET_BASE_URL",
        default=WEBAUTHN_RP_ORIGIN,
    )
    SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
    SMTP_PORT = _int_env("SMTP_PORT", default="587", minimum=1, maximum=65535)
    SMTP_USE_TLS = _optional_bool("SMTP_USE_TLS", default=True)
    SMTP_USERNAME = _optional_env_or_file("SMTP_USERNAME")
    SMTP_PASSWORD = _optional_env_or_file("SMTP_PASSWORD")
    if PASSWORD_RESET_ENABLED and APP_ENV == "production":
        if PASSWORD_RESET_EMAIL_BACKEND == "console":
            raise RuntimeError("PASSWORD_RESET_EMAIL_BACKEND=console is not allowed in production")
        if not PASSWORD_RESET_EMAIL_FROM:
            raise RuntimeError("PASSWORD_RESET_EMAIL_FROM is required when password reset is enabled")
        if PASSWORD_RESET_EMAIL_BACKEND == "smtp":
            if not SMTP_HOST:
                raise RuntimeError("SMTP_HOST is required when production password reset uses SMTP")
            if not SMTP_USERNAME:
                raise RuntimeError("SMTP_USERNAME or SMTP_USERNAME_FILE is required in production")
            if not SMTP_PASSWORD:
                raise RuntimeError("SMTP_PASSWORD or SMTP_PASSWORD_FILE is required in production")

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
    SECURITY_AUDIT_ANCHOR_PATH = os.getenv("SECURITY_AUDIT_ANCHOR_PATH")
    SECURITY_AUDIT_HMAC_KEY = _configured_secret(
        "SECURITY_AUDIT_HMAC_KEY",
        min_length=32,
        development_default="development-audit-hmac-key-change-before-production",
    )

    SESSION_TYPE = "redis"
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

    RATELIMIT_STORAGE_URI = None
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
    WEBAUTHN_STEP_UP_TTL_SECONDS = int(os.getenv("WEBAUTHN_STEP_UP_TTL_SECONDS", "120"))
    if WEBAUTHN_STEP_UP_TTL_SECONDS < 30 or WEBAUTHN_STEP_UP_TTL_SECONDS > 300:
        raise RuntimeError("WEBAUTHN_STEP_UP_TTL_SECONDS must be between 30 and 300")

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


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
