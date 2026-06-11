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


def _required_url(name: str, *, schemes: set[str], require_password: bool) -> str:
    value = _required_env_or_file(name)
    parsed = urlparse(value)
    if parsed.scheme not in schemes:
        allowed = ", ".join(sorted(schemes))
        raise RuntimeError(f"{name} must use one of these schemes: {allowed}")
    if not parsed.hostname:
        raise RuntimeError(f"{name} must include a real host")
    if require_password and not parsed.password:
        raise RuntimeError(f"{name} must include credentials")
    if name == "DATABASE_URL" and (not parsed.username or parsed.path in {"", "/"}):
        raise RuntimeError("DATABASE_URL must include username and database name")
    if name == "REDIS_URL" and (parsed.query or parsed.fragment):
        raise RuntimeError(
            "REDIS_URL must not include query parameters or a fragment; "
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


class Config:
    APP_ENV = APP_ENV
    SECRET_KEY = _required_secret("SECRET_KEY", min_length=32)
    WTF_CSRF_SECRET_KEY = _required_secret("WTF_CSRF_SECRET_KEY", min_length=32)
    SESSION_HMAC_ACTIVE_KEY_ID = _required_env("SESSION_HMAC_ACTIVE_KEY_ID")
    SESSION_HMAC_KEYS = _required_session_hmac_keys(
        "SESSION_HMAC_KEYS_JSON",
        active_key_id=SESSION_HMAC_ACTIVE_KEY_ID,
    )
    SQLALCHEMY_DATABASE_URI = _required_url(
        "DATABASE_URL",
        schemes={"postgresql", "postgresql+psycopg2"},
        require_password=True,
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    REDIS_URL = _required_url("REDIS_URL", schemes={"redis", "rediss"}, require_password=True)
    REDIS_PROTOCOL = 2
    REDIS_LEGACY_RESPONSES = True
    REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS = 2.0
    REDIS_SOCKET_TIMEOUT_SECONDS = 5.0
    REDIS_HEALTH_CHECK_INTERVAL_SECONDS = 30
    REDIS_MAX_CONNECTIONS = 100
    MFA_AES256_GCM_KEY_B64 = _required_b64_32_bytes("MFA_AES256_GCM_KEY_B64")
    PASSWORD_PEPPER_B64 = _required_b64_32_bytes("PASSWORD_PEPPER_B64")
    PASSWORD_PBKDF2_ITERATIONS = int(os.getenv("PASSWORD_PBKDF2_ITERATIONS", "600000"))
    if PASSWORD_PBKDF2_ITERATIONS < 600000:
        raise RuntimeError("PASSWORD_PBKDF2_ITERATIONS must be 600000 or higher")
    PASSWORD_MAX_CHARS = int(os.getenv("PASSWORD_MAX_CHARS", "256"))
    if PASSWORD_MAX_CHARS < 64 or PASSWORD_MAX_CHARS > 1024:
        raise RuntimeError("PASSWORD_MAX_CHARS must be between 64 and 1024")
    MFA_ISSUER_NAME = os.getenv("MFA_ISSUER_NAME", "SITBank")

    WEBAUTHN_RP_ID = _required_webauthn_rp_id("WEBAUTHN_RP_ID")
    WEBAUTHN_RP_ORIGIN = _required_webauthn_origin("WEBAUTHN_RP_ORIGIN", rp_id=WEBAUTHN_RP_ID)
    WEBAUTHN_RP_NAME = "SITBank"
    WEBAUTHN_TIMEOUT_MS = 60_000
    WEBAUTHN_REQUIRED_CREDENTIALS = 2
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

    SESSION_TYPE = "redis"
    SESSION_KEY_PREFIX = "session:"
    SESSION_COOKIE_NAME = "__Host-sitbank_session"
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    SESSION_INACTIVITY_SECONDS = 15 * 60
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

    RATELIMIT_STORAGE_URI = REDIS_URL
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_KEY_PREFIX = "ospbank:ratelimit:"

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
