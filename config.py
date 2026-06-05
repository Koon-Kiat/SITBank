from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv


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


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    if _looks_placeholder(value):
        raise RuntimeError(f"{name} contains a placeholder value")
    return value


def _required_secret(name: str, *, min_length: int) -> str:
    value = _required_env(name)
    if len(value) < min_length:
        raise RuntimeError(f"{name} must be at least {min_length} characters")
    return value


def _required_url(name: str, *, schemes: set[str], require_password: bool) -> str:
    value = _required_env(name)
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

    value = _required_env(name)
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise RuntimeError(f"{name} must be valid base64") from exc
    if len(decoded) != 32:
        raise RuntimeError(f"{name} must decode to exactly 32 bytes")
    return value


class Config:
    SECRET_KEY = _required_secret("SECRET_KEY", min_length=32)
    SQLALCHEMY_DATABASE_URI = _required_url(
        "DATABASE_URL",
        schemes={"postgresql", "postgresql+psycopg2"},
        require_password=True,
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    REDIS_URL = _required_url("REDIS_URL", schemes={"redis", "rediss"}, require_password=True)
    MFA_AES256_GCM_KEY_B64 = _required_b64_32_bytes("MFA_AES256_GCM_KEY_B64")
    PASSWORD_PEPPER_B64 = _required_b64_32_bytes("PASSWORD_PEPPER_B64")
    PASSWORD_PBKDF2_ITERATIONS = int(os.getenv("PASSWORD_PBKDF2_ITERATIONS", "600000"))
    if PASSWORD_PBKDF2_ITERATIONS < 600000:
        raise RuntimeError("PASSWORD_PBKDF2_ITERATIONS must be 600000 or higher")
    MFA_ISSUER_NAME = os.getenv("MFA_ISSUER_NAME", "O$P$ Bank")

    WEBAUTHN_RP_ID = _required_webauthn_rp_id("WEBAUTHN_RP_ID")
    WEBAUTHN_RP_ORIGIN = _required_webauthn_origin("WEBAUTHN_RP_ORIGIN", rp_id=WEBAUTHN_RP_ID)
    WEBAUTHN_RP_NAME = "O$P$ Bank"
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

    SESSION_TYPE = "redis"
    SESSION_KEY_PREFIX = "session:"
    SESSION_COOKIE_NAME = "__Host-osp_session"
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
        "img-src": ["'self'", "data:"],
        "script-src": "'self'",
        "style-src": "'self'",
    }

    TRUSTED_PROXY_COUNT = int(os.getenv("TRUSTED_PROXY_COUNT", "1"))
    if TRUSTED_PROXY_COUNT < 0 or TRUSTED_PROXY_COUNT > 2:
        raise RuntimeError("TRUSTED_PROXY_COUNT must be between 0 and 2")


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
