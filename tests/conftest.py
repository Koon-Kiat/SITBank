from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import fakeredis
import pytest


os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-for-config")
os.environ.setdefault("WTF_CSRF_SECRET_KEY", "test-csrf-secret-that-is-long-enough-for-config")
os.environ.setdefault("SESSION_HMAC_ACTIVE_KEY_ID", "test-current")
os.environ.setdefault(
    "SESSION_HMAC_KEYS_JSON",
    json.dumps(
        {
            "test-current": base64.b64encode(b"2" * 32).decode("ascii"),
            "test-previous": base64.b64encode(b"3" * 32).decode("ascii"),
        }
    ),
)
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+psycopg2://user:pass@127.0.0.1:5432/sitbank_test",
)
os.environ.setdefault("REDIS_URL", "redis://:pass@127.0.0.1:6379/15")
os.environ.setdefault(
    "MFA_AES256_GCM_KEY_B64",
    base64.b64encode(b"0" * 32).decode("ascii"),
)
os.environ.setdefault(
    "PASSWORD_PEPPER_B64",
    base64.b64encode(b"1" * 32).decode("ascii"),
)
os.environ.setdefault("COMMON_PASSWORDS_PATH", str(Path(__file__).parent / "fixtures" / "common_passwords.txt"))
os.environ.setdefault("COMMON_PASSWORDS_MIN_ENTRIES", "100000")
os.environ.setdefault("PASSWORD_PBKDF2_ITERATIONS", "600000")
os.environ.setdefault("WEBAUTHN_RP_ID", "sitbank.duckdns.org")
os.environ.setdefault("WEBAUTHN_RP_ORIGIN", "https://sitbank.duckdns.org")


class TestConfig:
    TESTING = True
    SECRET_KEY = os.environ["SECRET_KEY"]
    WTF_CSRF_SECRET_KEY = os.environ["WTF_CSRF_SECRET_KEY"]
    SESSION_HMAC_ACTIVE_KEY_ID = os.environ["SESSION_HMAC_ACTIVE_KEY_ID"]
    SESSION_HMAC_KEYS = {
        "test-current": b"2" * 32,
        "test-previous": b"3" * 32,
    }
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = os.environ["REDIS_URL"]
    MFA_AES256_GCM_KEY_B64 = os.environ["MFA_AES256_GCM_KEY_B64"]
    PASSWORD_PEPPER_B64 = os.environ["PASSWORD_PEPPER_B64"]
    PASSWORD_PBKDF2_ITERATIONS = int(os.environ["PASSWORD_PBKDF2_ITERATIONS"])
    PASSWORD_MAX_CHARS = 256
    MFA_ISSUER_NAME = "O$P$ Bank Test"
    WEBAUTHN_RP_ID = os.environ["WEBAUTHN_RP_ID"]
    WEBAUTHN_RP_ORIGIN = os.environ["WEBAUTHN_RP_ORIGIN"]
    WEBAUTHN_RP_NAME = "O$P$ Bank Test"
    WEBAUTHN_TIMEOUT_MS = 60_000
    WEBAUTHN_REQUIRED_CREDENTIALS = 2
    WEBAUTHN_ENFORCE_KEY_SETUP = False
    WEBAUTHN_MDS_CACHE_PATH = str(Path(__file__).parent / "fixtures" / "fido-mds-cache.json")
    WEBAUTHN_APPROVED_AAGUIDS_PATH = str(Path(__file__).parent / "fixtures" / "fido-approved-aaguids.json")
    COMMON_PASSWORDS_PATH = os.environ["COMMON_PASSWORDS_PATH"]
    COMMON_PASSWORDS_MIN_ENTRIES = 1
    HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS = 0.25
    HIBP_CIRCUIT_FAILURE_THRESHOLD = 3
    HIBP_CIRCUIT_OPEN_SECONDS = 300
    SESSION_TYPE = "redis"
    SESSION_KEY_PREFIX = "session:"
    SESSION_COOKIE_NAME = "__Host-osp_session"
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_PERMANENT = True
    SESSION_INACTIVITY_SECONDS = 15 * 60
    SESSION_HISTORY_LIMIT = 20
    PENDING_MFA_MAX_AGE_SECONDS = 5 * 60
    WTF_CSRF_ENABLED = False
    WTF_CSRF_TIME_LIMIT = 15 * 60
    WTF_CSRF_SSL_STRICT = False
    WTF_CSRF_CHECK_DEFAULT = True
    WTF_CSRF_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    MAX_CONTENT_LENGTH = 1024 * 1024
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_KEY_PREFIX = "test:"
    FRESH_MFA_SECONDS = 5 * 60
    TOTP_LOGIN_VALID_WINDOW = 1
    TOTP_HIGH_RISK_VALID_WINDOW = 0
    WEBAUTHN_STEP_UP_TTL_SECONDS = 120
    TALISMAN_FORCE_HTTPS = False
    TALISMAN_CONTENT_SECURITY_POLICY = {
        "default-src": "'self'",
        "img-src": ["'self'", "data:"],
        "script-src": "'self'",
        "style-src": "'self'",
    }
    TRUSTED_PROXY_COUNT = 0


@pytest.fixture()
def app(monkeypatch):
    import app as app_module
    from app import create_app
    from app.extensions import db
    from app.security import passwords

    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    fake_session_redis = fakeredis.FakeRedis(decode_responses=False)

    def fake_from_url(url, decode_responses=False):
        return fake_redis if decode_responses else fake_session_redis

    monkeypatch.setattr(app_module, "Redis", type("FakeRedisFactory", (), {"from_url": staticmethod(fake_from_url)}))
    monkeypatch.setattr(passwords, "_is_password_pwned_by_hibp", lambda _password: False)

    flask_app = create_app(TestConfig)
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()
