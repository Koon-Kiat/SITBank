from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import fakeredis
import pytest


TEST_SESSION_HMAC_ACTIVE_KEY_ID = "test-current"
TEST_SESSION_HMAC_KEYS = {
    "test-current": b"2" * 32,
    "test-previous": b"3" * 32,
}
TEST_MFA_KEK_ACTIVE_ID = "test-mfa-current"
TEST_MFA_KEK_KEYS = {
    "test-mfa-current": b"4" * 32,
    "test-mfa-previous": b"5" * 32,
}


def _encoded_keyring(keys: dict[str, bytes]) -> str:
    return json.dumps(
        {
            key_id: base64.b64encode(key).decode("ascii")
            for key_id, key in keys.items()
        },
        separators=(",", ":"),
        sort_keys=True,
    )


os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-for-config")
os.environ.setdefault("WTF_CSRF_SECRET_KEY", "test-csrf-secret-that-is-long-enough-for-config")
os.environ["SESSION_HMAC_ACTIVE_KEY_ID"] = TEST_SESSION_HMAC_ACTIVE_KEY_ID
os.environ["SESSION_HMAC_KEYS_JSON"] = _encoded_keyring(TEST_SESSION_HMAC_KEYS)
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+psycopg2://user:pass@127.0.0.1:5432/sitbank_test",
)
os.environ.setdefault("REDIS_URL", "redis://:pass@127.0.0.1:6379/15")
os.environ["MFA_KEK_ACTIVE_ID"] = TEST_MFA_KEK_ACTIVE_ID
os.environ["MFA_KEK_KEYS_JSON"] = _encoded_keyring(TEST_MFA_KEK_KEYS)
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
    SESSION_HMAC_ACTIVE_KEY_ID = TEST_SESSION_HMAC_ACTIVE_KEY_ID
    SESSION_HMAC_KEYS = TEST_SESSION_HMAC_KEYS
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_MIGRATION_DATABASE_URI = None
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = os.environ["REDIS_URL"]
    REDIS_PROTOCOL = 2
    REDIS_LEGACY_RESPONSES = True
    REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS = 2.0
    REDIS_SOCKET_TIMEOUT_SECONDS = 5.0
    REDIS_HEALTH_CHECK_INTERVAL_SECONDS = 30
    REDIS_MAX_CONNECTIONS = 100
    MFA_KEK_ACTIVE_ID = TEST_MFA_KEK_ACTIVE_ID
    MFA_KEK_KEYS = TEST_MFA_KEK_KEYS
    PASSWORD_PEPPER_B64 = os.environ["PASSWORD_PEPPER_B64"]
    PASSWORD_PBKDF2_ITERATIONS = int(os.environ["PASSWORD_PBKDF2_ITERATIONS"])
    PASSWORD_MAX_CHARS = 256
    MFA_ISSUER_NAME = "SITBank Test"
    WEBAUTHN_RP_ID = os.environ["WEBAUTHN_RP_ID"]
    WEBAUTHN_RP_ORIGIN = os.environ["WEBAUTHN_RP_ORIGIN"]
    WEBAUTHN_RP_NAME = "SITBank Test"
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
    SECURITY_ALERT_ENABLED = False
    SECURITY_ALERT_WEBHOOK_URL = None
    SECURITY_ALERT_WEBHOOK_URL_FILE = None
    SECURITY_ALERT_MIN_SEVERITY = "high"
    SECURITY_ALERT_TIMEOUT_SECONDS = 5.0
    SECURITY_ALERT_DEDUPE_TTL_SECONDS = 300
    SESSION_TYPE = "redis"
    SESSION_KEY_PREFIX = "session:"
    SESSION_COOKIE_NAME = "__Host-sitbank_session"
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


SECURITY_TEST_FILES = frozenset(
    {
        "tests/test_config.py",
        "tests/test_deployment.py",
        "tests/test_group_a_security.py",
        "tests/test_mfa_envelope_crypto.py",
        "tests/test_owasp_regressions.py",
        "tests/test_passwords.py",
        "tests/test_pentest_auth_bypass.py",
        "tests/test_redis_session_integrity.py",
        "tests/test_route_inventory_security.py",
        "tests/test_secret_scanner.py",
        "tests/test_webauthn_lifecycle.py",
    }
)
DEPLOYMENT_TEST_FILES = frozenset({"tests/test_deployment.py"})
SLOW_TEST_FILES = frozenset(
    {
        "tests/test_deployment.py",
        "tests/test_group_a_security.py",
        "tests/test_pentest_auth_bypass.py",
        "tests/test_secret_scanner.py",
        "tests/test_webauthn_lifecycle.py",
    }
)
SERIAL_TEST_FILES = frozenset()


def _relative_repo_path(path: Path) -> str:
    repo_root = Path(__file__).resolve().parents[1]
    try:
        return path.resolve().relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def pytest_collection_modifyitems(config, items):
    marker_files = {
        "security": SECURITY_TEST_FILES,
        "deployment": DEPLOYMENT_TEST_FILES,
        "slow": SLOW_TEST_FILES,
        "serial": SERIAL_TEST_FILES,
    }
    for item in items:
        test_path = _relative_repo_path(Path(str(item.path)))
        for marker_name, test_files in marker_files.items():
            if test_path in test_files:
                item.add_marker(getattr(pytest.mark, marker_name))


@pytest.fixture()
def app(monkeypatch):
    import app as app_module
    from app import create_app
    from app.extensions import db
    from app.security import passwords

    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    fake_session_redis = fakeredis.FakeRedis(decode_responses=False)

    def fake_from_url(url, decode_responses=False, **_options):
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
