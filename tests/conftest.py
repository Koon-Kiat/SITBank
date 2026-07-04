from __future__ import annotations

import base64
import copy
import json
import os
from datetime import timedelta
from pathlib import Path

import pytest


TEST_SESSION_HMAC_ACTIVE_KEY_ID = "test-current"
TEST_SESSION_HMAC_KEYS = {
    "test-current": b"2" * 32,
    "test-previous": b"3" * 32,
}
TEST_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID = "test-admin-current"
TEST_ADMIN_SESSION_HMAC_KEYS = {
    "test-admin-current": b"6" * 32,
    "test-admin-previous": b"7" * 32,
}
TEST_SESSION_LOOKUP_HMAC_KEY = b"9" * 32
TEST_ADMIN_SESSION_LOOKUP_HMAC_KEY = b"a" * 32
TEST_MFA_KEK_ACTIVE_ID = "test-mfa-current"
TEST_MFA_KEK_KEYS = {
    "test-mfa-current": b"4" * 32,
    "test-mfa-previous": b"5" * 32,
}
TEST_TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID = "test-ledger-current"
TEST_TRANSACTION_LEDGER_HMAC_KEYS = {
    "test-ledger-current": b"b" * 32,
    "test-ledger-previous": b"c" * 32,
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
os.environ["SESSION_LOOKUP_HMAC_KEY"] = base64.b64encode(TEST_SESSION_LOOKUP_HMAC_KEY).decode("ascii")
os.environ["ADMIN_SESSION_HMAC_ACTIVE_KEY_ID"] = TEST_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID
os.environ["ADMIN_SESSION_HMAC_KEYS_JSON"] = _encoded_keyring(TEST_ADMIN_SESSION_HMAC_KEYS)
os.environ["ADMIN_SESSION_LOOKUP_HMAC_KEY"] = base64.b64encode(TEST_ADMIN_SESSION_LOOKUP_HMAC_KEY).decode("ascii")
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+psycopg2://user:pass@127.0.0.1:5432/sitbank_test",
)
os.environ["MFA_KEK_ACTIVE_ID"] = TEST_MFA_KEK_ACTIVE_ID
os.environ["MFA_KEK_KEYS_JSON"] = _encoded_keyring(TEST_MFA_KEK_KEYS)
os.environ["TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID"] = (
    TEST_TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID
)
os.environ["TRANSACTION_LEDGER_HMAC_KEYS_JSON"] = _encoded_keyring(
    TEST_TRANSACTION_LEDGER_HMAC_KEYS
)
os.environ.setdefault(
    "PASSWORD_PEPPER_B64",
    base64.b64encode(b"1" * 32).decode("ascii"),
)
os.environ.setdefault("ADMIN_SECRET_KEY", "test-admin-secret-key-that-is-long-enough")
os.environ.setdefault("ADMIN_WTF_CSRF_SECRET_KEY", "test-admin-csrf-secret-that-is-long-enough")
os.environ.setdefault(
    "ADMIN_DATABASE_URL",
    "postgresql+psycopg2://admin:pass@127.0.0.1:5432/sitbank_test",
)
os.environ.setdefault(
    "ADMIN_PASSWORD_PEPPER_B64",
    base64.b64encode(b"8" * 32).decode("ascii"),
)
os.environ.setdefault("COMMON_PASSWORDS_PATH", str(Path(__file__).parent / "fixtures" / "common_passwords.txt"))
os.environ.setdefault("COMMON_PASSWORDS_MIN_ENTRIES", "100000")
os.environ.setdefault("PASSWORD_PBKDF2_ITERATIONS", "600000")
os.environ.setdefault("SECURITY_AUDIT_HMAC_KEY", "test-audit-hmac-key-that-is-long-enough")


class TestConfig:
    TESTING = True
    APP_ENV = "testing"
    DEPLOYMENT_TARGET = "testing"
    STAGING_CLOUDFLARE_ACCESS_JWT_REQUIRED = False
    STAGING_CLOUDFLARE_ACCESS_AUD = ""
    STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN = ""
    STAGING_CLOUDFLARE_ACCESS_JWKS_CACHE_TTL_SECONDS = 300
    SECRET_KEY = os.environ["SECRET_KEY"]
    WTF_CSRF_SECRET_KEY = os.environ["WTF_CSRF_SECRET_KEY"]
    SESSION_HMAC_ACTIVE_KEY_ID = TEST_SESSION_HMAC_ACTIVE_KEY_ID
    SESSION_HMAC_KEYS = TEST_SESSION_HMAC_KEYS
    SESSION_LOOKUP_HMAC_KEY = TEST_SESSION_LOOKUP_HMAC_KEY
    ADMIN_SECRET_KEY = os.environ["ADMIN_SECRET_KEY"]
    ADMIN_WTF_CSRF_SECRET_KEY = os.environ["ADMIN_WTF_CSRF_SECRET_KEY"]
    ADMIN_SESSION_HMAC_ACTIVE_KEY_ID = TEST_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID
    ADMIN_SESSION_HMAC_KEYS = TEST_ADMIN_SESSION_HMAC_KEYS
    ADMIN_SESSION_LOOKUP_HMAC_KEY = TEST_ADMIN_SESSION_LOOKUP_HMAC_KEY
    ADMIN_SQLALCHEMY_DATABASE_URI = "sqlite+pysqlite:///:memory:"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_MIGRATION_DATABASE_URI = None
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MFA_KEK_ACTIVE_ID = TEST_MFA_KEK_ACTIVE_ID
    MFA_KEK_KEYS = TEST_MFA_KEK_KEYS
    TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID = (
        TEST_TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID
    )
    TRANSACTION_LEDGER_HMAC_KEYS = TEST_TRANSACTION_LEDGER_HMAC_KEYS
    PASSWORD_PEPPER_B64 = os.environ["PASSWORD_PEPPER_B64"]
    ADMIN_PASSWORD_PEPPER_B64 = os.environ["ADMIN_PASSWORD_PEPPER_B64"]
    PASSWORD_PBKDF2_ITERATIONS = int(os.environ["PASSWORD_PBKDF2_ITERATIONS"])
    PASSWORD_HISTORY_ENABLED = True
    PASSWORD_HISTORY_RETENTION_COUNT = 3
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_RECOMMENDED_MIN_LENGTH = 15
    PASSWORD_MAX_CHARS = 256
    MFA_ISSUER_NAME = "SITBank Test"
    COMMON_PASSWORDS_PATH = os.environ["COMMON_PASSWORDS_PATH"]
    COMMON_PASSWORDS_MIN_ENTRIES = 1
    HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS = 0.25
    HIBP_CIRCUIT_FAILURE_THRESHOLD = 3
    HIBP_CIRCUIT_OPEN_SECONDS = 300
    PASSWORD_RESET_ENABLED = True
    PASSWORD_RESET_TOKEN_TTL_SECONDS = 1800
    PASSWORD_RESET_TRANSACTION_TTL_SECONDS = 900
    MANUAL_RECOVERY_REQUEST_TTL_SECONDS = 7 * 24 * 60 * 60
    PASSWORD_RESET_EMAIL_BACKEND = "console"
    PASSWORD_RESET_EMAIL_FROM = "security@sitbank.test"
    PASSWORD_RESET_BASE_URL = "https://sitbank.pp.ua"
    SMTP_HOST = ""
    SMTP_PORT = 587
    SMTP_USE_TLS = True
    SMTP_USERNAME = None
    SMTP_PASSWORD = None
    SECURITY_ALERT_ENABLED = False
    SECURITY_ALERT_WEBHOOK_URL = None
    SECURITY_ALERT_WEBHOOK_URL_FILE = None
    SECURITY_ALERT_MIN_SEVERITY = "high"
    SECURITY_ALERT_TIMEOUT_SECONDS = 5.0
    SECURITY_ALERT_DEDUPE_TTL_SECONDS = 300
    SECURITY_ALERT_STATE_PATH = None
    SECURITY_AUDIT_ANCHOR_PATH = None
    SECURITY_AUDIT_HMAC_KEY = os.environ["SECURITY_AUDIT_HMAC_KEY"]
    SESSION_TYPE = "database"
    SESSION_KEY_PREFIX = "session:"
    SESSION_COOKIE_NAME = "__Host-sitbank_session"
    ADMIN_SESSION_KEY_PREFIX = "admin-session:"
    ADMIN_SESSION_COOKIE_NAME = "__Host-sitbank_admin_session"
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_PERMANENT = True
    SESSION_INACTIVITY_SECONDS = 15 * 60
    CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS = 12 * 60 * 60
    ADMIN_PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
    ADMIN_SESSION_INACTIVITY_SECONDS = 5 * 60
    ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS = 4 * 60 * 60
    ADMIN_PENDING_MFA_MAX_AGE_SECONDS = 60
    SESSION_METADATA_KEY_PREFIX = "ospbank:session_meta:"
    USER_SESSIONS_KEY_PREFIX = "ospbank:user_sessions:"
    PAST_SESSIONS_KEY_PREFIX = "ospbank:past_sessions:"
    REVOKED_SESSION_KEY_PREFIX = "ospbank:revoked_session:"
    AUTH_FAILURE_KEY_PREFIX = "ospbank:authfail:"
    ADMIN_SESSION_METADATA_KEY_PREFIX = "ospbank:admin:session_meta:"
    ADMIN_USER_SESSIONS_KEY_PREFIX = "ospbank:admin:user_sessions:"
    ADMIN_PAST_SESSIONS_KEY_PREFIX = "ospbank:admin:past_sessions:"
    ADMIN_REVOKED_SESSION_KEY_PREFIX = "ospbank:admin:revoked_session:"
    ADMIN_AUTH_FAILURE_KEY_PREFIX = "ospbank:admin:authfail:"
    SECURITY_STATE_CLEANUP_BATCH_SIZE = 500
    SECURITY_STATE_RETENTION_DAYS = 30
    SESSION_HISTORY_LIMIT = 20
    CUSTOMER_MAX_ACTIVE_SESSIONS = 1
    ADMIN_MAX_ACTIVE_SESSIONS = 1
    MAX_ACTIVE_SESSIONS = 1
    PENDING_MFA_MAX_AGE_SECONDS = 5 * 60
    CUSTOMER_PENDING_MFA_MAX_AGE_SECONDS = PENDING_MFA_MAX_AGE_SECONDS
    SESSION_ABSOLUTE_LIFETIME_SECONDS = CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS
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
    ADMIN_RATELIMIT_STORAGE_URI = "memory://"
    ADMIN_RATELIMIT_KEY_PREFIX = "test-admin:"
    FRESH_MFA_SECONDS = 5 * 60
    TOTP_LOGIN_VALID_WINDOW = 1
    TOTP_HIGH_RISK_VALID_WINDOW = 0
    ADMIN_ALLOWED_EMAIL_DOMAINS = frozenset(
        {"sit.singaporetech.edu.sg", "singaporetech.edu.sg"}
    )
    SIT_WORKPLACE_EMAIL_DOMAINS = ADMIN_ALLOWED_EMAIL_DOMAINS
    STAFF_INVITE_ALIAS_SEPARATORS = ("+",)
    CUSTOMER_EMAIL_PLUS_ALIAS_DOMAINS = frozenset({"gmail.com", "googlemail.com"})
    CUSTOMER_EMAIL_DOT_INSENSITIVE_DOMAINS = frozenset({"gmail.com", "googlemail.com"})
    CUSTOMER_TEMP_EMAIL_DOMAINS = frozenset(
        {"10minutemail.com", "guerrillamail.com", "mailinator.com", "temp-mail.org", "yopmail.com"}
    )
    ROOT_ADMIN_EMAILS = frozenset(
        {
            "root1@sit.singaporetech.edu.sg",
            "root2@sit.singaporetech.edu.sg",
            "root3@sit.singaporetech.edu.sg",
            "root4@sit.singaporetech.edu.sg",
            "root5@sit.singaporetech.edu.sg",
        }
    )
    STAFF_INVITE_TTL_SECONDS = 24 * 60 * 60
    STAFF_WORKPLACE_VERIFICATION_TTL_SECONDS = 15 * 60
    TURNSTILE_ENABLED = False
    TURNSTILE_SITE_KEY = ""
    TURNSTILE_SECRET_KEY = None
    TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    TURNSTILE_CUSTOMER_LOGIN_ENABLED = False
    TURNSTILE_CUSTOMER_REGISTER_OTP_ENABLED = False
    TURNSTILE_CUSTOMER_REGISTER_ENABLED = False
    TURNSTILE_CUSTOMER_PASSWORD_RESET_ENABLED = False
    TURNSTILE_CUSTOMER_MANUAL_RECOVERY_ENABLED = False
    TURNSTILE_ADMIN_LOGIN_ENABLED = False
    TURNSTILE_ADMIN_INVITE_ACCEPT_ENABLED = True
    TURNSTILE_FAIL_CLOSED_IN_PRODUCTION = True
    PROFILE_EMAIL_CHANGE_TTL_SECONDS = 5 * 60
    TALISMAN_FORCE_HTTPS = False
    TALISMAN_CONTENT_SECURITY_POLICY = {
        "default-src": "'self'",
        "img-src": ["'self'", "data:"],
        "script-src": ["'self'", "https://challenges.cloudflare.com"],
        "style-src": "'self'",
        "frame-src": ["'self'", "https://challenges.cloudflare.com"],
    }
    TRUSTED_PROXY_COUNT = 0


SECURITY_TEST_FILES = frozenset(
    {
        "tests/test_account_security_actions.py",
        "tests/test_admin_audit_viewer.py",
        "tests/test_admin_bootstrap_root.py",
        "tests/test_admin_dashboard_role_separation.py",
        "tests/test_admin_manual_recovery.py",
        "tests/test_admin_route_inventory_security.py",
        "tests/test_admin_staff_invites.py",
        "tests/test_audit_alerting.py",
        "tests/test_auth_registration_login.py",
        "tests/test_authenticated_portal_ui.py",
        "tests/test_banking_transaction_security.py",
        "tests/test_ci_local.py",
        "tests/test_cloudflare_access_staging.py",
        "tests/test_cloudflare_origin_pull_ca.py",
        "tests/test_config.py",
        "tests/test_deployment.py",
        "tests/test_health_endpoints.py",
        "tests/test_mfa_envelope_crypto.py",
        "tests/test_mfa_lifecycle.py",
        "tests/test_owasp_regressions.py",
        "tests/test_payee_idor.py",
        "tests/test_payee_management_security.py",
        "tests/test_passwords.py",
        "tests/test_pentest_auth_bypass.py",
        "tests/test_db_session_integrity.py",
        "tests/test_gitleaks_workflow.py",
        "tests/test_lint_target_discovery.py",
        "tests/test_route_inventory_security.py",
        "tests/test_secret_scanner.py",
        "tests/test_static_analysis_workflows.py",
        "tests/test_session_absolute_lifetime.py",
        "tests/test_session_management.py",
        "tests/test_session_risk_binding.py",
        "tests/test_local_transfer_security.py",
    }
)
DEPLOYMENT_TEST_FILES = frozenset(
    {
        "tests/test_ci_local.py",
        "tests/test_cloudflare_origin_pull_ca.py",
        "tests/test_deployment.py",
    }
)
SLOW_TEST_FILES = frozenset(
    {
        "tests/test_account_security_actions.py",
        "tests/test_admin_staff_invites.py",
        "tests/test_audit_alerting.py",
        "tests/test_auth_registration_login.py",
        "tests/test_authenticated_portal_ui.py",
        "tests/test_banking_transaction_security.py",
        "tests/test_deployment.py",
        "tests/test_health_endpoints.py",
        "tests/test_mfa_lifecycle.py",
        "tests/test_pentest_auth_bypass.py",
        "tests/test_secret_scanner.py",
        "tests/test_session_absolute_lifetime.py",
        "tests/test_session_management.py",
        "tests/test_session_risk_binding.py",
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


def pytest_xdist_auto_num_workers(config) -> int:
    del config
    return min(os.cpu_count() or 1, 4)


def _clear_database_rows(flask_app) -> None:
    from app.extensions import db

    with flask_app.app_context():
        db.session.remove()
        with db.engine.begin() as connection:
            for table in reversed(db.metadata.sorted_tables):
                connection.execute(table.delete())
            if db.engine.dialect.name == "sqlite":
                has_sequence = connection.exec_driver_sql(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'sqlite_sequence'"
                ).scalar()
                if has_sequence:
                    connection.exec_driver_sql("DELETE FROM sqlite_sequence")
        db.session.remove()


def _restore_test_app_state(flask_app, baseline_config: dict) -> None:
    from app.extensions import limiter

    flask_app.config.clear()
    flask_app.config.update(copy.deepcopy(baseline_config))
    flask_app.extensions["password_reset_outbox"] = []
    flask_app.extensions.pop("e2e_fake_password_hashes", None)
    with flask_app.app_context():
        limiter.reset()
    _clear_database_rows(flask_app)


@pytest.fixture(scope="session")
def _worker_app():
    from app import create_app
    from app.extensions import db

    flask_app = create_app(TestConfig)
    with flask_app.app_context():
        db.create_all()
    baseline_config = copy.deepcopy(dict(flask_app.config))
    try:
        yield flask_app, baseline_config
    finally:
        with flask_app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()


@pytest.fixture()
def app(_worker_app, monkeypatch):
    from app.security import passwords

    monkeypatch.setattr(passwords, "_is_password_pwned_by_hibp", lambda _password: False)
    flask_app, baseline_config = _worker_app
    _restore_test_app_state(flask_app, baseline_config)
    try:
        with flask_app.app_context():
            yield flask_app
    finally:
        _restore_test_app_state(flask_app, baseline_config)


@pytest.fixture()
def mutable_app(monkeypatch):
    from app import create_app
    from app.extensions import db
    from app.security import passwords

    monkeypatch.setattr(passwords, "_is_password_pwned_by_hibp", lambda _password: False)
    flask_app = create_app(TestConfig)
    with flask_app.app_context():
        db.create_all()
        try:
            yield flask_app
        finally:
            db.session.remove()
            db.drop_all()
            db.engine.dispose()


@pytest.fixture()
def client(app):
    return app.test_client()
