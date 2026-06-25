from __future__ import annotations

CUSTOMER_APP_SECRET_INPUTS = {
    "SECRET_KEY": "secret_key",
    "WTF_CSRF_SECRET_KEY": "wtf_csrf_secret_key",
    "SESSION_HMAC_KEYS_JSON": "session_hmac_keys_json",
    "DATABASE_URL": "database_url",
    "REDIS_URL": "redis_url",
    "MFA_KEK_KEYS_JSON": "mfa_kek_keys_json",
    "PASSWORD_PEPPER_B64": "password_pepper_b64",
    "SECURITY_AUDIT_HMAC_KEY": "security_audit_hmac_key",
    "SECURITY_ALERT_WEBHOOK_URL": "security_alert_webhook_url",
    "SMTP_USERNAME": "smtp_username",
    "SMTP_PASSWORD": "smtp_password",
}

ADMIN_APP_SECRET_INPUTS = {
    "ADMIN_SECRET_KEY": "admin_secret_key",
    "ADMIN_WTF_CSRF_SECRET_KEY": "admin_wtf_csrf_secret_key",
    "ADMIN_SESSION_HMAC_KEYS_JSON": "admin_session_hmac_keys_json",
    "ADMIN_DATABASE_URL": "admin_database_url",
    "ADMIN_REDIS_URL": "admin_redis_url",
    "ADMIN_PASSWORD_PEPPER_B64": "admin_password_pepper_b64",
}

APP_SECRET_INPUTS = CUSTOMER_APP_SECRET_INPUTS

MIGRATION_SECRET_INPUTS = {
    "DATABASE_MIGRATION_URL": "database_migration_url",
}

CONFIG_SECRET_INPUTS = {
    **MIGRATION_SECRET_INPUTS,
    **CUSTOMER_APP_SECRET_INPUTS,
    **ADMIN_APP_SECRET_INPUTS,
}

DEPLOYMENT_SECRET_INPUTS = {
    name: secret_file
    for name, secret_file in {**MIGRATION_SECRET_INPUTS, **CUSTOMER_APP_SECRET_INPUTS}.items()
    if name != "SESSION_HMAC_KEYS_JSON"
}

PRODUCTION_SECRET_INPUTS = {
    name: secret_file
    for name, secret_file in CONFIG_SECRET_INPUTS.items()
    if name not in {"SESSION_HMAC_KEYS_JSON", "ADMIN_SESSION_HMAC_KEYS_JSON"}
}

APP_SECRET_FILE_ENVIRONMENT = {
    f"{name}_FILE": f"/run/secrets/{secret_file}"
    for name, secret_file in CUSTOMER_APP_SECRET_INPUTS.items()
}

ADMIN_SECRET_FILE_ENVIRONMENT = {
    f"{name}_FILE": f"/run/secrets/{secret_file}"
    for name, secret_file in ADMIN_APP_SECRET_INPUTS.items()
}

APP_SECRET_FILES = tuple(CUSTOMER_APP_SECRET_INPUTS.values())
ADMIN_SECRET_FILES = tuple(ADMIN_APP_SECRET_INPUTS.values())
DEPLOYMENT_SECRET_FILES = tuple(
    {**MIGRATION_SECRET_INPUTS, **CUSTOMER_APP_SECRET_INPUTS}.values()
)
PRODUCTION_SECRET_FILES = tuple(CONFIG_SECRET_INPUTS.values())
STAGING_DATA_SERVICE_SECRETS = {
    "postgres_owner_password": "postgres_owner_password",
    "postgres_app_password": "postgres_app_password",
    "redis_conf": "redis.conf",
}
STAGING_DATA_SERVICE_SECRET_FILES = tuple(STAGING_DATA_SERVICE_SECRETS.values())

NON_SECRET_DEFAULTS = {
    "COMMON_PASSWORDS_MIN_ENTRIES": "100000",
    "HIBP_CIRCUIT_FAILURE_THRESHOLD": "3",
    "HIBP_CIRCUIT_OPEN_SECONDS": "300",
    "HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS": "2.0",
    "PASSWORD_RESET_EMAIL_BACKEND": "smtp",
    "PASSWORD_RESET_ENABLED": "true",
    "PASSWORD_RESET_TOKEN_TTL_SECONDS": "1800",
    "PASSWORD_RESET_TRANSACTION_TTL_SECONDS": "900",
    "PASSWORD_PBKDF2_ITERATIONS": "600000",
    "SECURITY_ALERT_DEDUPE_TTL_SECONDS": "300",
    "SECURITY_ALERT_ENABLED": "true",
    "SECURITY_ALERT_MIN_SEVERITY": "high",
    "SECURITY_ALERT_STATE_PATH": "/run/state/security-alert-state.json",
    "SECURITY_ALERT_TIMEOUT_SECONDS": "5.0",
    "SECURITY_AUDIT_ANCHOR_PATH": "/run/state/security-audit.anchor",
    "SMTP_PORT": "587",
    "SMTP_USE_TLS": "true",
    "TRUSTED_PROXY_COUNT": "1",
}

POLICY_CONFIG_PATHS = {
    "COMMON_PASSWORDS_PATH": "/run/config/common-passwords.txt",
    "WEBAUTHN_APPROVED_AAGUIDS_PATH": "/run/config/fido-approved-aaguids.json",
    "WEBAUTHN_MDS_CACHE_PATH": "/run/config/fido-mds-cache.json",
}

NON_SECRET_RUNTIME_ENVIRONMENT = tuple(
    sorted(
        {
            "APP_ENV",
            "PASSWORD_RESET_BASE_URL",
            "PASSWORD_RESET_EMAIL_FROM",
            "MFA_KEK_ACTIVE_ID",
            "MFA_ISSUER_NAME",
            "SESSION_HMAC_ACTIVE_KEY_ID",
            "SMTP_HOST",
            "WEBAUTHN_RP_ID",
            "WEBAUTHN_RP_ORIGIN",
            *NON_SECRET_DEFAULTS,
            *POLICY_CONFIG_PATHS,
        }
    )
)

ADMIN_NON_SECRET_RUNTIME_ENVIRONMENT = (
    "ADMIN_SESSION_HMAC_ACTIVE_KEY_ID",
    "ADMIN_SESSION_KEY_PREFIX",
    "ADMIN_RATELIMIT_KEY_PREFIX",
)

PRODUCTION_NON_SECRET_RUNTIME_ENVIRONMENT = tuple(
    sorted({*NON_SECRET_RUNTIME_ENVIRONMENT, *ADMIN_NON_SECRET_RUNTIME_ENVIRONMENT})
)
