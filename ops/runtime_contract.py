from __future__ import annotations

CUSTOMER_APP_SECRET_INPUTS = {
    "SECRET_KEY": "secret_key",
    "WTF_CSRF_SECRET_KEY": "wtf_csrf_secret_key",
    "SESSION_HMAC_KEYS_JSON": "session_hmac_keys_json",
    "SESSION_LOOKUP_HMAC_KEY": "session_lookup_hmac_key",
    "DATABASE_URL": "database_url",
    "MFA_KEK_KEYS_JSON": "mfa_kek_keys_json",
    "TRANSACTION_LEDGER_HMAC_KEYS_JSON": "transaction_ledger_hmac_keys_json",
    "PASSWORD_PEPPER_B64": "password_pepper_b64",
    "ROOT_ADMIN_EMAILS": "root_admin_emails",
    "SECURITY_AUDIT_HMAC_KEY": "security_audit_hmac_key",
    "SECURITY_ALERT_WEBHOOK_URL": "security_alert_webhook_url",
    "SMTP_USERNAME": "smtp_username",
    "SMTP_PASSWORD": "smtp_password",
    "TURNSTILE_SECRET_KEY": "turnstile_secret_key",
}

ADMIN_APP_SECRET_INPUTS = {
    "ADMIN_SECRET_KEY": "admin_secret_key",
    "ADMIN_WTF_CSRF_SECRET_KEY": "admin_wtf_csrf_secret_key",
    "ADMIN_SESSION_HMAC_KEYS_JSON": "admin_session_hmac_keys_json",
    "ADMIN_SESSION_LOOKUP_HMAC_KEY": "admin_session_lookup_hmac_key",
    "ADMIN_DATABASE_URL": "admin_database_url",
    "MFA_KEK_KEYS_JSON": "mfa_kek_keys_json",
    "TRANSACTION_LEDGER_HMAC_KEYS_JSON": "transaction_ledger_hmac_keys_json",
    "ADMIN_PASSWORD_PEPPER_B64": "admin_password_pepper_b64",
    "ROOT_ADMIN_EMAILS": "root_admin_emails",
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
}
STAGING_DATA_SERVICE_SECRET_FILES = tuple(STAGING_DATA_SERVICE_SECRETS.values())

NON_SECRET_DEFAULTS = {
    "COMMON_PASSWORDS_MIN_ENTRIES": "100000",  # NOSONAR - policy count
    "CUSTOMER_EMAIL_DOT_INSENSITIVE_DOMAINS": "gmail.com,googlemail.com",
    "CUSTOMER_EMAIL_PLUS_ALIAS_DOMAINS": "gmail.com,googlemail.com",
    "CUSTOMER_TEMP_EMAIL_DOMAINS": (
        "10minutemail.com,guerrillamail.com,mailinator.com,temp-mail.org,yopmail.com"
    ),
    "HIBP_CIRCUIT_FAILURE_THRESHOLD": "3",
    "HIBP_CIRCUIT_OPEN_SECONDS": "300",
    "HIBP_PASSWORD_CHECK_TIMEOUT_SECONDS": "2.0",  # NOSONAR - timeout
    "PAYEE_COOLDOWN_SECONDS": "43200",
    "PASSWORD_RESET_EMAIL_BACKEND": "smtp",  # NOSONAR - backend selector
    "PASSWORD_RESET_ENABLED": "true",  # NOSONAR - feature flag
    "PASSWORD_RESET_TOKEN_TTL_SECONDS": "1800",  # NOSONAR - token lifetime
    "PASSWORD_RESET_TRANSACTION_TTL_SECONDS": "900",  # NOSONAR - flow lifetime
    "PASSWORD_PBKDF2_ITERATIONS": "600000",  # NOSONAR - work factor
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

TURNSTILE_RUNTIME_ENVIRONMENT = (
    "TURNSTILE_ENABLED",
    "TURNSTILE_SITE_KEY",
    "TURNSTILE_VERIFY_URL",
    "TURNSTILE_CUSTOMER_LOGIN_ENABLED",
    "TURNSTILE_CUSTOMER_REGISTER_OTP_ENABLED",
    "TURNSTILE_CUSTOMER_REGISTER_ENABLED",
    "TURNSTILE_CUSTOMER_PASSWORD_RESET_ENABLED",
    "TURNSTILE_CUSTOMER_MANUAL_RECOVERY_ENABLED",
    "TURNSTILE_ADMIN_LOGIN_ENABLED",
    "TURNSTILE_ADMIN_INVITE_ACCEPT_ENABLED",
    "TURNSTILE_FAIL_CLOSED_IN_PRODUCTION",
)

POLICY_CONFIG_PATHS = {
    "COMMON_PASSWORDS_PATH": "/run/config/common-passwords.txt",
}

NON_SECRET_RUNTIME_ENVIRONMENT = tuple(
    sorted(
        {
            "APP_ENV",
            "DEPLOYMENT_TARGET",
            "PASSWORD_RESET_BASE_URL",
            "PASSWORD_RESET_EMAIL_FROM",
            "MFA_KEK_ACTIVE_ID",
            "MFA_ISSUER_NAME",
            "SESSION_HMAC_ACTIVE_KEY_ID",
            "TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID",
            "SMTP_HOST",
            *NON_SECRET_DEFAULTS,
            *POLICY_CONFIG_PATHS,
            *TURNSTILE_RUNTIME_ENVIRONMENT,
        }
    )
)

STAGING_CLOUDFLARE_ACCESS_RUNTIME_ENVIRONMENT = (
    "STAGING_CLOUDFLARE_ACCESS_AUD",
    "STAGING_CLOUDFLARE_ACCESS_JWKS_CACHE_TTL_SECONDS",
    "STAGING_CLOUDFLARE_ACCESS_JWT_REQUIRED",
    "STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN",
)

ADMIN_NON_SECRET_RUNTIME_ENVIRONMENT = (
    "ADMIN_SESSION_HMAC_ACTIVE_KEY_ID",
    "ADMIN_SESSION_KEY_PREFIX",
    "ADMIN_RATELIMIT_KEY_PREFIX",
)

PRODUCTION_NON_SECRET_RUNTIME_ENVIRONMENT = tuple(
    sorted({*NON_SECRET_RUNTIME_ENVIRONMENT, *ADMIN_NON_SECRET_RUNTIME_ENVIRONMENT})
)
