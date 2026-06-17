from __future__ import annotations

APP_SECRET_INPUTS = {
    "SECRET_KEY": "secret_key",
    "WTF_CSRF_SECRET_KEY": "wtf_csrf_secret_key",
    "SESSION_HMAC_KEYS_JSON": "session_hmac_keys_json",
    "DATABASE_URL": "database_url",
    "REDIS_URL": "redis_url",
    "MFA_KEK_KEYS_JSON": "mfa_kek_keys_json",
    "PASSWORD_PEPPER_B64": "password_pepper_b64",
}

MIGRATION_SECRET_INPUTS = {
    "DATABASE_MIGRATION_URL": "database_migration_url",
}

CONFIG_SECRET_INPUTS = {
    **MIGRATION_SECRET_INPUTS,
    **APP_SECRET_INPUTS,
}

DEPLOYMENT_SECRET_INPUTS = {
    name: secret_file
    for name, secret_file in CONFIG_SECRET_INPUTS.items()
    if name != "SESSION_HMAC_KEYS_JSON"
}

APP_SECRET_FILE_ENVIRONMENT = {
    f"{name}_FILE": f"/run/secrets/{secret_file}"
    for name, secret_file in APP_SECRET_INPUTS.items()
}

APP_SECRET_FILES = tuple(APP_SECRET_INPUTS.values())
DEPLOYMENT_SECRET_FILES = tuple(CONFIG_SECRET_INPUTS.values())
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
    "PASSWORD_PBKDF2_ITERATIONS": "600000",
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
            "MFA_KEK_ACTIVE_ID",
            "MFA_ISSUER_NAME",
            "SESSION_HMAC_ACTIVE_KEY_ID",
            "WEBAUTHN_RP_ID",
            "WEBAUTHN_RP_ORIGIN",
            *NON_SECRET_DEFAULTS,
            *POLICY_CONFIG_PATHS,
        }
    )
)
