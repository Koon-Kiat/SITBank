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

MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS = 12 * 60 * 60
MAX_PAYEE_COOLDOWN_SECONDS = 30 * 24 * 60 * 60
DEFAULT_DEVELOPMENT_PASSWORD_MIN_LENGTH = 8
MIN_PRODUCTION_PASSWORD_LENGTH = 15
DEFAULT_CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS = 12 * 60 * 60
DEFAULT_ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS = 4 * 60 * 60
MAX_SESSION_ABSOLUTE_LIFETIME_SECONDS = 30 * 24 * 60 * 60
MEMORY_RATE_LIMIT_STORAGE = "memory://"
POSTGRESQL_PSYCOPG2_SCHEME = "postgresql+psycopg2"
CSP_SELF = "'self'"
CSP_NONE = "'none'"
OFFICIAL_TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_ORIGIN = "https://challenges.cloudflare.com"
CONFIG_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$"
)
CONFIG_EMAIL_RE = re.compile(r"^(?=.{1,255}$)(?=.{1,128}@)[^@\x00-\x1f\x7f]+@[^@\x00-\x1f\x7f]+$")
ROOT_ADMIN_NUMERIC_PLACEHOLDER_RE = re.compile(
    r"^([a-z][a-z_-]*)(\d+)$"
)
ROOT_ADMIN_NUMERIC_PLACEHOLDER_PREFIXES = frozenset(
    {
        "admin",
        "changeme",
        "demo",
        "example",
        "placeholder",
        "replaceme",
        "root",
        "rootadmin",
        "test",
    }
)
PERSONAL_EMAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "outlook.com",
        "hotmail.com",
        "yahoo.com",
        "icloud.com",
        "proton.me",
        "protonmail.com",
    }
)
STAGING_ROOT_ADMIN_EMAIL_COUNT = 2
PRODUCTION_ROOT_ADMIN_EMAIL_COUNT = 5
ROOT_ADMIN_EMAIL_COUNT = PRODUCTION_ROOT_ADMIN_EMAIL_COUNT
DEFAULT_ROOT_ADMIN_EMAILS = frozenset(
    f"root{index}@sit.singaporetech.edu.sg"
    for index in range(1, ROOT_ADMIN_EMAIL_COUNT + 1)
)
DEFAULT_ROOT_ADMIN_EMAILS_CSV = ",".join(
    f"root{index}@sit.singaporetech.edu.sg"
    for index in range(1, ROOT_ADMIN_EMAIL_COUNT + 1)
)
ROOT_ADMIN_PLACEHOLDER_LOCAL_PARTS = frozenset(
    {
        "admin",
        "demo",
        "example",
        "placeholder",
        "root",
        "root-admin",
        "root_admin",
        "rootadmin",
        "test",
    }
)


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
    "TRANSACTION_LEDGER_HMAC_KEYS": "TRANSACTION_LEDGER_HMAC_KEYS_JSON",
    "PASSWORD_PEPPER_B64": "PASSWORD_PEPPER_B64",
    "SECURITY_AUDIT_HMAC_KEY": "SECURITY_AUDIT_HMAC_KEY",
}

ADMIN_RUNTIME_SECRET_ENV_NAMES = {
    "SECRET_KEY": "ADMIN_SECRET_KEY",
    "WTF_CSRF_SECRET_KEY": "ADMIN_WTF_CSRF_SECRET_KEY",
    "SESSION_HMAC_KEYS": "ADMIN_SESSION_HMAC_KEYS_JSON",
    "SESSION_LOOKUP_HMAC_KEY": "ADMIN_SESSION_LOOKUP_HMAC_KEY",
    "SQLALCHEMY_DATABASE_URI": "ADMIN_DATABASE_URL",
    "MFA_KEK_KEYS": "MFA_KEK_KEYS_JSON",
    "TRANSACTION_LEDGER_HMAC_KEYS": "TRANSACTION_LEDGER_HMAC_KEYS_JSON",
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


def _env_or_file_conflict_message(name: str) -> str:
    return f"Configure either {name} or {name}_FILE, not both"


def _required_env_or_file(name: str) -> str:
    direct_value = os.getenv(name)
    file_value = os.getenv(f"{name}_FILE")
    if direct_value and file_value:
        raise RuntimeError(_env_or_file_conflict_message(name))
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
        raise RuntimeError(_env_or_file_conflict_message(name))
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
    path, resolved = _resolved_audit_anchor_path(name, value)
    resolved_parent = _resolved_audit_anchor_parent(name, path)

    _reject_unsafe_audit_anchor_location(name, resolved, database_url=database_url)
    _reject_world_writable_path(name, resolved_parent, "parent directory")
    _validate_audit_anchor_access(name, path, resolved, resolved_parent)
    return str(resolved)


def _resolved_audit_anchor_path(name: str, value: str) -> tuple[Path, Path]:
    text = str(value or "").strip()
    if not text:
        raise RuntimeError(f"{name} must not be empty")
    if any(character in text for character in ("\x00", "\r", "\n")):
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
    return path, resolved


def _resolved_audit_anchor_parent(name: str, path: Path) -> Path:
    parent = path.parent
    if parent.is_symlink():
        raise RuntimeError(f"{name} parent directory must not be a symlink")
    try:
        resolved_parent = parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f"{name} parent directory must exist") from exc
    if not resolved_parent.is_dir():
        raise RuntimeError(f"{name} parent must be a directory")
    return resolved_parent


def _validate_audit_anchor_access(
    name: str,
    path: Path,
    resolved: Path,
    resolved_parent: Path,
) -> None:
    if path.exists():
        _reject_world_writable_path(name, resolved, "file")
        if not os.access(resolved, os.R_OK | os.W_OK):
            raise RuntimeError(f"{name} must be readable and writable by the runtime")
    elif not os.access(resolved_parent, os.W_OK | os.X_OK):
        raise RuntimeError(f"{name} parent directory must be writable by the runtime")


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
        raise RuntimeError(_env_or_file_conflict_message(name))
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


def _csv_env_set(name: str, *, default: str) -> frozenset[str]:
    raw_value = os.getenv(name, default)
    values = frozenset(
        item.strip().casefold()
        for item in raw_value.split(",")
        if item.strip()
    )
    if not values:
        raise RuntimeError(f"{name} must contain at least one value")
    return values


def _csv_env_values(name: str, *, default: str) -> tuple[str, ...]:
    raw_value = os.getenv(name, default)
    return _csv_values(name, raw_value)


def _csv_env_or_file_values(name: str, *, default: str) -> tuple[str, ...]:
    direct_value = os.getenv(name)
    file_value = os.getenv(f"{name}_FILE")
    if direct_value is not None and file_value:
        raise RuntimeError(_env_or_file_conflict_message(name))
    if file_value:
        raw_value = _read_secret_file(name, file_value)
    elif direct_value is not None:
        raw_value = direct_value
    else:
        raw_value = default
    return _csv_values(name, raw_value)


def _csv_values(name: str, raw_value: str) -> tuple[str, ...]:
    values: list[str] = []
    for item in raw_value.split(","):
        normalized = item.strip().casefold()
        if not normalized:
            raise RuntimeError(f"{name} must not contain empty entries")
        values.append(normalized)
    if not values:
        raise RuntimeError(f"{name} must contain at least one value")
    return tuple(values)


def _csv_domain_set(name: str, *, default: str, reject_personal: bool = True) -> frozenset[str]:
    domains = _csv_env_set(name, default=default)
    if any(not _valid_config_domain(domain, reject_personal=reject_personal) for domain in domains):
        raise RuntimeError(f"{name} must contain only approved workplace email domains")
    return domains


def _csv_public_domain_set(name: str, *, default: str) -> frozenset[str]:
    domains = _csv_env_set(name, default=default)
    if any(not _valid_config_domain(domain, reject_personal=False) for domain in domains):
        raise RuntimeError(f"{name} must contain only valid email domains")
    return domains


def _valid_config_domain(domain: str, *, reject_personal: bool) -> bool:
    normalized = str(domain or "").strip().casefold()
    if not normalized or _looks_placeholder(normalized):
        return False
    if normalized in {"example.com", "example.test", "localhost"}:
        return False
    if normalized.endswith(".") or "*" in normalized or "@" in normalized or "/" in normalized:
        return False
    if reject_personal and normalized in PERSONAL_EMAIL_DOMAINS:
        return False
    return bool(CONFIG_DOMAIN_RE.fullmatch(normalized))


def _valid_config_email(value: str) -> bool:
    normalized = str(value or "").strip().casefold()
    if not normalized or _looks_placeholder(normalized):
        return False
    if "\x00" in normalized or "\r" in normalized or "\n" in normalized:
        return False
    local, separator, domain = normalized.partition("@")
    if separator != "@" or not local or not _valid_config_domain(domain, reject_personal=True):
        return False
    return bool(CONFIG_EMAIL_RE.fullmatch(normalized))


def _root_admin_email_has_placeholder_identity(value: str) -> bool:
    normalized = str(value or "").strip().casefold()
    local, separator, domain = normalized.partition("@")
    if separator != "@":
        return True
    if _looks_placeholder(local) or _looks_placeholder(domain):
        return True
    if local in ROOT_ADMIN_PLACEHOLDER_LOCAL_PARTS:
        return True
    numeric_placeholder = ROOT_ADMIN_NUMERIC_PLACEHOLDER_RE.fullmatch(local)
    if numeric_placeholder:
        normalized_prefix = numeric_placeholder.group(1).replace("-", "").replace("_", "")
        if normalized_prefix in ROOT_ADMIN_NUMERIC_PLACEHOLDER_PREFIXES:
            return True
    if any(token in local for token in ("placeholder", "example", "demo", "changeme", "replace")):
        return True
    return domain in {"example.com", "example.test"}


def root_admin_email_allowlist_failures(
    values: object,
    *,
    allowed_domains: object,
    reject_default: bool,
    required_count: int = ROOT_ADMIN_EMAIL_COUNT,
) -> list[str]:
    emails, failures = _normalized_root_admin_email_values(
        values,
        required_count=required_count,
    )
    if emails is None:
        return failures

    failures.extend(
        _root_admin_email_shape_failures(
            emails,
            allowed_domains,
            required_count=required_count,
            allow_builtin_default=not reject_default and frozenset(emails) == DEFAULT_ROOT_ADMIN_EMAILS,
        )
    )
    if reject_default and frozenset(emails) == DEFAULT_ROOT_ADMIN_EMAILS:
        failures.append("ROOT_ADMIN_EMAILS must be explicitly configured for production/admin runtime")
    return failures


def _normalized_root_admin_email_values(
    values: object,
    *,
    required_count: int,
) -> tuple[tuple[str, ...] | None, list[str]]:
    if not isinstance(values, (set, frozenset, list, tuple)):
        return None, [
            f"ROOT_ADMIN_EMAILS must configure exactly {required_count} root administrators"
        ]
    emails = tuple(str(item or "").strip().casefold() for item in values)
    return emails, []


def _root_admin_email_shape_failures(
    emails: tuple[str, ...],
    allowed_domains: object,
    *,
    required_count: int,
    allow_builtin_default: bool = False,
) -> list[str]:
    failures: list[str] = []
    if any(not item for item in emails):
        failures.append("ROOT_ADMIN_EMAILS must not contain empty entries")
    if len(emails) != required_count:
        failures.append(
            f"ROOT_ADMIN_EMAILS must configure exactly {required_count} root administrators"
        )
    if len(set(emails)) != len(emails):
        failures.append("ROOT_ADMIN_EMAILS must not contain duplicate email addresses")

    allowed = frozenset(str(item or "").strip().casefold() for item in (allowed_domains or ()))
    email_set = frozenset(emails)
    if any(not _valid_config_email(item) for item in emails) or not _all_email_domains_allowed(email_set, allowed):
        failures.append("ROOT_ADMIN_EMAILS must use approved admin workplace domains")
    if not allow_builtin_default and any(_root_admin_email_has_placeholder_identity(item) for item in emails):
        failures.append("ROOT_ADMIN_EMAILS must not contain placeholder, demo, or example identities")
    return failures


def _root_admin_email_set(
    name: str,
    *,
    default: str,
    allowed_domains: frozenset[str],
    app_env: str,
    deployment_target: str,
) -> frozenset[str]:
    emails = _csv_env_or_file_values(name, default=default)
    required_count = _required_root_admin_email_count(
        deployment_target=deployment_target,
    )
    failures = root_admin_email_allowlist_failures(
        emails,
        allowed_domains=allowed_domains,
        reject_default=_production_like(app_env, deployment_target),
        required_count=required_count,
    )
    if failures:
        raise RuntimeError(failures[0])
    return frozenset(emails)


def _required_root_admin_email_count(*, deployment_target: str) -> int:
    if str(deployment_target or "").strip().casefold() == "staging":
        return STAGING_ROOT_ADMIN_EMAIL_COUNT
    return PRODUCTION_ROOT_ADMIN_EMAIL_COUNT


def _email_domain(value: str) -> str:
    _local, separator, domain = str(value or "").strip().partition("@")
    return domain.casefold() if separator else ""


def _all_email_domains_allowed(emails: frozenset[str], allowed_domains: frozenset[str]) -> bool:
    return all(_valid_config_email(item) and _email_domain(item) in allowed_domains for item in emails)


def _optional_turnstile_secret() -> str | None:
    direct_value = os.getenv("TURNSTILE_SECRET_KEY")
    file_value = os.getenv("TURNSTILE_SECRET_KEY_FILE")
    if direct_value and file_value:
        raise RuntimeError("Configure either TURNSTILE_SECRET_KEY or TURNSTILE_SECRET_KEY_FILE, not both")
    if file_value:
        return _read_secret_file("TURNSTILE_SECRET_KEY", file_value)
    if not direct_value:
        return None
    if _looks_placeholder(direct_value):
        raise RuntimeError("TURNSTILE_SECRET_KEY contains a placeholder value")
    return direct_value


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


def _production_like(app_env: str, deployment_target: str | None = None) -> bool:
    normalized_env = str(app_env or "").strip().casefold()
    normalized_target = str(deployment_target or "").strip().casefold()
    return normalized_env == "production" or normalized_target in {"staging", "production"}


def _validate_smtp_transport_config(
    *,
    app_env: str,
    deployment_target: str,
    email_backend: str,
    smtp_use_tls: bool,
) -> None:
    if email_backend != "smtp":
        return
    if _production_like(app_env, deployment_target) and not smtp_use_tls:
        raise RuntimeError("SMTP_USE_TLS=true is required for staging and production SMTP")


def _validate_active_session_limit_config(
    *,
    customer_limit: object,
    admin_limit: object,
) -> None:
    for name, value in {
        "CUSTOMER_MAX_ACTIVE_SESSIONS": customer_limit,
        "ADMIN_MAX_ACTIVE_SESSIONS": admin_limit,
    }.items():
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"{name} must be an integer") from exc
        if parsed != 1:
            raise RuntimeError(f"{name} must be 1")


def _validate_password_history_config(
    *,
    enabled: object,
    retention_count: object,
) -> None:
    if enabled is not True:
        raise RuntimeError("PASSWORD_HISTORY_ENABLED must be true")
    try:
        retention = int(retention_count)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("PASSWORD_HISTORY_RETENTION_COUNT must be an integer") from exc
    if retention < 3:
        raise RuntimeError("PASSWORD_HISTORY_RETENTION_COUNT must be at least 3")


def _validate_turnstile_verify_url(
    *,
    app_env: str,
    deployment_target: str,
    verify_url: str,
) -> str:
    value = str(verify_url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError("TURNSTILE_VERIFY_URL must be an HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError("TURNSTILE_VERIFY_URL must not include credentials, query, or fragment")
    if _production_like(app_env, deployment_target) and value != OFFICIAL_TURNSTILE_VERIFY_URL:
        raise RuntimeError("TURNSTILE_VERIFY_URL must use the official Cloudflare Siteverify endpoint")
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


def _validate_password_length_config(
    *,
    app_env: str,
    minimum_length: object,
    maximum_chars: object,
) -> None:
    try:
        minimum = int(minimum_length)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("PASSWORD_MIN_LENGTH must be an integer") from exc
    try:
        maximum = int(maximum_chars)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("PASSWORD_MAX_CHARS must be an integer") from exc
    if minimum < 1 or minimum > 1024:
        raise RuntimeError("PASSWORD_MIN_LENGTH must be between 1 and 1024")
    if maximum < 64 or maximum > 1024:
        raise RuntimeError("PASSWORD_MAX_CHARS must be between 64 and 1024")
    if maximum < minimum:
        raise RuntimeError("PASSWORD_MAX_CHARS must be at least PASSWORD_MIN_LENGTH")
    if str(app_env or "").strip().casefold() == "production" and minimum < MIN_PRODUCTION_PASSWORD_LENGTH:
        raise RuntimeError(
            "PASSWORD_MIN_LENGTH must be at least "
            f"{MIN_PRODUCTION_PASSWORD_LENGTH} in production"
        )


def _validate_payee_cooldown_config(
    *,
    app_env: str,
    cooldown_seconds: object,
    min_production_seconds: object = MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS,
) -> None:
    try:
        cooldown = int(cooldown_seconds)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("PAYEE_COOLDOWN_SECONDS must be an integer") from exc
    try:
        minimum = int(min_production_seconds)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS must be an integer") from exc
    if cooldown < 1 or cooldown > MAX_PAYEE_COOLDOWN_SECONDS:
        raise RuntimeError(
            "PAYEE_COOLDOWN_SECONDS must be between 1 and "
            f"{MAX_PAYEE_COOLDOWN_SECONDS} seconds"
        )
    if minimum < 1 or minimum > MAX_PAYEE_COOLDOWN_SECONDS:
        raise RuntimeError(
            "MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS must be between 1 and "
            f"{MAX_PAYEE_COOLDOWN_SECONDS} seconds"
        )
    if str(app_env or "").strip().casefold() == "production" and cooldown < minimum:
        raise RuntimeError(
            "PAYEE_COOLDOWN_SECONDS must be at least "
            f"{minimum} seconds in production"
        )


def _validate_session_absolute_lifetime_config(
    *,
    customer_lifetime_seconds: object,
    admin_lifetime_seconds: object,
    customer_pending_mfa_seconds: object,
    admin_pending_mfa_seconds: object,
) -> None:
    try:
        customer_lifetime = int(customer_lifetime_seconds)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS must be an integer") from exc
    try:
        admin_lifetime = int(admin_lifetime_seconds)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS must be an integer") from exc
    try:
        customer_pending_mfa = int(customer_pending_mfa_seconds)
        admin_pending_mfa = int(admin_pending_mfa_seconds)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("PENDING_MFA_MAX_AGE_SECONDS values must be integers") from exc

    bounds_message = f"between 1 and {MAX_SESSION_ABSOLUTE_LIFETIME_SECONDS} seconds"
    if customer_lifetime < 1 or customer_lifetime > MAX_SESSION_ABSOLUTE_LIFETIME_SECONDS:
        raise RuntimeError(f"CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS must be {bounds_message}")
    if admin_lifetime < 1 or admin_lifetime > MAX_SESSION_ABSOLUTE_LIFETIME_SECONDS:
        raise RuntimeError(f"ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS must be {bounds_message}")
    if customer_lifetime <= customer_pending_mfa:
        raise RuntimeError(
            "CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS must be greater than "
            "PENDING_MFA_MAX_AGE_SECONDS"
        )
    if admin_lifetime <= admin_pending_mfa:
        raise RuntimeError(
            "ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS must be greater than "
            "ADMIN_PENDING_MFA_MAX_AGE_SECONDS"
        )
    if admin_lifetime > customer_lifetime:
        raise RuntimeError(
            "ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS must be less than or equal to "
            "CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS"
        )


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
    transaction_ledger_active_key_id = str(
        _configured_value(
            config,
            "TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID",
            lambda: _required_env("TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID"),
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
                schemes={"postgresql", POSTGRESQL_PSYCOPG2_SCHEME},
                require_password=True,
            ),
        ),
        "SQLALCHEMY_MIGRATION_DATABASE_URI": _configured_value(
            config,
            "SQLALCHEMY_MIGRATION_DATABASE_URI",
            lambda: _optional_url(
                "DATABASE_MIGRATION_URL",
                schemes={"postgresql", POSTGRESQL_PSYCOPG2_SCHEME},
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
        "TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID": transaction_ledger_active_key_id,
        "TRANSACTION_LEDGER_HMAC_KEYS": _configured_value(
            config,
            "TRANSACTION_LEDGER_HMAC_KEYS",
            lambda: _required_keyring(
                "TRANSACTION_LEDGER_HMAC_KEYS_JSON",
                active_key_id=transaction_ledger_active_key_id,
                active_label="TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID",
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
        "PENDING_MFA_MAX_AGE_SECONDS": config.get("CUSTOMER_PENDING_MFA_MAX_AGE_SECONDS")
        or config.get("PENDING_MFA_MAX_AGE_SECONDS")
        or 5 * 60,
        "SESSION_ABSOLUTE_LIFETIME_SECONDS": config.get("CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS")
        or DEFAULT_CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS,
        "MAX_ACTIVE_SESSIONS": config.get("CUSTOMER_MAX_ACTIVE_SESSIONS") or 1,
        "AUTH_FAILURE_KEY_PREFIX": config.get("AUTH_FAILURE_KEY_PREFIX") or "ospbank:authfail:",
        "RATELIMIT_STORAGE_URI": config.get("RATELIMIT_STORAGE_URI") or MEMORY_RATE_LIMIT_STORAGE,
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
    mfa_kek_active_id = str(
        _configured_value(
            config,
            "MFA_KEK_ACTIVE_ID",
            lambda: _required_env("MFA_KEK_ACTIVE_ID"),
        )
    )
    transaction_ledger_active_key_id = str(
        _configured_value(
            config,
            "TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID",
            lambda: _required_env("TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID"),
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
                schemes={"postgresql", POSTGRESQL_PSYCOPG2_SCHEME},
                require_password=True,
            ),
        ),
        "SQLALCHEMY_MIGRATION_DATABASE_URI": None,
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
        "TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID": transaction_ledger_active_key_id,
        "TRANSACTION_LEDGER_HMAC_KEYS": _configured_value(
            config,
            "TRANSACTION_LEDGER_HMAC_KEYS",
            lambda: _required_keyring(
                "TRANSACTION_LEDGER_HMAC_KEYS_JSON",
                active_key_id=transaction_ledger_active_key_id,
                active_label="TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID",
            ),
        ),
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
        "SESSION_ABSOLUTE_LIFETIME_SECONDS": config.get("ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS")
        or DEFAULT_ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS,
        "MAX_ACTIVE_SESSIONS": config.get("ADMIN_MAX_ACTIVE_SESSIONS") or 1,
        "AUTH_FAILURE_KEY_PREFIX": config.get("ADMIN_AUTH_FAILURE_KEY_PREFIX") or "ospbank:admin:authfail:",
        "RATELIMIT_STORAGE_URI": config.get("ADMIN_RATELIMIT_STORAGE_URI") or MEMORY_RATE_LIMIT_STORAGE,
        "RATELIMIT_KEY_PREFIX": config.get("ADMIN_RATELIMIT_KEY_PREFIX")
        or os.getenv("ADMIN_RATELIMIT_KEY_PREFIX", "ospbank:admin:ratelimit:"),
        "ADMIN_AUTH_ENABLED": True,
        "ADMIN_STEP_UP_PHASE": "totp",
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
    DEPLOYMENT_TARGET = os.getenv("DEPLOYMENT_TARGET", "development").strip().lower()
    STAGING_CLOUDFLARE_ACCESS_JWT_REQUIRED = _optional_bool(
        "STAGING_CLOUDFLARE_ACCESS_JWT_REQUIRED",
        default=False,
    )
    STAGING_CLOUDFLARE_ACCESS_AUD = os.getenv(
        "STAGING_CLOUDFLARE_ACCESS_AUD",
        "",
    ).strip()
    STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN = os.getenv(
        "STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN",
        "",
    ).strip()
    STAGING_CLOUDFLARE_ACCESS_JWKS_CACHE_TTL_SECONDS = _int_env(
        "STAGING_CLOUDFLARE_ACCESS_JWKS_CACHE_TTL_SECONDS",
        default="300",
        minimum=60,
        maximum=3600,
    )
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
    TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID = None
    TRANSACTION_LEDGER_HMAC_KEYS = None
    PASSWORD_PEPPER_B64 = None
    PASSWORD_PBKDF2_ITERATIONS = int(os.getenv("PASSWORD_PBKDF2_ITERATIONS", "600000"))
    if PASSWORD_PBKDF2_ITERATIONS < 600000:
        raise RuntimeError("PASSWORD_PBKDF2_ITERATIONS must be 600000 or higher")
    PASSWORD_HISTORY_ENABLED = _optional_bool("PASSWORD_HISTORY_ENABLED", default=True)
    PASSWORD_HISTORY_RETENTION_COUNT = _int_env(
        "PASSWORD_HISTORY_RETENTION_COUNT",
        default="3",
        minimum=3,
        maximum=24,
    )
    _validate_password_history_config(
        enabled=PASSWORD_HISTORY_ENABLED,
        retention_count=PASSWORD_HISTORY_RETENTION_COUNT,
    )
    PASSWORD_MIN_LENGTH = _int_env(
        "PASSWORD_MIN_LENGTH",
        default=(
            str(MIN_PRODUCTION_PASSWORD_LENGTH)
            if APP_ENV == "production"
            else str(DEFAULT_DEVELOPMENT_PASSWORD_MIN_LENGTH)
        ),
        minimum=1,
        maximum=1024,
    )
    PASSWORD_RECOMMENDED_MIN_LENGTH = max(MIN_PRODUCTION_PASSWORD_LENGTH, PASSWORD_MIN_LENGTH)
    PASSWORD_MAX_CHARS = _int_env(
        "PASSWORD_MAX_CHARS",
        default="256",
        minimum=64,
        maximum=1024,
    )
    _validate_password_length_config(
        app_env=APP_ENV,
        minimum_length=PASSWORD_MIN_LENGTH,
        maximum_chars=PASSWORD_MAX_CHARS,
    )
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
    _validate_smtp_transport_config(
        app_env=APP_ENV,
        deployment_target=DEPLOYMENT_TARGET,
        email_backend=PASSWORD_RESET_EMAIL_BACKEND,
        smtp_use_tls=SMTP_USE_TLS,
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
    CUSTOMER_MAX_ACTIVE_SESSIONS = _int_env(
        "CUSTOMER_MAX_ACTIVE_SESSIONS",
        default="1",
        minimum=1,
        maximum=1,
    )
    ADMIN_MAX_ACTIVE_SESSIONS = _int_env(
        "ADMIN_MAX_ACTIVE_SESSIONS",
        default="1",
        minimum=1,
        maximum=1,
    )
    _validate_active_session_limit_config(
        customer_limit=CUSTOMER_MAX_ACTIVE_SESSIONS,
        admin_limit=ADMIN_MAX_ACTIVE_SESSIONS,
    )
    PENDING_MFA_MAX_AGE_SECONDS = int(os.getenv("PENDING_MFA_MAX_AGE_SECONDS", "300"))
    if PENDING_MFA_MAX_AGE_SECONDS < 60 or PENDING_MFA_MAX_AGE_SECONDS > SESSION_INACTIVITY_SECONDS:
        raise RuntimeError("PENDING_MFA_MAX_AGE_SECONDS must be between 60 and SESSION_INACTIVITY_SECONDS")
    CUSTOMER_PENDING_MFA_MAX_AGE_SECONDS = PENDING_MFA_MAX_AGE_SECONDS
    ADMIN_SESSION_INACTIVITY_SECONDS = _int_env(
        "ADMIN_SESSION_INACTIVITY_SECONDS",
        default="300",
        minimum=60,
        maximum=60 * 60,
    )
    ADMIN_PENDING_MFA_MAX_AGE_SECONDS = _int_env(
        "ADMIN_PENDING_MFA_MAX_AGE_SECONDS",
        default="60",
        minimum=60,
        maximum=ADMIN_SESSION_INACTIVITY_SECONDS,
    )
    CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS = _int_env(
        "CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS",
        default=str(DEFAULT_CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS),
        minimum=1,
        maximum=MAX_SESSION_ABSOLUTE_LIFETIME_SECONDS,
    )
    ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS = _int_env(
        "ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS",
        default=str(DEFAULT_ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS),
        minimum=1,
        maximum=MAX_SESSION_ABSOLUTE_LIFETIME_SECONDS,
    )
    SESSION_ABSOLUTE_LIFETIME_SECONDS = CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS
    _validate_session_absolute_lifetime_config(
        customer_lifetime_seconds=CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS,
        admin_lifetime_seconds=ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS,
        customer_pending_mfa_seconds=CUSTOMER_PENDING_MFA_MAX_AGE_SECONDS,
        admin_pending_mfa_seconds=ADMIN_PENDING_MFA_MAX_AGE_SECONDS,
    )

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

    RATELIMIT_STORAGE_URI = MEMORY_RATE_LIMIT_STORAGE
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
        "default-src": CSP_SELF,
        "base-uri": CSP_SELF,
        "object-src": CSP_NONE,
        "frame-ancestors": CSP_NONE,
        "form-action": CSP_SELF,
        "img-src": [CSP_SELF, "data:"],
        "script-src": CSP_SELF,
        "script-src-attr": CSP_NONE,
        "style-src": CSP_SELF,
        "style-src-attr": CSP_NONE,
        "connect-src": CSP_SELF,
        "font-src": CSP_SELF,
        "manifest-src": CSP_SELF,
        "frame-src": [CSP_SELF, TURNSTILE_ORIGIN],
    }
    TALISMAN_CONTENT_SECURITY_POLICY["script-src"] = [CSP_SELF, TURNSTILE_ORIGIN]

    TRUSTED_PROXY_COUNT = int(os.getenv("TRUSTED_PROXY_COUNT", "1"))
    if TRUSTED_PROXY_COUNT < 0 or TRUSTED_PROXY_COUNT > 2:
        raise RuntimeError("TRUSTED_PROXY_COUNT must be between 0 and 2")

    # 60 seconds (1 min) for testing — change to 43200 for 12h in production
    MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS = MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS
    PAYEE_COOLDOWN_SECONDS = _int_env(
        "PAYEE_COOLDOWN_SECONDS",
        default="60",
        minimum=1,
        maximum=MAX_PAYEE_COOLDOWN_SECONDS,
    )
    _validate_payee_cooldown_config(
        app_env=APP_ENV,
        cooldown_seconds=PAYEE_COOLDOWN_SECONDS,
        min_production_seconds=MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS,
    )

    ADMIN_ALLOWED_EMAIL_DOMAINS = _csv_domain_set(
        "ADMIN_ALLOWED_EMAIL_DOMAINS",
        default=os.getenv(
            "SIT_WORKPLACE_EMAIL_DOMAINS",
            "sit.singaporetech.edu.sg,singaporetech.edu.sg",
        ),
    )
    SIT_WORKPLACE_EMAIL_DOMAINS = ADMIN_ALLOWED_EMAIL_DOMAINS
    STAFF_INVITE_ALIAS_SEPARATORS = tuple(
        item
        for item in os.getenv("STAFF_INVITE_ALIAS_SEPARATORS", "+").split(",")
        if item
    )
    CUSTOMER_EMAIL_PLUS_ALIAS_DOMAINS = _csv_public_domain_set(
        "CUSTOMER_EMAIL_PLUS_ALIAS_DOMAINS",
        default="gmail.com,googlemail.com",
    )
    CUSTOMER_EMAIL_DOT_INSENSITIVE_DOMAINS = _csv_public_domain_set(
        "CUSTOMER_EMAIL_DOT_INSENSITIVE_DOMAINS",
        default="gmail.com,googlemail.com",
    )
    CUSTOMER_TEMP_EMAIL_DOMAINS = _csv_public_domain_set(
        "CUSTOMER_TEMP_EMAIL_DOMAINS",
        default="10minutemail.com,guerrillamail.com,mailinator.com,temp-mail.org,yopmail.com",
    )
    ROOT_ADMIN_EMAILS = _root_admin_email_set(
        "ROOT_ADMIN_EMAILS",
        default=DEFAULT_ROOT_ADMIN_EMAILS_CSV,
        allowed_domains=ADMIN_ALLOWED_EMAIL_DOMAINS,
        app_env=APP_ENV,
        deployment_target=DEPLOYMENT_TARGET,
    )
    STAFF_INVITE_TTL_SECONDS = _int_env(
        "STAFF_INVITE_TTL_SECONDS",
        default=str(24 * 60 * 60),
        minimum=15 * 60,
        maximum=48 * 60 * 60,
    )
    STAFF_WORKPLACE_VERIFICATION_TTL_SECONDS = _int_env(
        "STAFF_WORKPLACE_VERIFICATION_TTL_SECONDS",
        default="900",
        minimum=300,
        maximum=3600,
    )
    TURNSTILE_ENABLED = _optional_bool("TURNSTILE_ENABLED", default=False)
    TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY", "").strip()
    TURNSTILE_SECRET_KEY = _optional_turnstile_secret()
    TURNSTILE_VERIFY_URL = _validate_turnstile_verify_url(
        app_env=APP_ENV,
        deployment_target=DEPLOYMENT_TARGET,
        verify_url=os.getenv("TURNSTILE_VERIFY_URL", OFFICIAL_TURNSTILE_VERIFY_URL),
    )
    TURNSTILE_CUSTOMER_LOGIN_ENABLED = _optional_bool("TURNSTILE_CUSTOMER_LOGIN_ENABLED", default=False)
    TURNSTILE_CUSTOMER_REGISTER_OTP_ENABLED = _optional_bool(
        "TURNSTILE_CUSTOMER_REGISTER_OTP_ENABLED",
        default=False,
    )
    TURNSTILE_CUSTOMER_REGISTER_ENABLED = _optional_bool("TURNSTILE_CUSTOMER_REGISTER_ENABLED", default=False)
    TURNSTILE_CUSTOMER_PASSWORD_RESET_ENABLED = _optional_bool(
        "TURNSTILE_CUSTOMER_PASSWORD_RESET_ENABLED",
        default=False,
    )
    TURNSTILE_CUSTOMER_MANUAL_RECOVERY_ENABLED = _optional_bool(
        "TURNSTILE_CUSTOMER_MANUAL_RECOVERY_ENABLED",
        default=False,
    )
    TURNSTILE_ADMIN_LOGIN_ENABLED = _optional_bool("TURNSTILE_ADMIN_LOGIN_ENABLED", default=False)
    TURNSTILE_ADMIN_INVITE_ACCEPT_ENABLED = _optional_bool(
        "TURNSTILE_ADMIN_INVITE_ACCEPT_ENABLED",
        default=True,
    )
    TURNSTILE_FAIL_CLOSED_IN_PRODUCTION = _optional_bool(
        "TURNSTILE_FAIL_CLOSED_IN_PRODUCTION",
        default=True,
    )
    PROFILE_EMAIL_CHANGE_TTL_SECONDS = _int_env(
        "PROFILE_EMAIL_CHANGE_TTL_SECONDS",
        default="300",
        minimum=60,
        maximum=900,
    )


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
