from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from flask import Flask
from sqlalchemy import text

from app.extensions import db
from app.models import (
    AuthAttemptCounter,
    PasswordResetToken,
    PasswordResetTransaction,
    SecurityAlertDedupe,
    SecurityAuditEvent,
    SecurityCircuitBreaker,
    ServerSideSession,
    StaffInvite,
    TotpReplayRecord,
)
from app.security.alerts import validate_security_alert_config
from app.security.audit import validate_audit_integrity_config
from app.security.passwords import (
    validate_common_password_dictionary,
    validate_password_hash_config,
)
from app.security.session_hmac import (
    SESSION_PAYLOAD_FORMAT_VERSION,
    validate_session_hmac_config,
)
from config import (
    MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS,
    _validate_payee_cooldown_config,
    _validate_session_absolute_lifetime_config,
)


@dataclass
class ProductionReadinessResult:
    """Sanitized result of validating production security prerequisites."""

    failures: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return not self.failures


class ProductionStartupSecurityError(RuntimeError):
    """Raised only when a production WSGI process is unsafe to start."""


def is_production_app(app: Flask) -> bool:
    return str(app.config.get("APP_ENV") or "").strip().casefold() == "production"


def validate_production_security_prerequisites(
    app: Flask,
    *,
    app_mode: str,
) -> ProductionReadinessResult:
    """Validate production policy without exposing configured secret values.

    This deliberately uses the already-loaded Flask configuration.  A restarted
    process therefore validates its freshly loaded secret files and runtime role,
    while readiness revalidates database-backed dependencies after startup.
    """

    result = ProductionReadinessResult()
    requested_mode = str(app_mode or "").strip().casefold()

    with app.app_context():
        _validate_mode_and_route_isolation(app, requested_mode, result)
        _validate_database_connectivity_and_tables(app, requested_mode, result)
        _validate_password_policy(app, result)
        _validate_session_policy(app, requested_mode, result)
        _validate_mfa_policy(app, result)
        _validate_alert_and_audit_policy(app, result)
        _validate_edge_policy(app, result)
        _validate_lifetime_policy(app, result)
        _validate_runtime_database_privileges(app, result)

    return result


def enforce_production_startup_guard(app: Flask, *, app_mode: str) -> None:
    """Fail closed when an actual production WSGI process lacks prerequisites."""

    if not is_production_app(app):
        return

    result = validate_production_security_prerequisites(app, app_mode=app_mode)
    if result.ready:
        return

    failures = "; ".join(result.failures)
    app.logger.critical(
        "Production startup security guard failed: %s. Run flask production-check for details.",
        failures,
    )
    raise ProductionStartupSecurityError(
        "Production startup security guard failed: "
        f"{failures}. Run flask production-check for details."
    )


def log_production_readiness_failure(app: Flask, result: ProductionReadinessResult) -> None:
    """Log only the validator's sanitized labels for production operators."""

    app.logger.error(
        "Production readiness security guard failed: %s",
        "; ".join(result.failures),
    )


def _validate_mode_and_route_isolation(
    app: Flask,
    requested_mode: str,
    result: ProductionReadinessResult,
) -> None:
    configured_mode = str(app.config.get("APP_MODE") or "").strip().casefold()
    if requested_mode not in {"customer", "admin"}:
        result.failures.append("Runtime app mode is invalid")
        return
    if configured_mode != requested_mode:
        result.failures.append("APP_MODE does not match the runtime app mode")

    endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
    if requested_mode == "admin":
        if app.config.get("ADMIN_AUTH_ENABLED") is not True:
            result.failures.append("Admin authentication must be enabled")
        if app.config.get("SESSION_COOKIE_NAME") != "__Host-sitbank_admin_session":
            result.failures.append("Admin session cookie name must be isolated")
        if not str(app.config.get("SESSION_KEY_PREFIX") or "").startswith("admin-"):
            result.failures.append("Admin session key prefix must be isolated")
        if not str(app.config.get("AUTH_FAILURE_KEY_PREFIX") or "").startswith("ospbank:admin:"):
            result.failures.append("Admin auth security-state prefix must be isolated")
        if not str(app.config.get("RATELIMIT_KEY_PREFIX") or "").startswith("ospbank:admin:"):
            result.failures.append("Admin rate-limit key prefix must be isolated")
        root_admin_emails = app.config.get("ROOT_ADMIN_EMAILS") or set()
        if not isinstance(root_admin_emails, (set, frozenset, list, tuple)) or len(root_admin_emails) != 7:
            result.failures.append("ROOT_ADMIN_EMAILS must configure exactly 7 root administrators")
        if any(endpoint.startswith(("auth.", "web.", "banking.", "main.")) for endpoint in endpoints):
            result.failures.append("Admin runtime must not register customer routes")
    else:
        if app.config.get("ADMIN_AUTH_ENABLED") is not False:
            result.failures.append("Customer runtime must not enable admin authentication")
        if app.config.get("SESSION_COOKIE_NAME") == "__Host-sitbank_admin_session":
            result.failures.append("Customer session cookie name must not collide with admin")
        if str(app.config.get("SESSION_KEY_PREFIX") or "").startswith("admin-"):
            result.failures.append("Customer session key prefix must not use the admin namespace")
        if any(endpoint.startswith("admin.") for endpoint in endpoints):
            result.failures.append("Customer runtime must not register admin routes")


def _validate_database_connectivity_and_tables(
    app: Flask,
    app_mode: str,
    result: ProductionReadinessResult,
) -> None:
    try:
        db.session.execute(text("SELECT 1"))
    except Exception as exc:
        _database_failure(result, "PostgreSQL connectivity check", exc)
        return

    table_checks = [
        (ServerSideSession, "server_side_sessions table"),
        (AuthAttemptCounter, "auth_attempt_counters table"),
        (TotpReplayRecord, "totp_replay_records table"),
        (PasswordResetToken, "password_reset_tokens table"),
        (PasswordResetTransaction, "password_reset_transactions table"),
        (SecurityAlertDedupe, "security_alert_dedupe table"),
        (SecurityCircuitBreaker, "security_circuit_breakers table"),
        (SecurityAuditEvent, "security_audit_events table"),
    ]
    if app_mode == "admin":
        table_checks.append((StaffInvite, "staff_invites table"))

    for model, label in table_checks:
        try:
            db.session.execute(db.select(model.id).limit(1))
        except Exception as exc:
            _database_failure(result, f"{label} access check", exc)
            return


def _validate_password_policy(app: Flask, result: ProductionReadinessResult) -> None:
    try:
        entries = validate_common_password_dictionary()
    except Exception as exc:
        _failure(result, "Common password dictionary check", exc)
    else:
        result.details["common_password_dictionary_entries"] = entries
        if entries < 100000:
            result.failures.append("Common password dictionary must contain at least 100000 entries")

    try:
        validate_password_hash_config()
    except Exception as exc:
        _failure(result, "Password hash configuration check", exc)


def _validate_session_policy(
    app: Flask,
    app_mode: str,
    result: ProductionReadinessResult,
) -> None:
    if app.config.get("SESSION_TYPE") != "database":
        result.failures.append("SESSION_TYPE must remain database-backed")
    if SESSION_PAYLOAD_FORMAT_VERSION != 2:
        result.failures.append("Database session payload integrity format is unsupported")

    try:
        session_hmac_keys = validate_session_hmac_config()
    except Exception as exc:
        _failure(result, "Session HMAC configuration check", exc)
    else:
        result.details["session_hmac_key_count"] = session_hmac_keys

    lookup_key = app.config.get("SESSION_LOOKUP_HMAC_KEY")
    if not isinstance(lookup_key, bytes) or len(lookup_key) != 32:
        result.failures.append("SESSION_LOOKUP_HMAC_KEY must be configured as 32 bytes")

    if app.config.get("SESSION_COOKIE_SECURE") is not True:
        result.failures.append("SESSION_COOKIE_SECURE must be enabled")
    if app.config.get("SESSION_COOKIE_HTTPONLY") is not True:
        result.failures.append("SESSION_COOKIE_HTTPONLY must be enabled")
    if app.config.get("SESSION_COOKIE_SAMESITE") != "Strict":
        result.failures.append("SESSION_COOKIE_SAMESITE must be Strict")
    if app_mode == "customer" and app.config.get("SESSION_COOKIE_NAME") != "__Host-sitbank_session":
        result.failures.append("Customer session cookie name must be isolated")


def _validate_mfa_policy(app: Flask, result: ProductionReadinessResult) -> None:
    mfa_kek_keys = app.config.get("MFA_KEK_KEYS")
    mfa_kek_active_id = app.config.get("MFA_KEK_ACTIVE_ID")
    if not isinstance(mfa_kek_keys, dict) or not mfa_kek_keys:
        result.failures.append("MFA_KEK_KEYS_JSON must configure at least one MFA KEK")
    elif mfa_kek_active_id not in mfa_kek_keys:
        result.failures.append("MFA_KEK_ACTIVE_ID must identify a configured MFA KEK")
    else:
        result.details["mfa_kek_count"] = len(mfa_kek_keys)

    if _int_config(app, "TOTP_LOGIN_VALID_WINDOW") not in {0, 1}:
        result.failures.append("TOTP_LOGIN_VALID_WINDOW must be 0 or 1")
    if _int_config(app, "TOTP_HIGH_RISK_VALID_WINDOW") != 0:
        result.failures.append("TOTP_HIGH_RISK_VALID_WINDOW must be 0")
    fresh_mfa_seconds = _int_config(app, "FRESH_MFA_SECONDS")
    if fresh_mfa_seconds is None or fresh_mfa_seconds < 60 or fresh_mfa_seconds > 15 * 60:
        result.failures.append("FRESH_MFA_SECONDS must be between 60 and 900")


def _validate_alert_and_audit_policy(app: Flask, result: ProductionReadinessResult) -> None:
    try:
        alert_config = validate_security_alert_config(require_delivery=True)
    except Exception as exc:
        _failure(result, "Security alert configuration check", exc)
    else:
        result.details["security_alerting"] = {
            "enabled": bool(alert_config["enabled"]),
            "min_severity": alert_config["min_severity"],
            "dedupe_ttl_seconds": alert_config["dedupe_ttl_seconds"],
        }

    try:
        audit_key_length = validate_audit_integrity_config()
    except Exception as exc:
        _failure(result, "Audit integrity configuration check", exc)
    else:
        result.details["audit_hmac_key_length"] = audit_key_length


def _validate_edge_policy(app: Flask, result: ProductionReadinessResult) -> None:
    if _int_config(app, "PASSWORD_PBKDF2_ITERATIONS") is None or _int_config(
        app, "PASSWORD_PBKDF2_ITERATIONS"
    ) < 600000:
        result.failures.append("PASSWORD_PBKDF2_ITERATIONS must be 600000 or higher")
    if not is_production_app(app):
        result.failures.append("APP_ENV must be production")
    if app.config.get("SQLALCHEMY_MIGRATION_DATABASE_URI"):
        result.failures.append("DATABASE_MIGRATION_URL must not be configured for the runtime app")
    if len(str(app.config.get("WTF_CSRF_SECRET_KEY") or "")) < 32:
        result.failures.append("WTF_CSRF_SECRET_KEY must be at least 32 characters")
    if _int_config(app, "TRUSTED_PROXY_COUNT") != 1:
        result.failures.append("TRUSTED_PROXY_COUNT must be 1 for the single Nginx proxy boundary")
    if app.config.get("WTF_CSRF_ENABLED") is not True:
        result.failures.append("WTF_CSRF_ENABLED must be enabled")
    if app.config.get("WTF_CSRF_CHECK_DEFAULT") is not True:
        result.failures.append("WTF_CSRF_CHECK_DEFAULT must be enabled")
    if app.config.get("TALISMAN_FORCE_HTTPS") is not True:
        result.failures.append("TALISMAN_FORCE_HTTPS must be enabled")
    if not str(app.config.get("RATELIMIT_STORAGE_URI") or "").startswith("memory://"):
        result.failures.append(
            "Flask-Limiter storage must remain non-authoritative; DB-backed auth counters enforce security limits"
        )


def _validate_lifetime_policy(app: Flask, result: ProductionReadinessResult) -> None:
    try:
        _validate_payee_cooldown_config(
            app_env=str(app.config.get("APP_ENV") or ""),
            cooldown_seconds=app.config.get("PAYEE_COOLDOWN_SECONDS"),
            min_production_seconds=app.config.get(
                "MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS",
                MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS,
            ),
        )
    except Exception as exc:
        # This validator only emits fixed configuration names and integer bounds.
        result.failures.append(f"Payee cooldown configuration check failed: {exc}")

    try:
        _validate_session_absolute_lifetime_config(
            customer_lifetime_seconds=app.config.get("CUSTOMER_SESSION_ABSOLUTE_LIFETIME_SECONDS"),
            admin_lifetime_seconds=app.config.get("ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS"),
            customer_pending_mfa_seconds=app.config.get("CUSTOMER_PENDING_MFA_MAX_AGE_SECONDS"),
            admin_pending_mfa_seconds=app.config.get("ADMIN_PENDING_MFA_MAX_AGE_SECONDS"),
        )
    except Exception as exc:
        # This validator only emits fixed configuration names and integer bounds.
        result.failures.append(f"Session absolute lifetime configuration check failed: {exc}")


def _validate_runtime_database_privileges(app: Flask, result: ProductionReadinessResult) -> None:
    """Check stable runtime-role properties without needing the migration role.

    The deploy-time verifier still performs destructive privilege probes with the
    migration role.  Runtime only verifies that its own PostgreSQL connection
    cannot create schema objects or own public-schema objects.
    """

    if app.testing:
        return
    if db.engine.dialect.name != "postgresql":
        result.failures.append("Runtime database must use PostgreSQL")
        return
    try:
        privileges = db.session.execute(
            text(
                """
                SELECT
                    has_database_privilege(current_database(), 'CREATE') AS database_create,
                    has_schema_privilege(current_user, 'public', 'CREATE') AS schema_create,
                    EXISTS (
                        SELECT 1
                        FROM pg_class AS class
                        JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
                        JOIN pg_roles AS role ON role.oid = class.relowner
                        WHERE namespace.nspname = 'public'
                          AND role.rolname = current_user
                          AND class.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
                    ) AS owns_schema_object,
                    has_table_privilege('public.security_audit_events', 'UPDATE') AS audit_update,
                    has_table_privilege('public.security_audit_events', 'DELETE') AS audit_delete,
                    has_table_privilege('public.security_audit_events', 'TRUNCATE') AS audit_truncate
                """
            )
        ).mappings().one()
    except Exception as exc:
        _database_failure(result, "Runtime database privilege check", exc)
        return

    if privileges["database_create"] or privileges["schema_create"] or privileges["owns_schema_object"]:
        result.failures.append("Runtime DB role must not be able to mutate schema objects")
    if privileges["audit_update"] or privileges["audit_delete"] or privileges["audit_truncate"]:
        result.failures.append("Runtime DB role must not mutate security audit events")


def _int_config(app: Flask, key: str) -> int | None:
    try:
        return int(app.config.get(key))
    except (TypeError, ValueError):
        return None


def _failure(result: ProductionReadinessResult, label: str, exc: Exception) -> None:
    result.failures.append(f"{label} failed ({type(exc).__name__})")


def _database_failure(result: ProductionReadinessResult, label: str, exc: Exception) -> None:
    _failure(result, label, exc)
    try:
        db.session.rollback()
    except Exception:
        pass
