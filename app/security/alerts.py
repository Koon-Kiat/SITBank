from __future__ import annotations

import json
import os
import re
import urllib.request
from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from flask import current_app, has_app_context

from app.extensions import db
from app.models import SecurityAlertDedupe, SecurityAuditEvent, User
from app.security.sensitive_values import contains_sensitive_url
from app.security.session_hmac import active_hmac_hex


IMMEDIATE_ALERT_EVENT_TYPES = {
    "security_audit_write_failed": "security_audit_write_failed",
    "account_lock": "account_lock",
    "webauthn_clone_detected": "webauthn_clone_detected",
    "audit_chain_verification_failed": "audit_chain_verification_failed",
    "audit_anchor_mismatch": "audit_anchor_mismatch",
    "audit_append_only_protection_failed": "audit_append_only_protection_failed",
    "runtime_db_privilege_verification_failed": "runtime_db_privilege_verification_failed",
    "password_reset_token_reused": "password_reset_token_reused",
    "password_reset_webauthn_failed": "password_reset_webauthn_failed",
    "manual_recovery_requested": "manual_recovery_requested",
}
TRANSACTION_EVENT_TYPES = {
    "banking_outbound_transfer",
    "banking_scheduled_transfer_execution",
    "banking_transaction_authorization",
    "webauthn_transaction_stage",
    "webauthn_transaction_options",
    "webauthn_transaction_verify",
}
PASSWORD_RESET_EVENT_TYPES = {
    "password_reset_requested",
    "password_reset_failed",
    "password_reset_mfa_failed",
    "password_reset_webauthn_failed",
    "password_reset_token_reused",
    "manual_recovery_requested",
}
ALERT_SEVERITY_RANK = {"low": 10, "medium": 20, "high": 30, "critical": 40}
DEFAULT_ALERT_TIMEOUT_SECONDS = 5.0
DEFAULT_ALERT_DEDUPE_TTL_SECONDS = 300
DISCORD_EMBED_FIELD_LIMIT = 10
ALERT_USER_AGENT = "SITBank-SecurityAlerts/1.0"
DISCORD_DISPLAY_TIMEZONE = timezone(timedelta(hours=8))
DISCORD_DISPLAY_TIMEZONE_LABEL = "UTC+8"
DELIVERY_SAFE_KEYS = {
    "alert_type",
    "anchor_error_count",
    "correlation_id",
    "count",
    "display_timestamp",
    "event_count",
    "event_id",
    "event_type",
    "generated_at",
    "latest_event_id",
    "message",
    "outcome",
    "public_session_ref",
    "safe_user_id",
    "safe_user_identifier",
    "session_ref",
    "severity",
    "source",
    "summary",
    "table",
    "timestamp",
    "user_id",
    "user_ref",
    "window_seconds",
    "current_count",
    "current_max_id",
    "previous_count",
    "previous_max_id",
}
DATABASE_INTEGRITY_TABLES = {
    "security_audit_events": SecurityAuditEvent,
    "users": User,
}
DATABASE_INTEGRITY_STATE_VERSION = 1
DELIVERY_SENSITIVE_KEY_PARTS = (
    "access_token",
    "api_key",
    "apikey",
    "assertion",
    "authenticator_data",
    "authorization",
    "bearer",
    "challenge",
    "client_data",
    "cookie",
    "credential",
    "csrf",
    "database_url",
    "hmac",
    "kek",
    "mfa_secret",
    "passwd",
    "password",
    "postgres_url",
    "postgresql_url",
    "private_key",
    "redis_url",
    "refresh_token",
    "recovery_code",
    "secret",
    "session",
    "session_id",
    "sid",
    "signature",
    "smtp_password",
    "smtp_url",
    "smtp_username",
    "set_cookie",
    "set-cookie",
    "token",
    "totp",
    "webhook",
)
DELIVERY_PRIVATE_KEY_RE = re.compile(
    r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY",
    re.IGNORECASE,
)
DELIVERY_LONG_TOKEN_RE = re.compile(r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_+/=-]{40,}")
UUID_TEXT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class AlertConfigurationError(RuntimeError):
    pass


REDACTED_VALUE = "[redacted]"


def evaluate_security_alerts(*, now: datetime | None = None) -> list[dict[str, Any]]:
    current_time = _as_utc(now or datetime.now(timezone.utc))
    longest_window = timedelta(minutes=15)
    events = _recent_events(current_time - longest_window)
    alerts: list[dict[str, Any]] = []

    _add_immediate_alerts(alerts, events, current_time=current_time)
    _add_login_failure_alerts(alerts, events, current_time=current_time)
    _add_auth_backoff_alerts(alerts, events, current_time=current_time)
    _add_password_reset_alerts(alerts, events, current_time=current_time)
    _add_transaction_failure_alerts(alerts, events, current_time=current_time)

    return sorted(alerts, key=lambda item: (item["alert_type"], str(item.get("source", ""))))


def build_security_alert_report(
    *,
    deliver: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    current_time = _as_utc(now or datetime.now(timezone.utc))
    alert_config = validate_security_alert_config()
    audit_chain_alerts, audit_chain_status = _audit_chain_verification_alerts(
        current_time=current_time
    )
    database_integrity_alerts, database_integrity_status = _database_integrity_alerts(
        current_time=current_time,
        update_state=deliver,
    )
    alerts = sorted(
        _filter_alerts_by_min_severity(
            [
                *evaluate_security_alerts(now=current_time),
                *audit_chain_alerts,
                *database_integrity_alerts,
            ],
            alert_config["min_severity"],
        ),
        key=lambda item: (item["alert_type"], str(item.get("source", ""))),
    )
    delivery = {
        "attempted": False,
        "configured": alert_config["webhook_configured"],
        "enabled": alert_config["enabled"],
    }
    dedupe = {
        "enabled": False,
        "ttl_seconds": alert_config["dedupe_ttl_seconds"],
        "suppressed": 0,
    }
    deliverable_alerts = alerts
    if deliver and alerts and alert_config["enabled"]:
        try:
            deliverable_alerts, dedupe = _dedupe_alerts(
                alerts,
                ttl_seconds=alert_config["dedupe_ttl_seconds"],
            )
        except AlertConfigurationError as exc:
            delivery = {
                "attempted": False,
                "configured": True,
                "enabled": True,
                "delivered": False,
                "error_type": _safe_text(type(exc).__name__, 80),
            }
        else:
            if deliverable_alerts:
                delivery = deliver_security_alerts(
                    deliverable_alerts,
                    timeout_seconds=alert_config["timeout_seconds"],
                )
                delivery["enabled"] = True
            else:
                delivery = {
                    "attempted": False,
                    "configured": alert_config["webhook_configured"],
                    "enabled": True,
                    "delivered": True,
                    "deduped": True,
                }
    return {
        "message": "security_alert_report",
        "generated_at": _utc_iso(current_time),
        "alert_count": len(alerts),
        "deliverable_alert_count": len(deliverable_alerts),
        "alerts": alerts,
        "audit_chain": audit_chain_status,
        "database_integrity": database_integrity_status,
        "dedupe": dedupe,
        "delivery": delivery,
    }


def deliver_security_alerts(
    alerts: list[dict[str, Any]],
    *,
    webhook_url: str | None = None,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    if not alerts:
        return {"attempted": False, "configured": False}

    try:
        url = webhook_url if webhook_url is not None else configured_alert_webhook_url()
    except AlertConfigurationError as exc:
        return {
            "attempted": False,
            "configured": True,
            "delivered": False,
            "error_type": _safe_text(type(exc).__name__, 80),
        }
    if not url:
        return {"attempted": False, "configured": False}
    try:
        url = _validated_webhook_url(url)
    except AlertConfigurationError as exc:
        return {
            "attempted": False,
            "configured": True,
            "delivered": False,
            "error_type": _safe_text(type(exc).__name__, 80),
        }

    provider = _webhook_provider(url)
    body = _alert_webhook_body(alerts, provider=provider)
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": ALERT_USER_AGENT,
        },
        method="POST",
    )
    if timeout_seconds is None:
        timeout_seconds = _configured_alert_timeout_seconds()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # nosec B310
            status_code = int(getattr(response, "status", 0) or response.getcode())
    except Exception as exc:
        return {
            "attempted": True,
            "configured": True,
            "delivered": False,
            "error_type": _safe_text(type(exc).__name__, 80),
            "provider": provider,
        }

    return {
        "attempted": True,
        "configured": True,
        "delivered": 200 <= status_code < 300,
        "provider": provider,
        "status_code": status_code,
    }


def validate_security_alert_config(
    *,
    require_delivery: bool = False,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    enabled = _configured_alert_enabled(environ)
    min_severity = _configured_alert_min_severity(environ)
    timeout_seconds = _configured_alert_timeout_seconds(environ)
    dedupe_ttl_seconds = _configured_alert_dedupe_ttl_seconds(environ)
    webhook_url = configured_alert_webhook_url(environ)

    if require_delivery and not enabled:
        raise AlertConfigurationError("SECURITY_ALERT_ENABLED must be true in production")
    if enabled or require_delivery:
        if not webhook_url:
            raise AlertConfigurationError("SECURITY_ALERT_WEBHOOK_URL_FILE is required when security alerting is enabled")
        _validated_webhook_url(webhook_url)

    return {
        "enabled": enabled,
        "webhook_configured": bool(webhook_url),
        "min_severity": min_severity,
        "timeout_seconds": timeout_seconds,
        "dedupe_ttl_seconds": dedupe_ttl_seconds,
    }


def configured_alert_webhook_url(environ: Mapping[str, str] | None = None) -> str | None:
    if environ is None and has_app_context():
        configured_url = current_app.config.get("SECURITY_ALERT_WEBHOOK_URL")
        if configured_url:
            return _safe_secret_text(str(configured_url))
        file_path = str(current_app.config.get("SECURITY_ALERT_WEBHOOK_URL_FILE") or "").strip()
        if file_path:
            return _read_webhook_url_file(file_path)
        return None

    source = environ or os.environ
    file_path = str(source.get("SECURITY_ALERT_WEBHOOK_URL_FILE") or "").strip()
    if file_path and str(source.get("SECURITY_ALERT_WEBHOOK_URL") or "").strip():
        raise AlertConfigurationError(
            "Configure either SECURITY_ALERT_WEBHOOK_URL or SECURITY_ALERT_WEBHOOK_URL_FILE, not both"
        )
    if file_path:
        return _read_webhook_url_file(file_path)
    return _safe_secret_text(str(source.get("SECURITY_ALERT_WEBHOOK_URL") or ""))


def _configured_alert_enabled(environ: Mapping[str, str] | None = None) -> bool:
    if environ is None and has_app_context():
        return bool(current_app.config.get("SECURITY_ALERT_ENABLED", False))
    source = environ or os.environ
    raw_value = str(source.get("SECURITY_ALERT_ENABLED") or "").strip()
    if not raw_value:
        return str(source.get("APP_ENV") or "").strip().casefold() == "production"
    normalized = raw_value.casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise AlertConfigurationError("SECURITY_ALERT_ENABLED must be a boolean value")


def _configured_alert_min_severity(environ: Mapping[str, str] | None = None) -> str:
    if environ is None and has_app_context():
        value = str(current_app.config.get("SECURITY_ALERT_MIN_SEVERITY", "high")).strip().casefold()
    else:
        source = environ or os.environ
        value = str(source.get("SECURITY_ALERT_MIN_SEVERITY") or "high").strip().casefold()
    if value not in ALERT_SEVERITY_RANK:
        raise AlertConfigurationError("SECURITY_ALERT_MIN_SEVERITY is invalid")
    return value


def _configured_alert_timeout_seconds(environ: Mapping[str, str] | None = None) -> float:
    if environ is None and has_app_context():
        raw_value = current_app.config.get("SECURITY_ALERT_TIMEOUT_SECONDS", DEFAULT_ALERT_TIMEOUT_SECONDS)
    else:
        source = environ or os.environ
        raw_value = source.get("SECURITY_ALERT_TIMEOUT_SECONDS") or str(DEFAULT_ALERT_TIMEOUT_SECONDS)
    try:
        value = float(raw_value)
    except (TypeError, ValueError) as exc:
        raise AlertConfigurationError("SECURITY_ALERT_TIMEOUT_SECONDS must be numeric") from exc
    if value < 1.0 or value > 30.0:
        raise AlertConfigurationError("SECURITY_ALERT_TIMEOUT_SECONDS must be between 1 and 30")
    return value


def _configured_alert_dedupe_ttl_seconds(environ: Mapping[str, str] | None = None) -> int:
    if environ is None and has_app_context():
        raw_value = current_app.config.get("SECURITY_ALERT_DEDUPE_TTL_SECONDS", DEFAULT_ALERT_DEDUPE_TTL_SECONDS)
    else:
        source = environ or os.environ
        raw_value = source.get("SECURITY_ALERT_DEDUPE_TTL_SECONDS") or str(DEFAULT_ALERT_DEDUPE_TTL_SECONDS)
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise AlertConfigurationError("SECURITY_ALERT_DEDUPE_TTL_SECONDS must be an integer") from exc
    if value < 60 or value > 86400:
        raise AlertConfigurationError("SECURITY_ALERT_DEDUPE_TTL_SECONDS must be between 60 and 86400")
    return value


def _read_webhook_url_file(file_path: str) -> str | None:
    try:
        with open(file_path, encoding="utf-8") as handle:
            return _safe_secret_text(handle.read())
    except OSError as exc:
        raise AlertConfigurationError(
            f"SECURITY_ALERT_WEBHOOK_URL_FILE is not readable: {type(exc).__name__}"
        ) from exc


def _validated_webhook_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise AlertConfigurationError("SECURITY_ALERT_WEBHOOK_URL must be an HTTPS URL")
    return url


def _webhook_provider(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").casefold()
    path = parsed.path or ""
    if host in {"discord.com", "discordapp.com"} and path.startswith("/api/webhooks/"):
        return "discord"
    return "generic"


def _audit_chain_verification_alerts(
    *,
    current_time: datetime,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from app.security.audit import verify_audit_hash_chain

    anchor_path = _configured_audit_anchor_path()
    anchor_configured = anchor_path is not None
    anchor = None
    if anchor_path is not None:
        try:
            anchor = _load_audit_anchor(anchor_path)
        except AlertConfigurationError as exc:
            return [
                _alert(
                    "audit_anchor_mismatch",
                    current_time=current_time,
                    severity="critical",
                    count=1,
                    window_seconds=0,
                    source="audit_anchor",
                    error_type=type(exc).__name__,
                    reason="anchor_unavailable",
                )
            ], {
                "checked": False,
                "valid": False,
                "anchor_configured": True,
                "anchor_validated": False,
                "error_type": type(exc).__name__,
            }

    try:
        result = verify_audit_hash_chain(anchor=anchor)
    except Exception as exc:
        return [
            _alert(
                "audit_chain_verification_failed",
                current_time=current_time,
                severity="critical",
                count=1,
                window_seconds=0,
                source="audit_hash_chain",
                error_type=type(exc).__name__,
            )
        ], {
            "checked": False,
            "valid": False,
            "anchor_configured": anchor_configured,
            "anchor_validated": None,
            "error_type": type(exc).__name__,
        }

    status = _audit_chain_status(result, anchor_configured=anchor_configured)
    if result.get("valid") is True:
        return [], status

    anchor_error_count = len(result.get("anchor_errors") or [])
    alert_type = (
        "audit_anchor_mismatch"
        if anchor_error_count
        else "audit_chain_verification_failed"
    )
    source = "audit_anchor" if anchor_error_count else "audit_hash_chain"
    return [
        _alert(
            alert_type,
            current_time=current_time,
            severity="critical",
            count=max(1, len(result.get("errors") or [])),
            window_seconds=0,
            source=source,
            latest_event_id=result.get("latest_event_id"),
            event_count=result.get("event_count"),
            anchor_error_count=anchor_error_count,
        )
    ], status


def _configured_audit_anchor_path() -> Path | None:
    if has_app_context():
        value = current_app.config.get("SECURITY_AUDIT_ANCHOR_PATH")
    else:
        value = os.environ.get("SECURITY_AUDIT_ANCHOR_PATH")
    text = str(value or "").strip()
    return Path(text) if text else None


def _configured_alert_state_path() -> Path | None:
    if has_app_context():
        value = current_app.config.get("SECURITY_ALERT_STATE_PATH")
    else:
        value = os.environ.get("SECURITY_ALERT_STATE_PATH")
    text = str(value or "").strip()
    return Path(text) if text else None


def _load_audit_anchor(anchor_path: Path) -> dict[str, Any]:
    try:
        anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AlertConfigurationError(
            f"SECURITY_AUDIT_ANCHOR_PATH is not readable: {type(exc).__name__}"
        ) from exc
    if not isinstance(anchor, dict):
        raise AlertConfigurationError("SECURITY_AUDIT_ANCHOR_PATH must contain a JSON object")
    return anchor


def _audit_chain_status(
    result: Mapping[str, Any],
    *,
    anchor_configured: bool,
) -> dict[str, Any]:
    return {
        "checked": True,
        "valid": bool(result.get("valid")),
        "anchor_configured": anchor_configured,
        "anchor_validated": result.get("anchor_validated"),
        "anchor_status": result.get("anchor_status"),
        "anchor_stale": bool(result.get("anchor_stale")),
        "anchor_event_id": result.get("anchor_event_id"),
        "events_since_anchor": result.get("events_since_anchor"),
        "anchor_refresh_required": bool(result.get("anchor_refresh_required")),
        "event_count": int(result.get("event_count") or 0),
        "latest_event_id": result.get("latest_event_id"),
        "error_count": len(result.get("errors") or []),
        "anchor_error_count": len(result.get("anchor_errors") or []),
    }


def _database_integrity_alerts(
    *,
    current_time: datetime,
    update_state: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    state_path = _configured_alert_state_path()
    if state_path is None:
        return [], {
            "checked": False,
            "configured": False,
        }

    status: dict[str, Any] = {
        "checked": False,
        "configured": True,
        "state_path_configured": True,
    }
    try:
        current_state = _database_integrity_snapshot(current_time)
        previous_state = _load_database_integrity_state(state_path)
    except AlertConfigurationError as exc:
        return [
            _alert(
                "database_integrity_state_unavailable",
                current_time=current_time,
                severity="critical",
                count=1,
                window_seconds=0,
                source="database_integrity_state",
                error_type=type(exc).__name__,
            )
        ], {
            **status,
            "error_type": type(exc).__name__,
        }
    except Exception as exc:
        return [
            _alert(
                "database_integrity_check_failed",
                current_time=current_time,
                severity="critical",
                count=1,
                window_seconds=0,
                source="database_integrity",
                error_type=type(exc).__name__,
            )
        ], {
            **status,
            "error_type": type(exc).__name__,
        }

    alerts = _database_integrity_regression_alerts(
        previous_state,
        current_state,
        current_time=current_time,
    )
    if update_state and not alerts:
        try:
            _write_database_integrity_state(state_path, current_state)
        except AlertConfigurationError as exc:
            return [
                _alert(
                    "database_integrity_state_unavailable",
                    current_time=current_time,
                    severity="critical",
                    count=1,
                    window_seconds=0,
                    source="database_integrity_state",
                    error_type=type(exc).__name__,
                )
            ], {
                **status,
                "error_type": type(exc).__name__,
            }

    return alerts, {
        "checked": True,
        "configured": True,
        "baseline_available": previous_state is not None,
        "valid": not alerts,
        "table_count": len(current_state["tables"]),
        "tables": current_state["tables"],
    }


def _database_integrity_snapshot(current_time: datetime) -> dict[str, Any]:
    tables: dict[str, dict[str, int | None]] = {}
    for table_name, model in DATABASE_INTEGRITY_TABLES.items():
        count_value, max_id = db.session.execute(
            db.select(db.func.count(model.id), db.func.max(model.id))
        ).one()
        tables[table_name] = {
            "count": int(count_value or 0),
            "max_id": int(max_id) if max_id is not None else None,
        }
    return {
        "message": "security_alert_database_integrity_state",
        "version": DATABASE_INTEGRITY_STATE_VERSION,
        "generated_at": _utc_iso(current_time),
        "tables": tables,
    }


def _load_database_integrity_state(state_path: Path) -> dict[str, Any] | None:
    try:
        raw_state = state_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError) as exc:
        raise AlertConfigurationError(
            f"SECURITY_ALERT_STATE_PATH is not readable: {type(exc).__name__}"
        ) from exc
    try:
        state = json.loads(raw_state)
    except json.JSONDecodeError as exc:
        raise AlertConfigurationError("SECURITY_ALERT_STATE_PATH must contain JSON") from exc
    if not isinstance(state, dict):
        raise AlertConfigurationError("SECURITY_ALERT_STATE_PATH must contain a JSON object")
    tables = state.get("tables")
    if not isinstance(tables, dict):
        raise AlertConfigurationError("SECURITY_ALERT_STATE_PATH is missing table metrics")
    return state


def _write_database_integrity_state(state_path: Path, state: Mapping[str, Any]) -> None:
    parent = state_path.parent
    if not parent:
        raise AlertConfigurationError("SECURITY_ALERT_STATE_PATH must include a parent directory")
    try:
        parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        temporary_path = state_path.with_name(f".{state_path.name}.tmp")
        temporary_path.write_text(
            json.dumps(state, separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary_path.replace(state_path)
    except OSError as exc:
        raise AlertConfigurationError(
            f"SECURITY_ALERT_STATE_PATH is not writable: {type(exc).__name__}"
        ) from exc


def _database_integrity_regression_alerts(
    previous_state: Mapping[str, Any] | None,
    current_state: Mapping[str, Any],
    *,
    current_time: datetime,
) -> list[dict[str, Any]]:
    if previous_state is None:
        return []
    previous_tables = previous_state.get("tables")
    current_tables = current_state.get("tables")
    if not isinstance(previous_tables, Mapping) or not isinstance(current_tables, Mapping):
        raise AlertConfigurationError("database integrity state is malformed")

    alerts: list[dict[str, Any]] = []
    for table_name in DATABASE_INTEGRITY_TABLES:
        previous_metrics = previous_tables.get(table_name)
        current_metrics = current_tables.get(table_name)
        if not isinstance(previous_metrics, Mapping) or not isinstance(current_metrics, Mapping):
            continue
        previous_count = _state_int(previous_metrics.get("count"))
        current_count = _state_int(current_metrics.get("count"))
        previous_max_id = _state_optional_int(previous_metrics.get("max_id"))
        current_max_id = _state_optional_int(current_metrics.get("max_id"))
        count_regressed = previous_count > 0 and current_count < previous_count
        id_regressed = (
            previous_max_id is not None
            and previous_max_id > 0
            and (current_max_id is None or current_max_id < previous_max_id)
        )
        if not count_regressed and not id_regressed:
            continue
        alerts.append(
            _alert(
                "database_table_regression",
                current_time=current_time,
                severity="critical",
                count=1,
                window_seconds=0,
                source=f"table:{table_name}",
                table=table_name,
                previous_count=previous_count,
                current_count=current_count,
                previous_max_id=previous_max_id or 0,
                current_max_id=current_max_id or 0,
                reason="row_count_or_identity_rewind",
            )
        )
    return alerts


def _state_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _state_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _alert_webhook_body(alerts: list[dict[str, Any]], *, provider: str) -> bytes:
    generated_at = _utc_iso(datetime.now(timezone.utc))
    safe_alerts = [_sanitize_alert_for_delivery(alert) for alert in alerts]
    if provider == "discord":
        payload = _discord_alert_payload(safe_alerts, generated_at=generated_at)
    else:
        payload = {
            "message": "security_alerts",
            "generated_at": generated_at,
            "alerts": safe_alerts,
        }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sanitize_alert_for_delivery(alert: Mapping[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in alert.items():
        key_text = _safe_text(key, 80) or "field"
        key_lower = key_text.casefold()
        if _is_sensitive_delivery_key(key_lower):
            clean[key_text] = REDACTED_VALUE
            continue
        clean[key_text] = _sanitize_delivery_value(value, key_lower, depth=0)
    return clean


def _sanitize_delivery_value(value: Any, key_lower: str, *, depth: int) -> Any:
    if isinstance(value, bool | int | float) or value is None:
        return value
    if depth < 4 and isinstance(value, Mapping):
        nested: dict[str, Any] = {}
        for nested_key, nested_value in list(value.items())[:25]:
            nested_key_text = _safe_text(nested_key, 80) or "field"
            nested_key_lower = nested_key_text.casefold()
            nested[nested_key_text] = (
                REDACTED_VALUE
                if _is_sensitive_delivery_key(nested_key_lower)
                else _sanitize_delivery_value(nested_value, nested_key_lower, depth=depth + 1)
            )
        return nested
    if depth < 4 and isinstance(value, list | tuple):
        return [
            _sanitize_delivery_value(item, key_lower, depth=depth + 1)
            for item in list(value)[:25]
        ]

    raw_text = str(value)
    if contains_sensitive_url(raw_text):
        return REDACTED_VALUE
    text = _safe_text(raw_text, 512)
    if _looks_like_sensitive_delivery_value(text):
        return REDACTED_VALUE
    return text


def _is_sensitive_delivery_key(key_lower: str) -> bool:
    normalized = key_lower.replace("-", "_")
    if normalized in DELIVERY_SAFE_KEYS:
        return False
    return any(part in normalized for part in DELIVERY_SENSITIVE_KEY_PARTS)


def _looks_like_sensitive_delivery_value(text: str) -> bool:
    if not text:
        return False
    lowered = text.casefold()
    if lowered == REDACTED_VALUE:
        return True
    if lowered.startswith(("bearer ", "basic ", "token ")):
        return True
    if DELIVERY_PRIVATE_KEY_RE.search(text):
        return True
    if UUID_TEXT_RE.fullmatch(text.strip()):
        return False
    return bool(DELIVERY_LONG_TOKEN_RE.fullmatch(text.strip()))


def _discord_alert_payload(alerts: list[dict[str, Any]], *, generated_at: str) -> dict[str, Any]:
    displayed_alerts = alerts[:DISCORD_EMBED_FIELD_LIMIT]
    omitted = len(alerts) - len(displayed_alerts)
    embed = {
        "title": "SITBank Security Alerts",
        "description": _discord_alert_summary(alerts, generated_at=generated_at),
        "color": _discord_embed_color(alerts),
        "timestamp": generated_at,
        "fields": [_discord_alert_field(alert) for alert in displayed_alerts],
        "footer": {"text": "Audit monitoring"},
    }
    if omitted > 0:
        embed["fields"].append(
            {
                "name": "Additional alerts",
                "value": f"{omitted} more alert(s) omitted from this Discord summary.",
                "inline": False,
            }
        )
    return {
        "content": f"SITBank security alerts: {len(alerts)} active",
        "embeds": [embed],
        "allowed_mentions": {"parse": []},
    }


def _discord_alert_summary(alerts: list[dict[str, Any]], *, generated_at: str) -> str:
    timestamp = _parse_utc_iso(generated_at).astimezone(DISCORD_DISPLAY_TIMEZONE)
    date_text = timestamp.strftime("%Y-%m-%d")
    time_text = timestamp.strftime("%H:%M:%S.%f")
    return (
        f"{len(alerts)} active alert(s).\n"
        f"Date: {date_text}\n"
        f"Time: {time_text}\n"
        f"Timezone: {DISCORD_DISPLAY_TIMEZONE_LABEL}"
    )


def _discord_embed_color(alerts: list[dict[str, Any]]) -> int:
    highest = max(
        (
            ALERT_SEVERITY_RANK.get(str(alert.get("severity", "low")).casefold(), 0)
            for alert in alerts
        ),
        default=0,
    )
    if highest >= ALERT_SEVERITY_RANK["critical"]:
        return 0xD92D20
    if highest >= ALERT_SEVERITY_RANK["high"]:
        return 0xDC6803
    if highest >= ALERT_SEVERITY_RANK["medium"]:
        return 0xF79009
    return 0x1570EF


def _discord_alert_field(alert: Mapping[str, Any]) -> dict[str, Any]:
    severity = _safe_text(alert.get("severity"), 24).upper() or "UNKNOWN"
    alert_type = _safe_text(alert.get("alert_type"), 80) or "security_alert"
    source = _safe_text(alert.get("source"), 160) or "unknown"
    count = _safe_text(alert.get("count"), 12) or "1"
    window = _format_window_seconds(alert.get("window_seconds"))
    return {
        "name": f"{severity} | {alert_type}"[:256],
        "value": (
            f"Source: {source}\n"
            f"Count: {count}\n"
            f"Window: {window}"
        )[:1024],
        "inline": False,
    }


def _format_window_seconds(value: Any) -> str:
    try:
        seconds = int(value or 0)
    except (TypeError, ValueError):
        seconds = 0
    if seconds <= 0:
        return "immediate"
    if seconds % 60 == 0:
        minutes = seconds // 60
        return f"{minutes} minute(s)"
    return f"{seconds} second(s)"


def _filter_alerts_by_min_severity(alerts: list[dict[str, Any]], min_severity: str) -> list[dict[str, Any]]:
    minimum = ALERT_SEVERITY_RANK[min_severity]
    return [
        alert
        for alert in alerts
        if ALERT_SEVERITY_RANK.get(str(alert.get("severity", "low")).casefold(), 0) >= minimum
    ]


def _dedupe_alerts(
    alerts: list[dict[str, Any]],
    *,
    ttl_seconds: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not has_app_context():
        raise AlertConfigurationError("Application context is required for security alert dedupe")
    current_time = datetime.now(timezone.utc)
    deliverable: list[dict[str, Any]] = []
    suppressed = 0
    for alert in alerts:
        key_hash = _alert_dedupe_key_hash(alert)
        record = db.session.execute(
            db.select(SecurityAlertDedupe).where(SecurityAlertDedupe.dedupe_key_hash == key_hash)
        ).scalar_one_or_none()
        if record is not None and _as_utc(record.expires_at) > current_time:
            record.count = int(record.count or 1) + 1
            record.last_seen_at = current_time
            suppressed += 1
            continue
        if record is None:
            record = SecurityAlertDedupe(
                dedupe_key_hash=key_hash,
                first_seen_at=current_time,
            )
            db.session.add(record)
        else:
            record.first_seen_at = current_time
            record.count = 1
        record.event_type = _safe_text(alert.get("alert_type"), 80) or "security_alert"
        record.last_seen_at = current_time
        record.expires_at = current_time + timedelta(seconds=ttl_seconds)
        deliverable.append(alert)
    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        raise AlertConfigurationError("DB security alert dedupe failed") from exc
    return deliverable, {
        "enabled": True,
        "ttl_seconds": ttl_seconds,
        "suppressed": suppressed,
    }


def _alert_dedupe_key_hash(alert: Mapping[str, Any]) -> str:
    return active_hmac_hex(_alert_dedupe_key(alert), length=64)


def _alert_dedupe_key(alert: Mapping[str, Any]) -> str:
    stable = {
        "alert_type": _safe_text(alert.get("alert_type"), 80),
        "severity": _safe_text(alert.get("severity"), 24),
        "source": _safe_text(alert.get("source"), 160),
        "window_seconds": int(alert.get("window_seconds") or 0),
    }
    return json.dumps(stable, separators=(",", ":"), sort_keys=True)


def _recent_events(since: datetime) -> list[SecurityAuditEvent]:
    return list(
        db.session.execute(
            db.select(SecurityAuditEvent)
            .where(SecurityAuditEvent.created_at >= since)
            .order_by(SecurityAuditEvent.id.asc())
        ).scalars()
    )


def _add_immediate_alerts(
    alerts: list[dict[str, Any]],
    events: list[SecurityAuditEvent],
    *,
    current_time: datetime,
) -> None:
    for event in events:
        alert_type = IMMEDIATE_ALERT_EVENT_TYPES.get(event.event_type)
        if not alert_type and event.event_type == "session_integrity" and event.outcome == "failure":
            alert_type = "session_integrity_failure"
        if not alert_type:
            continue
        alerts.append(
            _alert(
                alert_type,
                current_time=current_time,
                severity="critical",
                count=1,
                window_seconds=15 * 60,
                source=_event_source(event),
                event_id=event.id,
                event_type=event.event_type,
                outcome=event.outcome,
            )
        )


def _add_login_failure_alerts(
    alerts: list[dict[str, Any]],
    events: list[SecurityAuditEvent],
    *,
    current_time: datetime,
) -> None:
    window_start = current_time - timedelta(minutes=5)
    by_principal: Counter[str] = Counter()
    by_ip: Counter[str] = Counter()
    for event in events:
        if not _is_recent_login_failure(event, window_start):
            continue
        metadata = _metadata(event)
        principal_ref = _safe_ref(metadata.get("principal_ref"))
        if principal_ref:
            by_principal[principal_ref] += 1
        if event.ip_address:
            by_ip[_safe_text(event.ip_address, 64)] += 1

    _append_login_failure_bursts(
        alerts,
        by_principal,
        source_prefix="principal_ref",
        current_time=current_time,
    )
    _append_login_failure_bursts(
        alerts,
        by_ip,
        source_prefix="ip",
        current_time=current_time,
    )


def _is_recent_login_failure(event: SecurityAuditEvent, window_start: datetime) -> bool:
    return (
        _as_utc(event.created_at) >= window_start
        and event.event_type == "login"
        and event.outcome == "failure"
    )


def _append_login_failure_bursts(
    alerts: list[dict[str, Any]],
    counts: Counter[str],
    *,
    source_prefix: str,
    current_time: datetime,
) -> None:
    for source, count in counts.items():
        if count >= 10:
            alerts.append(
                _alert(
                    "login_failure_burst",
                    current_time=current_time,
                    severity="high",
                    count=count,
                    window_seconds=5 * 60,
                    source=f"{source_prefix}:{source}",
                )
            )


def _add_auth_backoff_alerts(
    alerts: list[dict[str, Any]],
    events: list[SecurityAuditEvent],
    *,
    current_time: datetime,
) -> None:
    window_start = current_time - timedelta(minutes=10)
    by_source: Counter[str] = Counter()
    for event in events:
        if _as_utc(event.created_at) < window_start:
            continue
        if event.event_type not in {"auth_backoff", "rate_limit"}:
            continue
        by_source[_event_source(event)] += 1
    for source, count in by_source.items():
        if count >= 5:
            alerts.append(
                _alert(
                    "auth_backoff_or_rate_limit_burst",
                    current_time=current_time,
                    severity="high",
                    count=count,
                    window_seconds=10 * 60,
                    source=source,
                )
            )


def _add_password_reset_alerts(
    alerts: list[dict[str, Any]],
    events: list[SecurityAuditEvent],
    *,
    current_time: datetime,
) -> None:
    window_start = current_time - timedelta(minutes=10)
    request_by_source: Counter[str] = Counter()
    failure_by_source: Counter[str] = Counter()
    for event in events:
        if _as_utc(event.created_at) < window_start:
            continue
        if event.event_type not in PASSWORD_RESET_EVENT_TYPES:
            continue
        source = _event_source(event)
        if event.event_type in {"password_reset_requested", "manual_recovery_requested"}:
            request_by_source[source] += 1
        if event.outcome in {"failure", "blocked", "expired"}:
            failure_by_source[source] += 1

    for source, count in request_by_source.items():
        if count >= 5:
            alerts.append(
                _alert(
                    "password_reset_request_burst",
                    current_time=current_time,
                    severity="high",
                    count=count,
                    window_seconds=10 * 60,
                    source=source,
                )
            )
    for source, count in failure_by_source.items():
        if count >= 3:
            alerts.append(
                _alert(
                    "password_reset_failure_burst",
                    current_time=current_time,
                    severity="high",
                    count=count,
                    window_seconds=10 * 60,
                    source=source,
                )
            )


def _add_transaction_failure_alerts(
    alerts: list[dict[str, Any]],
    events: list[SecurityAuditEvent],
    *,
    current_time: datetime,
) -> None:
    window_start = current_time - timedelta(minutes=15)
    by_user_ref: Counter[str] = Counter()
    global_count = 0
    for event in events:
        if _as_utc(event.created_at) < window_start:
            continue
        if not _is_transaction_failure(event):
            continue
        global_count += 1
        by_user_ref[_transaction_group(event)] += 1

    for source, count in by_user_ref.items():
        if count >= 3:
            alerts.append(
                _alert(
                    "transaction_failure_burst",
                    current_time=current_time,
                    severity="high",
                    count=count,
                    window_seconds=15 * 60,
                    source=source,
                )
            )
    if global_count >= 10:
        alerts.append(
            _alert(
                "transaction_failure_global_burst",
                current_time=current_time,
                severity="critical",
                count=global_count,
                window_seconds=15 * 60,
                source="global",
            )
        )


def _is_transaction_failure(event: SecurityAuditEvent) -> bool:
    if event.event_type not in TRANSACTION_EVENT_TYPES:
        return False
    return event.outcome in {"failure", "blocked", "denied", "expired"}


def _transaction_group(event: SecurityAuditEvent) -> str:
    metadata = _metadata(event)
    transaction_ref = (
        _safe_ref(metadata.get("transaction_ref"))
        or _safe_ref(metadata.get("idempotency_key_ref"))
        or _safe_ref(metadata.get("payee_account_ref"))
        or "missing_ref"
    )
    user_ref = f"user:{event.user_id}" if event.user_id is not None else "user:unknown"
    return _safe_text(f"{user_ref}:transaction_ref:{transaction_ref}", 160)


def _event_source(event: SecurityAuditEvent) -> str:
    metadata = _metadata(event)
    principal_ref = _safe_ref(metadata.get("principal_ref"))
    if principal_ref:
        return f"principal_ref:{principal_ref}"
    session_ref = _safe_ref(event.session_ref)
    if session_ref:
        return f"session_ref:{session_ref}"
    if event.ip_address:
        return f"ip:{_safe_text(event.ip_address, 64)}"
    return "unknown"


def _metadata(event: SecurityAuditEvent) -> dict[str, Any]:
    return event.event_metadata if isinstance(event.event_metadata, dict) else {}


def _alert(
    alert_type: str,
    *,
    current_time: datetime,
    severity: str,
    count: int,
    window_seconds: int,
    source: str,
    **extra: Any,
) -> dict[str, Any]:
    alert = {
        "alert_type": _safe_text(alert_type, 80),
        "severity": _safe_text(severity, 24),
        "count": int(count),
        "window_seconds": int(window_seconds),
        "source": _safe_text(source, 160),
        "generated_at": _utc_iso(current_time),
    }
    for key, value in extra.items():
        if value is None:
            continue
        alert[_safe_text(key, 48)] = (
            int(value) if isinstance(value, int) and not isinstance(value, bool) else _safe_text(value, 120)
        )
    return alert


def _safe_ref(value: Any) -> str | None:
    text = _safe_text(value, 64)
    if not text:
        return None
    if not all(char.isalnum() or char in {"-", "_", ":"} for char in text):
        return None
    return text


def _safe_secret_text(value: str) -> str | None:
    text = value.strip()
    return text or None


def _safe_text(value: Any, limit: int) -> str:
    if value is None:
        return ""
    text = str(value)
    cleaned = "".join(char if (char >= " " and char != "\x7f") else " " for char in text)
    compact = " ".join(cleaned.split())[:limit]
    lowered = compact.casefold()
    if lowered.startswith(("bearer ", "basic ", "token ")):
        return REDACTED_VALUE
    return compact


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utc_iso(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _parse_utc_iso(value: str) -> datetime:
    return _as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
