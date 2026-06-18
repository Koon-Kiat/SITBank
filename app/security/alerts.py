from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from flask import current_app, has_app_context

from app.extensions import db
from app.models import SecurityAuditEvent


IMMEDIATE_ALERT_EVENT_TYPES = {
    "security_audit_write_failed": "security_audit_write_failed",
    "account_lock": "account_lock",
    "webauthn_clone_detected": "webauthn_clone_detected",
    "audit_chain_verification_failed": "audit_chain_verification_failed",
    "audit_anchor_mismatch": "audit_anchor_mismatch",
    "audit_append_only_protection_failed": "audit_append_only_protection_failed",
    "runtime_db_privilege_verification_failed": "runtime_db_privilege_verification_failed",
}
TRANSACTION_EVENT_TYPES = {
    "banking_outbound_transfer",
    "banking_scheduled_transfer_execution",
    "banking_transaction_authorization",
    "webauthn_transaction_stage",
    "webauthn_transaction_options",
    "webauthn_transaction_verify",
}
ALERT_SEVERITY_RANK = {"low": 10, "medium": 20, "high": 30, "critical": 40}
DEFAULT_ALERT_TIMEOUT_SECONDS = 5.0
DEFAULT_ALERT_DEDUPE_TTL_SECONDS = 300
DISCORD_EMBED_FIELD_LIMIT = 10
ALERT_USER_AGENT = "SITBank-SecurityAlerts/1.0"
DISCORD_DISPLAY_TIMEZONE = timezone(timedelta(hours=8))
DISCORD_DISPLAY_TIMEZONE_LABEL = "UTC+8"


class AlertConfigurationError(RuntimeError):
    pass


def evaluate_security_alerts(*, now: datetime | None = None) -> list[dict[str, Any]]:
    current_time = _as_utc(now or datetime.now(timezone.utc))
    longest_window = timedelta(minutes=15)
    events = _recent_events(current_time - longest_window)
    alerts: list[dict[str, Any]] = []

    _add_immediate_alerts(alerts, events, current_time=current_time)
    _add_login_failure_alerts(alerts, events, current_time=current_time)
    _add_auth_backoff_alerts(alerts, events, current_time=current_time)
    _add_transaction_failure_alerts(alerts, events, current_time=current_time)

    return sorted(alerts, key=lambda item: (item["alert_type"], str(item.get("source", ""))))


def build_security_alert_report(
    *,
    deliver: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    current_time = _as_utc(now or datetime.now(timezone.utc))
    alert_config = validate_security_alert_config()
    alerts = _filter_alerts_by_min_severity(
        evaluate_security_alerts(now=current_time),
        alert_config["min_severity"],
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


def _alert_webhook_body(alerts: list[dict[str, Any]], *, provider: str) -> bytes:
    generated_at = _utc_iso(datetime.now(timezone.utc))
    if provider == "discord":
        payload = _discord_alert_payload(alerts, generated_at=generated_at)
    else:
        payload = {
            "message": "security_alerts",
            "generated_at": generated_at,
            "alerts": alerts,
        }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


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
    if not has_app_context() or "redis" not in current_app.extensions:
        raise AlertConfigurationError("Redis is required for security alert dedupe")
    redis_client = current_app.extensions["redis"]
    deliverable: list[dict[str, Any]] = []
    for alert in alerts:
        key = _alert_dedupe_key(alert)
        try:
            accepted = redis_client.set(key, "1", ex=ttl_seconds, nx=True)
        except Exception as exc:
            raise AlertConfigurationError("Redis security alert dedupe failed") from exc
        if accepted:
            deliverable.append(alert)
    return deliverable, {
        "enabled": True,
        "ttl_seconds": ttl_seconds,
        "suppressed": len(alerts) - len(deliverable),
    }


def _alert_dedupe_key(alert: Mapping[str, Any]) -> str:
    stable = {
        "alert_type": _safe_text(alert.get("alert_type"), 80),
        "severity": _safe_text(alert.get("severity"), 24),
        "source": _safe_text(alert.get("source"), 160),
        "window_seconds": int(alert.get("window_seconds") or 0),
    }
    digest = hashlib.sha256(
        json.dumps(stable, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return f"sitbank:security_alert:dedupe:{digest}"


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
        if _as_utc(event.created_at) < window_start:
            continue
        if event.event_type != "login" or event.outcome != "failure":
            continue
        metadata = _metadata(event)
        principal_ref = _safe_ref(metadata.get("principal_ref"))
        if principal_ref:
            by_principal[principal_ref] += 1
        if event.ip_address:
            by_ip[_safe_text(event.ip_address, 64)] += 1

    for principal_ref, count in by_principal.items():
        if count >= 10:
            alerts.append(
                _alert(
                    "login_failure_burst",
                    current_time=current_time,
                    severity="high",
                    count=count,
                    window_seconds=5 * 60,
                    source=f"principal_ref:{principal_ref}",
                )
            )
    for ip_address, count in by_ip.items():
        if count >= 10:
            alerts.append(
                _alert(
                    "login_failure_burst",
                    current_time=current_time,
                    severity="high",
                    count=count,
                    window_seconds=5 * 60,
                    source=f"ip:{ip_address}",
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
        return "[redacted]"
    return compact


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utc_iso(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _parse_utc_iso(value: str) -> datetime:
    return _as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
