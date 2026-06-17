from __future__ import annotations

import json
import os
import urllib.request
from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from app.extensions import db
from app.models import SecurityAuditEvent


IMMEDIATE_ALERT_EVENT_TYPES = {
    "security_audit_write_failed": "security_audit_write_failed",
    "account_lock": "account_lock",
    "webauthn_clone_detected": "webauthn_clone_detected",
}
TRANSACTION_EVENT_TYPES = {
    "banking_outbound_transfer",
    "banking_scheduled_transfer_execution",
    "banking_transaction_authorization",
    "webauthn_transaction_stage",
    "webauthn_transaction_options",
    "webauthn_transaction_verify",
}


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
    alerts = evaluate_security_alerts(now=current_time)
    delivery = {"attempted": False, "configured": False}
    if deliver and alerts:
        delivery = deliver_security_alerts(alerts)
    return {
        "message": "security_alert_report",
        "generated_at": _utc_iso(current_time),
        "alert_count": len(alerts),
        "alerts": alerts,
        "delivery": delivery,
    }


def deliver_security_alerts(
    alerts: list[dict[str, Any]],
    *,
    webhook_url: str | None = None,
    timeout_seconds: float = 5.0,
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

    body = json.dumps(
        {
            "message": "security_alerts",
            "generated_at": _utc_iso(datetime.now(timezone.utc)),
            "alerts": alerts,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # nosec B310
            status_code = int(getattr(response, "status", 0) or response.getcode())
    except Exception as exc:
        return {
            "attempted": True,
            "configured": True,
            "delivered": False,
            "error_type": _safe_text(type(exc).__name__, 80),
        }

    return {
        "attempted": True,
        "configured": True,
        "delivered": 200 <= status_code < 300,
        "status_code": status_code,
    }


def configured_alert_webhook_url(environ: Mapping[str, str] | None = None) -> str | None:
    source = environ or os.environ
    file_path = str(source.get("SECURITY_ALERT_WEBHOOK_URL_FILE") or "").strip()
    if file_path:
        try:
            with open(file_path, encoding="utf-8") as handle:
                return _safe_secret_text(handle.read())
        except OSError as exc:
            raise AlertConfigurationError(
                f"SECURITY_ALERT_WEBHOOK_URL_FILE is not readable: {type(exc).__name__}"
            ) from exc
    return _safe_secret_text(str(source.get("SECURITY_ALERT_WEBHOOK_URL") or ""))


def _validated_webhook_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise AlertConfigurationError("SECURITY_ALERT_WEBHOOK_URL must be an HTTPS URL")
    return url


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
