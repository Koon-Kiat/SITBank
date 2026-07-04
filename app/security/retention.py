from __future__ import annotations

from datetime import datetime
from typing import Any

from flask import current_app

from app.security.state_cleanup import cleanup_expired_security_state


APPROVED_SECURITY_STATE_CATEGORIES = (
    "expired_server_side_sessions",
    "expired_auth_attempt_counters",
    "expired_totp_replay_records",
    "expired_registration_otp_challenges",
    "expired_password_reset_transactions",
    "expired_password_reset_tokens_without_transactions",
    "expired_security_alert_dedupe_state",
    "closed_security_circuit_breakers_past_retention",
)

PRESERVED_RETENTION_CATEGORIES = (
    "customer_accounts",
    "staff_admin_accounts",
    "payees",
    "transactions",
    "security_audit_events",
    "manual_recovery_requests",
    "staff_invites",
    "investigation_or_held_records",
    "encrypted_backup_archives",
)


class RetentionCleanupError(ValueError):
    """Raised when an operator retention cleanup request is unsafe."""


def run_retention_cleanup(
    *,
    now: datetime | None = None,
    limit: int | None = None,
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """Run the approved temporary security-state retention workflow."""

    retention_days = _configured_int(
        "SECURITY_STATE_RETENTION_DAYS",
        minimum=1,
        maximum=365,
    )
    configured_batch_limit = _configured_int(
        "SECURITY_STATE_CLEANUP_BATCH_SIZE",
        minimum=1,
        maximum=5000,
    )
    requested_limit = _validated_limit(limit)
    batch_limit = (
        requested_limit if requested_limit is not None else configured_batch_limit
    )
    if not dry_run and not confirm:
        raise RetentionCleanupError(
            "State-changing retention cleanup requires --confirm"
        )

    counts = cleanup_expired_security_state(
        now=now,
        limit=requested_limit,
        dry_run=dry_run,
    )
    return {
        "mode": "dry_run" if dry_run else "confirmed",
        "dry_run": dry_run,
        "retention_days": retention_days,
        "batch_limit": batch_limit,
        "approved_categories": list(APPROVED_SECURITY_STATE_CATEGORIES),
        "preserved_categories": list(PRESERVED_RETENTION_CATEGORIES),
        "category_counts": counts,
        "scheduling": "weekly_operator_reviewed_dry_run",
    }


def _configured_int(name: str, *, minimum: int, maximum: int) -> int:
    try:
        value = int(current_app.config[name])
    except (KeyError, TypeError, ValueError) as exc:
        raise RetentionCleanupError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise RetentionCleanupError(
            f"{name} must be between {minimum} and {maximum}"
        )
    return value


def _validated_limit(limit: int | None) -> int | None:
    if limit is None:
        return None
    try:
        value = int(limit)
    except (TypeError, ValueError) as exc:
        raise RetentionCleanupError("--limit must be an integer") from exc
    if value < 1 or value > 5000:
        raise RetentionCleanupError("--limit must be between 1 and 5000")
    return value
