from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from flask import current_app

from app.extensions import db
from app.models import (
    AuthAttemptCounter,
    PasswordResetTransaction,
    RegistrationOtpChallenge,
    SecurityAlertDedupe,
    SecurityCircuitBreaker,
    ServerSideSession,
    TotpReplayRecord,
)


def cleanup_expired_security_state(
    *,
    now: datetime | None = None,
    limit: int | None = None,
) -> dict[str, int]:
    current_time = _as_utc(now or datetime.now(timezone.utc))
    batch_limit = _batch_limit(limit)
    retention_cutoff = current_time - timedelta(days=int(current_app.config["SECURITY_STATE_RETENTION_DAYS"]))

    counts = {
        "expired_sessions_marked": _mark_expired_sessions(current_time, batch_limit),
        "old_sessions_deleted": _delete_rows(
            ServerSideSession,
            ServerSideSession.ended_at.is_not(None),
            ServerSideSession.ended_at < retention_cutoff,
            limit=batch_limit,
        ),
        "auth_attempt_counters_deleted": _delete_rows(
            AuthAttemptCounter,
            AuthAttemptCounter.window_expires_at <= current_time,
            limit=batch_limit,
        ),
        "totp_replay_records_deleted": _delete_rows(
            TotpReplayRecord,
            TotpReplayRecord.expires_at <= current_time,
            limit=batch_limit,
        ),
        "registration_otp_challenges_deleted": _delete_rows(
            RegistrationOtpChallenge,
            RegistrationOtpChallenge.expires_at <= current_time,
            limit=batch_limit,
        ),
        "password_reset_transactions_deleted": _delete_rows(
            PasswordResetTransaction,
            PasswordResetTransaction.expires_at <= current_time,
            limit=batch_limit,
        ),
        "security_alert_dedupe_deleted": _delete_rows(
            SecurityAlertDedupe,
            SecurityAlertDedupe.expires_at <= current_time,
            limit=batch_limit,
        ),
        "security_circuit_breakers_deleted": _delete_rows(
            SecurityCircuitBreaker,
            SecurityCircuitBreaker.state != "open",
            SecurityCircuitBreaker.updated_at < retention_cutoff,
            limit=batch_limit,
        ),
    }
    db.session.commit()
    return counts


def _mark_expired_sessions(now: datetime, limit: int) -> int:
    statement = (
        db.select(ServerSideSession)
        .where(
            ServerSideSession.revoked_at.is_(None),
            ServerSideSession.ended_at.is_(None),
            ServerSideSession.expires_at <= now,
        )
        .order_by(ServerSideSession.expires_at.asc(), ServerSideSession.id.asc())
        .limit(limit)
    )
    records = list(db.session.execute(statement).scalars())
    for record in records:
        record.payload = None
        record.revoked_at = now
        record.ended_at = now
        record.ended_reason = "expired"
    return len(records)


def _delete_rows(model: Any, *criteria: Any, limit: int) -> int:
    ids = [
        row_id
        for row_id in db.session.execute(
            db.select(model.id).where(*criteria).order_by(model.id.asc()).limit(limit)
        ).scalars()
    ]
    if not ids:
        return 0
    db.session.execute(db.delete(model).where(model.id.in_(ids)))
    return len(ids)


def _batch_limit(limit: int | None) -> int:
    configured = limit if limit is not None else current_app.config["SECURITY_STATE_CLEANUP_BATCH_SIZE"]
    try:
        value = int(configured)
    except (TypeError, ValueError):
        value = int(current_app.config["SECURITY_STATE_CLEANUP_BATCH_SIZE"])
    return max(1, min(value, 5000))


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
