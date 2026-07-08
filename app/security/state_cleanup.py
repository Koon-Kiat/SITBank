from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from flask import current_app

from app.extensions import db
from app.models import (
    AuthAttemptCounter,
    KnownDevice,
    PasswordResetToken,
    PasswordResetTransaction,
    PublicTransactionIdempotency,
    RegistrationOtpChallenge,
    SecurityAlertDedupe,
    SecurityCircuitBreaker,
    ServerSideSession,
    TopUpApprovalRequest,
    TotpReplayRecord,
)


def cleanup_expired_security_state(
    *,
    now: datetime | None = None,
    limit: int | None = None,
    dry_run: bool = False,
    commit: bool = True,
) -> dict[str, int]:
    current_time = _as_utc(now or datetime.now(timezone.utc))
    batch_limit = _batch_limit(limit)
    retention_cutoff = current_time - timedelta(
        days=int(current_app.config["SECURITY_STATE_RETENTION_DAYS"])
    )

    counts = {
        "expired_sessions_marked": _mark_expired_sessions(
            current_time,
            batch_limit,
            dry_run=dry_run,
        ),
        "old_sessions_deleted": _delete_rows(
            ServerSideSession,
            ServerSideSession.ended_at.is_not(None),
            ServerSideSession.ended_at < retention_cutoff,
            limit=batch_limit,
            dry_run=dry_run,
        ),
        "auth_attempt_counters_deleted": _delete_rows(
            AuthAttemptCounter,
            AuthAttemptCounter.window_expires_at <= current_time,
            limit=batch_limit,
            dry_run=dry_run,
        ),
        "totp_replay_records_deleted": _delete_rows(
            TotpReplayRecord,
            TotpReplayRecord.expires_at <= current_time,
            limit=batch_limit,
            dry_run=dry_run,
        ),
        "registration_otp_challenges_deleted": _delete_rows(
            RegistrationOtpChallenge,
            RegistrationOtpChallenge.expires_at <= current_time,
            limit=batch_limit,
            dry_run=dry_run,
        ),
        "password_reset_transactions_deleted": _delete_rows(
            PasswordResetTransaction,
            PasswordResetTransaction.expires_at <= current_time,
            limit=batch_limit,
            dry_run=dry_run,
        ),
        "password_reset_tokens_deleted": _delete_rows(
            PasswordResetToken,
            PasswordResetToken.expires_at <= current_time,
            ~PasswordResetToken.id.in_(db.select(PasswordResetTransaction.token_id)),
            limit=batch_limit,
            dry_run=dry_run,
        ),
        "security_alert_dedupe_deleted": _delete_rows(
            SecurityAlertDedupe,
            SecurityAlertDedupe.expires_at <= current_time,
            limit=batch_limit,
            dry_run=dry_run,
        ),
        "security_circuit_breakers_deleted": _delete_rows(
            SecurityCircuitBreaker,
            SecurityCircuitBreaker.state != "open",
            SecurityCircuitBreaker.updated_at < retention_cutoff,
            limit=batch_limit,
            dry_run=dry_run,
        ),
        "public_transaction_idempotency_deleted": _delete_rows(
            PublicTransactionIdempotency,
            PublicTransactionIdempotency.expires_at <= current_time,
            limit=batch_limit,
            dry_run=dry_run,
        ),
        "expired_known_devices_deleted": _delete_rows(
            KnownDevice,
            KnownDevice.expires_at <= current_time,
            limit=batch_limit,
            dry_run=dry_run,
        ),
        "terminal_topup_approval_requests_deleted": _delete_rows(
            TopUpApprovalRequest,
            TopUpApprovalRequest.status.in_(("completed", "expired", "failed")),
            TopUpApprovalRequest.expires_at < retention_cutoff,
            limit=batch_limit,
            dry_run=dry_run,
        ),
    }
    if dry_run:
        db.session.rollback()
    elif commit:
        db.session.commit()
    else:
        db.session.flush()
    return counts


def _mark_expired_sessions(now: datetime, limit: int, *, dry_run: bool = False) -> int:
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
    if dry_run:
        return len(records)
    for record in records:
        record.payload = None
        record.revoked_at = now
        record.ended_at = now
        record.ended_reason = "expired"
    return len(records)


def _delete_rows(model: Any, *criteria: Any, limit: int, dry_run: bool = False) -> int:
    ids = list(
        db.session.execute(
            db.select(model.id).where(*criteria).order_by(model.id.asc()).limit(limit)
        ).scalars()
    )
    if not ids:
        return 0
    if dry_run:
        return len(ids)
    db.session.execute(db.delete(model).where(model.id.in_(ids)))
    return len(ids)


def _batch_limit(limit: int | None) -> int:
    configured = (
        limit
        if limit is not None
        else current_app.config["SECURITY_STATE_CLEANUP_BATCH_SIZE"]
    )
    try:
        value = int(configured)
    except (TypeError, ValueError):
        value = int(current_app.config["SECURITY_STATE_CLEANUP_BATCH_SIZE"])
    return max(1, min(value, 5000))


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
