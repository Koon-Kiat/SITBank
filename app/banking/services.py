from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

from flask import current_app, has_app_context
from marshmallow import ValidationError
from sqlalchemy import and_, func, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.auth.mfa_policy import has_enrolled_mfa_method
from app.auth.services import AuthError, ensure_account_not_frozen
from app.extensions import db
from app.banking.limits import (
    LOCAL_TRANSFER_DAILY_LIMIT_MAX,
    LOCAL_TRANSFER_DAILY_LIMIT_MIN,
    LOCAL_TRANSFER_DAILY_LIMIT_PRECISION,
    LOCAL_TRANSFER_DAILY_LIMIT_PRESETS,
    PAYUP_DAILY_LIMIT_MAX,
    PAYUP_DAILY_LIMIT_MIN,
    PAYUP_DAILY_LIMIT_PRECISION,
    PAYUP_DAILY_LIMIT_PRESETS,
)
from app.banking.schemas import MAX_TRANSACTION_AMOUNT, MIN_TRANSACTION_AMOUNT, PublicTransactionSchema
from app.models import (
    Payee,
    PublicTransactionIdempotency,
    SecurityAuditEvent,
    Transaction,
    TopUpCredit,
    User,
)
from app.security.audit import AuditWriteError, audit_event, audit_event_required, audit_reference
from app.security.email import send_security_email
from app.security.session_hmac import active_hmac_hex
from app.security.sessions import (
    authenticated_session_age_seconds,
    authenticated_session_risk_is_stable,
)
from app.security.transaction_integrity import (
    sign_topup_credit_integrity,
    sign_transaction_integrity,
    transaction_integrity_status,
)


_SGT_OFFSET = timezone(timedelta(hours=8))
_TRANSFER_CONFIRMATION_EXPIRED_MESSAGE = "Transfer confirmation has expired or was already used."
_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE = "Transaction request cannot be processed."
_PUBLIC_TRANSACTION_REPLAY_MESSAGE = "Transaction request has already been accepted."

TRANSFER_RISK_NORMAL = "normal"
TRANSFER_RISK_NEW_PAYEE = "new_payee"
TRANSFER_RISK_LARGE_TRANSFER = "large_transfer"
TRANSFER_STEP_UP_MFA = "mfa"
TRANSFER_RISKS = frozenset(
    {
        TRANSFER_RISK_NORMAL,
        TRANSFER_RISK_NEW_PAYEE,
        TRANSFER_RISK_LARGE_TRANSFER,
    }
)

PAYUP_RISK_ALLOW = "allow"
PAYUP_RISK_STEP_UP = "step_up"
PAYUP_RISK_BLOCK = "block"
_PAYUP_SENSITIVE_EVENT_TYPES = frozenset(
    {
        "manual_recovery_completed",
        "manual_recovery_requested",
        "mfa_replace_start",
        "mfa_replace_verify",
        "password_change",
        "password_reset_completed",
        "recovery_codes_generated",
        "recovery_codes_regenerate",
    }
)
_DAILY_LIMIT_WARNING_RATIO = Decimal("0.80")


@dataclass(frozen=True)
class PayupRiskDecision:
    decision: str
    reasons: tuple[str, ...]

    @property
    def requires_step_up(self) -> bool:
        return self.decision == PAYUP_RISK_STEP_UP

    @property
    def blocked(self) -> bool:
        return self.decision == PAYUP_RISK_BLOCK


def local_transfer_token_verifier(token: str) -> str:
    """Keyed verifier for local-transfer confirmation tokens."""
    return active_hmac_hex(f"local-transfer-confirmation:{str(token or '')}", length=64)


def payup_transfer_token_verifier(token: str) -> str:
    """Keyed verifier for PayUp confirmation tokens."""
    return active_hmac_hex(f"payup-transfer-confirmation:{str(token or '')}", length=64)


def transaction_hash_matches(transaction: Transaction) -> bool:
    return transaction_integrity_status(transaction) == "valid"


def _amount_audit_band(amount: Decimal) -> str:
    normalized = Decimal(str(amount)).copy_abs()
    if normalized < Decimal("100"):
        return "under_100"
    if normalized < Decimal("1000"):
        return "100_to_999"
    if normalized < Decimal("10000"):
        return "1000_to_9999"
    return "10000_or_more"


def _format_money(amount: Decimal | object) -> str:
    return str(Decimal(str(amount)).quantize(Decimal("0.01")))


def send_transfer_notification(
    user: User,
    *,
    direction: str,
    outcome: str,
    channel: str,
    amount: Decimal | None = None,
    transaction_reference: str | None = None,
    counterparty_label: str | None = None,
) -> None:
    normalized_direction = str(direction or "").strip().casefold()
    normalized_outcome = str(outcome or "").strip().casefold()
    if normalized_direction not in {"withdrawal", "deposit"}:
        raise ValueError("Unsupported transfer notification direction")
    if normalized_outcome not in {"success", "failure"}:
        raise ValueError("Unsupported transfer notification outcome")
    if not _transfer_activity_email_enabled(user):
        return

    direction_label = normalized_direction.title()
    status_label = "successful" if normalized_outcome == "success" else "unsuccessful"
    subject = f"SITBank {direction_label} {status_label}"
    lines = [
        f"A {direction_label.lower()} {channel} transaction was {status_label}.",
    ]
    if amount is not None:
        lines.append(f"Amount: SGD {_format_money(amount)}")
    if counterparty_label:
        lines.append(f"Recipient: {counterparty_label}")
    if transaction_reference:
        lines.append(f"Reference: {transaction_reference[:8].upper()}")
    lines.append(
        "If you did not request or expect this activity, contact SITBank support through the approved recovery path."
    )
    _send_banking_email(
        user,
        subject,
        "\n".join(lines),
        event_type="banking_transfer_notification",
        metadata={
            "direction": normalized_direction,
            "outcome": normalized_outcome,
            "channel": channel,
        },
    )


def maybe_send_daily_limit_warning(
    user: User,
    *,
    channel: str,
    used_before: Decimal,
    amount: Decimal,
    daily_limit: Decimal,
) -> None:
    limit = Decimal(str(daily_limit))
    if limit <= 0:
        return
    before_ratio = Decimal(str(used_before)) / limit
    after_amount = Decimal(str(used_before)) + Decimal(str(amount))
    after_ratio = after_amount / limit
    if before_ratio >= _DAILY_LIMIT_WARNING_RATIO or after_ratio < _DAILY_LIMIT_WARNING_RATIO:
        return

    percent_used = (after_ratio * Decimal("100")).quantize(Decimal("0.01"))
    body = "\n".join(
        [
            f"Your {channel} daily transfer usage has reached {percent_used}% of your limit.",
            f"Used today: SGD {_format_money(after_amount)}",
            f"Daily limit: SGD {_format_money(limit)}",
            "If this activity was not yours, contact SITBank support through the approved recovery path.",
        ]
    )
    _send_banking_email(
        user,
        f"SITBank {channel} daily limit 80% alert",
        body,
        event_type="banking_daily_limit_notification",
        metadata={"channel": channel, "threshold": "80_percent"},
    )


def send_transfer_limit_change_notification(
    user: User,
    *,
    outcome: str,
    payup_limit: Decimal | None = None,
    local_transfer_limit: Decimal | None = None,
) -> None:
    normalized_outcome = str(outcome or "").strip().casefold()
    if normalized_outcome not in {"success", "failure"}:
        raise ValueError("Unsupported transfer limit notification outcome")

    status_label = "successful" if normalized_outcome == "success" else "unsuccessful"
    lines = [f"Your daily transfer limit change was {status_label}."]
    if normalized_outcome == "success" and payup_limit is not None and local_transfer_limit is not None:
        lines.append(f"PayUp daily limit: SGD {_format_money(payup_limit)}")
        lines.append(f"Local Transfer daily limit: SGD {_format_money(local_transfer_limit)}")
    lines.append(
        "If you did not request this change, contact SITBank support through the approved recovery path."
    )
    _send_banking_email(
        user,
        f"SITBank transfer limit change {status_label}",
        "\n".join(lines),
        event_type="banking_transfer_limit_notification",
        metadata={"outcome": normalized_outcome},
    )


def _send_banking_email(
    user: User,
    subject: str,
    body: str,
    *,
    event_type: str,
    metadata: Mapping[str, object] | None = None,
) -> None:
    try:
        send_security_email(user.email, subject, body)
    except Exception as exc:
        current_app.logger.warning(
            "%s_failed error=%s",
            event_type,
            type(exc).__name__,
        )
        audit_event(
            event_type,
            "failure",
            user=user,
            metadata={"reason": "email_delivery_failed", **dict(metadata or {})},
        )
        return
    audit_event(event_type, "queued", user=user, metadata=dict(metadata or {}))


def _safe_send_notification(description: str, func, *args, **kwargs) -> None:
    """Run a best-effort post-transfer notification without letting it affect
    an already-committed transfer's reported outcome.

    ``send_transfer_notification``/``maybe_send_daily_limit_warning`` already
    swallow email-delivery and best-effort-audit failures internally, but this
    is a second, defense-in-depth guard: a completed, durably committed
    transfer must never be reported as failed (or have its notification step
    raise) because of a notification-path bug.
    """
    try:
        func(*args, **kwargs)
    except Exception as exc:
        current_app.logger.warning(
            "%s_failed error=%s",
            description,
            type(exc).__name__,
        )


def _transfer_activity_email_enabled(user: User) -> bool:
    return getattr(user, "transfer_activity_email_enabled", True) is not False


def ensure_outbound_transfer_allowed(user: User) -> None:
    _ensure_banking_action_allowed(user, "outbound_transfer", "outbound transfers")


def ensure_scheduled_transfer_execution_allowed(user: User) -> None:
    _ensure_banking_action_allowed(user, "scheduled_transfer_execution", "scheduled transfer execution")


def ensure_sensitive_profile_change_allowed(user: User) -> None:
    _ensure_banking_action_allowed(user, "sensitive_profile_change", "sensitive profile changes")


def before_outbound_transfer(user: User) -> None:
    ensure_outbound_transfer_allowed(user)


def before_scheduled_transfer_execution(user: User) -> None:
    ensure_scheduled_transfer_execution_allowed(user)


def before_sensitive_profile_change(user: User) -> None:
    ensure_sensitive_profile_change_allowed(user)


def validate_public_transaction_payload(
    payload: Mapping[str, object],
    *,
    user: User | None = None,
    idempotency_store: object | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    """Validate and durably reserve a future public transaction request.

    No production route currently calls this scaffold. A successful call is
    deliberately first-use only: same-payload replays are rejected until the
    reservation expires so a future caller cannot accidentally move money
    twice by ignoring replay metadata.
    """
    raw_payload = dict(payload)
    if has_app_context():
        _require_clean_public_transaction_session(
            user=user,
            idempotency_key=raw_payload.get("idempotency_key"),
        )
    try:
        normalized = PublicTransactionSchema().load(raw_payload)
    except ValidationError as exc:
        audit_public_transaction_validation(
            "failure",
            user=user,
            metadata={
                "reason": "schema_validation_failed",
                "field_count": len(raw_payload),
                "rejected_fields": sorted(_safe_field_name(key) for key in raw_payload)[:10],
            },
            idempotency_key=raw_payload.get("idempotency_key"),
            payee_account=raw_payload.get("payee"),
        )
        raise AuthError("Invalid transaction request", 400) from exc

    if not has_app_context():
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503)
    payload_message = _public_transaction_payload_message(normalized)
    payload_hash = public_transaction_payload_hash(normalized)
    if idempotency_store is not None:
        _audit_public_idempotency_failure(
            user=user,
            reason="non_durable_store_rejected",
            idempotency_key=normalized.get("idempotency_key"),
        )
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503)
    _reserve_public_transaction_idempotency(
        user=user,
        idempotency_key=normalized["idempotency_key"],
        payload_message=payload_message,
        now=now,
    )
    try:
        audit_public_transaction_validation(
            "success",
            user=user,
            metadata={
                "transaction_amount": normalized.get("amount"),
                "transaction_currency": normalized.get("currency"),
                "payload_hash_ref": audit_reference(
                    "transaction_payload_hash",
                    payload_hash,
                ),
                "idempotency_status": "reserved",
            },
            idempotency_key=normalized.get("idempotency_key"),
            payee_account=normalized.get("payee"),
            required=True,
        )
    except (AuditWriteError, SQLAlchemyError) as exc:
        db.session.rollback()
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503) from exc
    return normalized


def transfer_step_up_requirement(transfer_risk: str) -> str:
    _normalize_transfer_risk(transfer_risk)
    return TRANSFER_STEP_UP_MFA


def classify_transfer_risk(*, new_payee: bool = False, large_transfer: bool = False) -> str:
    if new_payee:
        return TRANSFER_RISK_NEW_PAYEE
    if large_transfer:
        return TRANSFER_RISK_LARGE_TRANSFER
    return TRANSFER_RISK_NORMAL


def verify_transfer_step_up(
    user: User,
    transfer_risk: str,
    *,
    totp_code: str | None = None,
    action: str = "transaction_authorization",
) -> None:
    from app.auth.services import verify_high_risk_authorization

    ensure_outbound_transfer_allowed(user)
    transfer_step_up_requirement(transfer_risk)
    verify_high_risk_authorization(user, totp_code, action)


def public_transaction_payload_hash(payload: Mapping[str, object]) -> str:
    active_key_id, _keyring = _public_transaction_hmac_keyring()
    return _public_transaction_hmac_hex(
        _public_transaction_payload_message(payload),
        key_id=active_key_id,
    )


def _public_transaction_payload_message(payload: Mapping[str, object]) -> str:
    canonical = {
        "amount": str(payload.get("amount")),
        "currency": str(payload.get("currency") or "").upper(),
        "payee": str(payload.get("payee") or "").upper(),
    }
    encoded = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"payload:{encoded.decode('utf-8')}"


def _normalize_transfer_risk(value: str) -> str:
    normalized = str(value or "").strip().casefold()
    if normalized not in TRANSFER_RISKS:
        raise AuthError("Invalid transfer risk classification", 400)
    return normalized


def audit_outbound_transfer(
    user: User,
    outcome: str,
    *,
    metadata: Mapping[str, object] | None = None,
    transaction_reference: object | None = None,
    payee_account: object | None = None,
    idempotency_key: object | None = None,
) -> None:
    audit_banking_action(
        "outbound_transfer",
        outcome,
        user=user,
        metadata=metadata,
        transaction_reference=transaction_reference,
        payee_account=payee_account,
        idempotency_key=idempotency_key,
    )


def audit_scheduled_transfer_execution(
    user: User,
    outcome: str,
    *,
    metadata: Mapping[str, object] | None = None,
    transaction_reference: object | None = None,
    payee_account: object | None = None,
) -> None:
    audit_banking_action(
        "scheduled_transfer_execution",
        outcome,
        user=user,
        metadata=metadata,
        transaction_reference=transaction_reference,
        payee_account=payee_account,
    )


def audit_public_transaction_validation(
    outcome: str,
    *,
    user: User | None = None,
    metadata: Mapping[str, object] | None = None,
    idempotency_key: object | None = None,
    payee_account: object | None = None,
    required: bool = False,
) -> None:
    audit_banking_action(
        "public_transaction_validation",
        outcome,
        user=user,
        metadata=metadata,
        idempotency_key=idempotency_key,
        payee_account=payee_account,
        required=required,
    )


def audit_transaction_authorization(
    user: User,
    outcome: str,
    *,
    metadata: Mapping[str, object] | None = None,
    transaction_reference: object | None = None,
    payee_account: object | None = None,
) -> None:
    audit_banking_action(
        "transaction_authorization",
        outcome,
        user=user,
        metadata=metadata,
        transaction_reference=transaction_reference,
        payee_account=payee_account,
    )


def audit_banking_action(
    action: str,
    outcome: str,
    *,
    user: User | None = None,
    metadata: Mapping[str, object] | None = None,
    transaction_reference: object | None = None,
    payee_account: object | None = None,
    idempotency_key: object | None = None,
    required: bool = False,
) -> None:
    event_metadata: dict[str, object] = {"action": action}
    if metadata:
        event_metadata.update(dict(metadata))
    if transaction_reference is not None:
        event_metadata["transaction_ref"] = audit_reference("transaction_reference", transaction_reference)
    if payee_account is not None:
        event_metadata["payee_account_ref"] = audit_reference("payee_account", payee_account)
    if idempotency_key is not None:
        event_metadata["idempotency_key_ref"] = audit_reference("idempotency_key", idempotency_key)
    requires_durable_audit = required or _requires_durable_audit(action, outcome)
    writer = audit_event_required if requires_durable_audit else audit_event
    writer(f"banking_{action}", outcome, user=user, metadata=event_metadata)
    if requires_durable_audit:
        # This helper is audit-only in the current banking scaffold; future
        # ledger mutations should own their transaction and commit explicitly.
        db.session.commit()


def _ensure_banking_action_allowed(user: User, action: str, label: str) -> None:
    try:
        ensure_account_not_frozen(user, label)
    except AuthError:
        audit_banking_action(
            action,
            "blocked",
            user=user,
            metadata={"reason": user.security_lock_reason or "account_frozen"},
        )
        raise


def _safe_field_name(value: object) -> str:
    return str(value).strip()[:64]


def _reserve_public_transaction_idempotency(
    *,
    user: User | None,
    idempotency_key: object,
    payload_message: str,
    now: datetime | None,
) -> PublicTransactionIdempotency:
    if (
        not isinstance(user, User)
        or user.id is None
        or db.session.get(User, user.id) is None
    ):
        _audit_public_idempotency_failure(
            user=user,
            reason="authenticated_scope_required",
            idempotency_key=idempotency_key,
        )
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503)

    current_time = _as_utc(now or datetime.now(timezone.utc))
    ttl_seconds = _public_transaction_idempotency_ttl_seconds()
    active_key_id, _keyring = _public_transaction_hmac_keyring()
    key_fingerprint = hashlib.sha256(
        (
            "public-transaction-key-fingerprint:"
            f"user:{user.id}:key:{str(idempotency_key)}"
        ).encode("utf-8")
    ).hexdigest()
    key_verifier = _public_transaction_hmac_hex(
        f"key:{str(idempotency_key)}",
        key_id=active_key_id,
    )
    payload_verifier = _public_transaction_hmac_hex(
        payload_message,
        key_id=active_key_id,
    )
    statement = (
        db.select(PublicTransactionIdempotency)
        .where(
            PublicTransactionIdempotency.user_id == user.id,
            PublicTransactionIdempotency.key_fingerprint == key_fingerprint,
        )
        .with_for_update()
    )
    record = db.session.execute(statement).scalar_one_or_none()
    if record is not None:
        return _reuse_or_reject_public_transaction_reservation(
            record,
            payload_message=payload_message,
            active_key_id=active_key_id,
            key_verifier=key_verifier,
            current_time=current_time,
            ttl_seconds=ttl_seconds,
            user=user,
            idempotency_key=idempotency_key,
        )

    record = PublicTransactionIdempotency(
        user_id=user.id,
        hmac_key_id=active_key_id,
        key_fingerprint=key_fingerprint,
        key_verifier=key_verifier,
        payload_verifier=payload_verifier,
        status="reserved",
        created_at=current_time,
        updated_at=current_time,
        expires_at=current_time + timedelta(seconds=ttl_seconds),
    )
    db.session.add(record)
    try:
        db.session.flush([record])
    except IntegrityError:
        db.session.rollback()
        record = db.session.execute(statement).scalar_one_or_none()
        if record is None:
            raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503)
        return _reuse_or_reject_public_transaction_reservation(
            record,
            payload_message=payload_message,
            active_key_id=active_key_id,
            key_verifier=key_verifier,
            current_time=current_time,
            ttl_seconds=ttl_seconds,
            user=user,
            idempotency_key=idempotency_key,
        )
    return record


def _require_clean_public_transaction_session(
    *,
    user: User | None,
    idempotency_key: object,
) -> None:
    if db.session.new or db.session.dirty or db.session.deleted:
        _audit_public_idempotency_failure(
            user=user,
            reason="pending_database_state_rejected",
            idempotency_key=idempotency_key,
        )
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503)


def _reuse_or_reject_public_transaction_reservation(
    record: PublicTransactionIdempotency,
    *,
    payload_message: str,
    active_key_id: str,
    key_verifier: str,
    current_time: datetime,
    ttl_seconds: int,
    user: User,
    idempotency_key: object,
) -> PublicTransactionIdempotency:
    if _as_utc(record.expires_at) <= current_time:
        record.hmac_key_id = active_key_id
        record.key_verifier = key_verifier
        record.payload_verifier = _public_transaction_hmac_hex(
            payload_message,
            key_id=active_key_id,
        )
        record.status = "reserved"
        record.result_reference = None
        record.created_at = current_time
        record.updated_at = current_time
        record.expires_at = current_time + timedelta(seconds=ttl_seconds)
        db.session.flush([record])
        return record

    _active_key_id, keyring = _public_transaction_hmac_keyring()
    if record.hmac_key_id not in keyring:
        _audit_public_idempotency_failure(
            user=user,
            reason="idempotency_hmac_key_unavailable",
            idempotency_key=idempotency_key,
        )
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503)
    expected_key_verifier = _public_transaction_hmac_hex(
        f"key:{str(idempotency_key)}",
        key_id=record.hmac_key_id,
    )
    if not hmac.compare_digest(record.key_verifier, expected_key_verifier):
        _audit_public_idempotency_failure(
            user=user,
            reason="idempotency_key_verifier_invalid",
            idempotency_key=idempotency_key,
        )
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503)

    same_payload = hmac.compare_digest(
        record.payload_verifier,
        _public_transaction_hmac_hex(
            payload_message,
            key_id=record.hmac_key_id,
        ),
    )
    _audit_public_idempotency_failure(
        user=user,
        reason=(
            "same_payload_replay_blocked"
            if same_payload
            else "idempotency_payload_conflict"
        ),
        idempotency_key=idempotency_key,
    )
    raise AuthError(
        (
            _PUBLIC_TRANSACTION_REPLAY_MESSAGE
            if same_payload
            else "Idempotency key conflicts with an earlier request."
        ),
        409,
    )


def _audit_public_idempotency_failure(
    *,
    user: User | None,
    reason: str,
    idempotency_key: object,
) -> None:
    db.session.rollback()
    audit_public_transaction_validation(
        "blocked",
        user=user,
        metadata={"reason": reason},
        idempotency_key=idempotency_key,
    )


def _public_transaction_idempotency_ttl_seconds() -> int:
    try:
        value = int(
            current_app.config["PUBLIC_TRANSACTION_IDEMPOTENCY_TTL_SECONDS"]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503) from exc
    if value < 60 or value > 7 * 24 * 60 * 60:
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503)
    return value


def _public_transaction_hmac_keyring() -> tuple[str, dict[str, bytes]]:
    active_key_id = str(
        current_app.config.get("TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID") or ""
    )
    configured_keyring = current_app.config.get("TRANSACTION_LEDGER_HMAC_KEYS")
    if not isinstance(configured_keyring, dict) or active_key_id not in configured_keyring:
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503)
    try:
        keyring = {
            str(key_id): bytes(key)
            for key_id, key in configured_keyring.items()
            if str(key_id).strip() and len(bytes(key)) == 32
        }
    except (TypeError, ValueError) as exc:
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503) from exc
    if active_key_id not in keyring or len(keyring) != len(configured_keyring):
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503)
    return active_key_id, keyring


def _public_transaction_hmac_hex(message: str, *, key_id: str) -> str:
    _active_key_id, keyring = _public_transaction_hmac_keyring()
    if key_id not in keyring:
        raise AuthError(_PUBLIC_TRANSACTION_UNAVAILABLE_MESSAGE, 503)
    subkey = hmac.new(
        keyring[key_id],
        b"sitbank-public-transaction-idempotency-v1",
        hashlib.sha256,
    ).digest()
    return hmac.new(
        subkey,
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _lock_transfer_participants(sender_id: int, recipient_id: int) -> tuple[User, User]:
    """Lock both accounts in consistent ascending ID order before SELECT FOR
    UPDATE so concurrent transfers between the same two accounts cannot
    deadlock.
    """
    lock_ids = sorted([sender_id, recipient_id])
    locked_rows = (
        User.query
        .filter(User.id.in_(lock_ids))
        .order_by(User.id.asc())
        .with_for_update()
        .all()
    )
    locked = {u.id: u for u in locked_rows}
    return locked[sender_id], locked[recipient_id]


def _reject_local_transfer(
    sender: User,
    message: str,
    status_code: int,
    *,
    metadata: dict,
    payee_account: str | None = None,
) -> None:
    audit_outbound_transfer(
        sender,
        "failure",
        metadata=metadata,
        payee_account=payee_account,
    )
    db.session.commit()
    send_transfer_notification(
        sender,
        direction="withdrawal",
        outcome="failure",
        channel="Local Transfer",
    )
    raise AuthError(message, status_code)


def _local_transfer_recipient(sender: User, payee: Payee) -> User:
    if payee.user_id != sender.id:
        _reject_local_transfer(
            sender,
            "Transfer denied.",
            403,
            metadata={
                "reason": "payee_ownership_mismatch",
                "payee_id_ref": audit_reference("payee_id", payee.id),
            },
        )

    recipient_user = User.query.filter_by(account_number=payee.account_number).first()
    if not recipient_user:
        _reject_local_transfer(
            sender,
            "Recipient account not found.",
            400,
            metadata={"reason": "recipient_not_found"},
            payee_account=payee.account_number,
        )

    if recipient_user.id == sender.id:
        _reject_local_transfer(
            sender,
            "Cannot transfer to yourself.",
            400,
            metadata={"reason": "self_transfer"},
        )

    if recipient_user.account_status not in ("active", "locked"):
        _reject_local_transfer(
            sender,
            "Recipient account is not available to receive transfers.",
            400,
            metadata={"reason": "recipient_account_unavailable"},
        )
    return recipient_user


def _ensure_payee_cooldown_elapsed(sender: User, payee: Payee, now: datetime) -> None:
    cooldown_seconds = int(current_app.config.get("PAYEE_COOLDOWN_SECONDS", 60))
    payee_created = _as_utc(payee.created_at)
    if (now - payee_created).total_seconds() < cooldown_seconds:
        _reject_local_transfer(
            sender,
            "Payee is still in cooldown.",
            400,
            metadata={"reason": "payee_in_cooldown"},
        )


def _load_pending_local_transfer(
    sender: User,
    payee: Payee,
    confirmation_token: str,
    now: datetime,
):
    from app.models import PendingTransfer

    pending_tfr = db.session.execute(
        db.select(PendingTransfer)
        .where(
            PendingTransfer.token == local_transfer_token_verifier(confirmation_token),
            PendingTransfer.user_id == sender.id,
            PendingTransfer.payee_id == payee.id,
            PendingTransfer.consumed_at.is_(None),
        )
        .with_for_update()
    ).scalar_one_or_none()

    if pending_tfr is None:
        _reject_local_transfer(
            sender,
            _TRANSFER_CONFIRMATION_EXPIRED_MESSAGE,
            409,
            metadata={"reason": "confirmation_token_not_found"},
        )

    if _as_utc(pending_tfr.expires_at) < now:
        _reject_local_transfer(
            sender,
            _TRANSFER_CONFIRMATION_EXPIRED_MESSAGE,
            409,
            metadata={"reason": "confirmation_token_expired"},
        )
    return pending_tfr


def _local_transfer_amount(sender: User, pending_tfr) -> Decimal:
    # normalize() strips trailing zeros (e.g. Decimal("10.10000") -> Decimal("10.1"))
    # so that the exponent check below correctly catches sub-cent amounts regardless
    # of the DB column scale used to store PendingTransfer.amount.
    amount = Decimal(str(pending_tfr.amount)).normalize()
    if not amount.is_finite() or amount.as_tuple().exponent < -2:
        _reject_local_transfer(
            sender,
            "Transfer amount must have at most two decimal places.",
            400,
            metadata={"reason": "invalid_amount_precision", "amount_band": _amount_audit_band(amount)},
        )
    amount = amount.quantize(Decimal("0.01"))

    if amount < MIN_TRANSACTION_AMOUNT or amount > MAX_TRANSACTION_AMOUNT:
        _reject_local_transfer(
            sender,
            "Transfer amount is out of the allowed range.",
            400,
            metadata={"reason": "amount_out_of_range", "amount_band": _amount_audit_band(amount)},
        )
    return amount


def parse_topup_amount(raw: str) -> Decimal:
    try:
        amount = Decimal(str(raw)).quantize(Decimal("0.01"))
    except InvalidOperation as exc:
        raise AuthError("Enter a valid amount.", 400) from exc

    if amount < MIN_TRANSACTION_AMOUNT or amount > MAX_TRANSACTION_AMOUNT:
        raise AuthError("Top-up amount is out of the allowed range.", 400)
    return amount


def credit_account_topup(user: User, amount: Decimal) -> TopUpCredit:
    """Credit a self-service top-up. Called only after the scanning device's
    TOTP code has been verified against the pending approval request.
    """

    locked_user = db.session.execute(
        db.select(User).where(User.id == user.id).with_for_update()
    ).scalar_one()
    ensure_account_not_frozen(locked_user, "account top-up")

    credit_ref = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc)
    (
        credit_hash,
        integrity_key_id,
        integrity_algorithm,
        integrity_version,
    ) = sign_topup_credit_integrity(
        credit_ref=credit_ref,
        user_id=locked_user.id,
        amount=amount,
        status="completed",
        created_at=created_at,
    )
    (
        txn_hash,
        txn_integrity_key_id,
        txn_integrity_algorithm,
        txn_integrity_version,
    ) = sign_transaction_integrity(
        transaction_ref=credit_ref,
        sender_id=locked_user.id,
        recipient_id=locked_user.id,
        payee_id=None,
        amount=amount,
        reference="",
        status="completed",
        transaction_type="topup",
        created_at=created_at,
    )
    locked_user.balance = Decimal(str(locked_user.balance)) + amount
    credit = TopUpCredit(
        credit_ref=credit_ref,
        credit_hash=credit_hash,
        credit_integrity_key_id=integrity_key_id,
        credit_integrity_algorithm=integrity_algorithm,
        credit_integrity_version=integrity_version,
        user_id=locked_user.id,
        amount=amount,
        status="completed",
        created_at=created_at,
    )
    db.session.add(credit)
    db.session.add(
        Transaction(
            transaction_ref=credit_ref,
            transaction_hash=txn_hash,
            transaction_integrity_key_id=txn_integrity_key_id,
            transaction_integrity_algorithm=txn_integrity_algorithm,
            transaction_integrity_version=txn_integrity_version,
            sender_id=locked_user.id,
            recipient_id=locked_user.id,
            payee_id=None,
            amount=amount,
            reference="",
            status="completed",
            transaction_type="topup",
            created_at=created_at,
        )
    )
    db.session.commit()
    audit_event(
        "account_topup",
        "success",
        user=locked_user,
        metadata={
            "amount_band": _amount_audit_band(amount),
            "credit_ref": audit_reference("topup_credit", credit_ref),
        },
    )
    return credit


def _ensure_local_transfer_balance(sender: User, payee: Payee, locked_sender: User, amount: Decimal) -> None:
    if locked_sender.balance < amount:
        _reject_local_transfer(
            sender,
            "Insufficient funds.",
            400,
            metadata={"reason": "insufficient_funds", "amount_band": _amount_audit_band(amount)},
            payee_account=payee.account_number,
        )


def _ensure_local_transfer_daily_limit(
    sender: User,
    payee: Payee,
    locked_sender: User,
    amount: Decimal,
) -> tuple[Decimal, Decimal]:
    daily_limit = Decimal(str(locked_sender.local_transfer_daily_limit))
    used_today = local_transfer_amount_used_today(locked_sender)
    if used_today + amount > daily_limit:
        _reject_local_transfer(
            sender,
            "This transfer would exceed your daily Local Transfer limit.",
            409,
            metadata={"reason": "daily_limit_exceeded", "amount_band": _amount_audit_band(amount)},
            payee_account=payee.account_number,
        )
    return used_today, daily_limit


def execute_local_transfer(
    *,
    sender: User,
    payee: Payee,
    confirmation_token: str,
) -> str:
    """Atomically debit sender and credit recipient. Returns transaction_ref.

    All amount and reference data are read from the PendingTransfer DB record
    identified by confirmation_token, which is consumed atomically with the
    transfer. This prevents concurrent double-submit replay.
    """
    ensure_outbound_transfer_allowed(sender)

    recipient_user = _local_transfer_recipient(sender, payee)
    now = datetime.now(timezone.utc)
    _ensure_payee_cooldown_elapsed(sender, payee, now)

    pending_tfr = _load_pending_local_transfer(sender, payee, confirmation_token, now)
    pending_tfr.consumed_at = now
    reference = (pending_tfr.reference or "")[:128]
    amount = _local_transfer_amount(sender, pending_tfr)

    locked_sender, locked_recipient = _lock_transfer_participants(sender.id, recipient_user.id)
    _ensure_local_transfer_balance(sender, payee, locked_sender, amount)

    # Recompute usage under the sender's row lock (acquired above), which serializes
    # concurrent Local Transfers from the same sender and makes this check-then-insert
    # sequence atomic, matching the equivalent PayUp daily-limit recheck.
    used_today, daily_limit = _ensure_local_transfer_daily_limit(
        sender,
        payee,
        locked_sender,
        amount,
    )

    txn_ref = str(uuid.uuid4())
    txn_created_at = datetime.now(timezone.utc)
    (
        txn_hash,
        integrity_key_id,
        integrity_algorithm,
        integrity_version,
    ) = sign_transaction_integrity(
        transaction_ref=txn_ref,
        sender_id=locked_sender.id,
        recipient_id=locked_recipient.id,
        payee_id=payee.id,
        amount=amount,
        reference=reference,
        status="completed",
        transaction_type="local_transfer",
        created_at=txn_created_at,
    )
    locked_sender.balance -= amount
    locked_recipient.balance += amount
    db.session.add(
        Transaction(
            transaction_ref=txn_ref,
            transaction_hash=txn_hash,
            transaction_integrity_key_id=integrity_key_id,
            transaction_integrity_algorithm=integrity_algorithm,
            transaction_integrity_version=integrity_version,
            sender_id=locked_sender.id,
            recipient_id=locked_recipient.id,
            payee_id=payee.id,
            amount=amount,
            reference=reference,
            status="completed",
            transaction_type="local_transfer",
            created_at=txn_created_at,
        )
    )
    pending_tfr.consumed_transaction_ref = txn_ref

    _audit_local_transfer_success(sender, payee, amount, reference, txn_ref)
    # Ledger commit boundary: the balance debit/credit, the Transaction row,
    # the pending-transfer consumption, and the required success audit row
    # above are all committed together here, as one durable unit, before any
    # best-effort customer notification runs. A notification failure below
    # can never roll back or otherwise affect this already-completed transfer.
    db.session.commit()
    _safe_send_notification(
        "local_transfer_sender_notification",
        send_transfer_notification,
        sender,
        direction="withdrawal",
        outcome="success",
        amount=amount,
        channel="Local Transfer",
        transaction_reference=txn_ref,
        counterparty_label=payee.recipient_name,
    )
    _safe_send_notification(
        "local_transfer_recipient_notification",
        send_transfer_notification,
        locked_recipient,
        direction="deposit",
        outcome="success",
        amount=amount,
        channel="Local Transfer",
        transaction_reference=txn_ref,
        counterparty_label=sender.full_name or sender.username,
    )
    _safe_send_notification(
        "local_transfer_daily_limit_notification",
        maybe_send_daily_limit_warning,
        sender,
        channel="Local Transfer",
        used_before=used_today,
        amount=amount,
        daily_limit=daily_limit,
    )
    return txn_ref


def _audit_local_transfer_success(
    sender: User,
    payee: Payee,
    amount: Decimal,
    reference: str,
    txn_ref: str,
) -> None:
    # A09: do not log raw reference; replace it with safe metadata that
    # cannot leak customer free-text into the security audit log.
    try:
        audit_outbound_transfer(
            sender,
            "success",
            metadata={
                "amount_band": _amount_audit_band(amount),
                "reference_present": bool(reference),
                "reference_length": len(reference),
            },
            transaction_reference=txn_ref,
            payee_account=payee.account_number,
        )
    except AuditWriteError:
        db.session.rollback()
        raise


def sgt_day_start_utc(now: datetime | None = None) -> datetime:
    """UTC instant corresponding to today's midnight in Singapore time (UTC+8, no DST)."""
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    day_start_sgt = reference.astimezone(_SGT_OFFSET).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return day_start_sgt.astimezone(timezone.utc)


def sgt_month_bounds_utc(year: int, month: int) -> tuple[datetime, datetime]:
    """UTC [start, end) instants for the given SGT calendar month."""
    start_sgt = datetime(year, month, 1, tzinfo=_SGT_OFFSET)
    end_sgt = (start_sgt.replace(day=28) + timedelta(days=4)).replace(day=1)
    return start_sgt.astimezone(timezone.utc), end_sgt.astimezone(timezone.utc)


def _signed_net_amount(user: User, *, start: datetime | None, end: datetime | None) -> Decimal:
    """Net signed sum of the user's completed transactions in [start, end)."""
    conditions = [
        or_(Transaction.sender_id == user.id, Transaction.recipient_id == user.id),
        Transaction.status == "completed",
    ]
    if start is not None:
        conditions.append(Transaction.created_at >= start)
    if end is not None:
        conditions.append(Transaction.created_at < end)
    rows = db.session.execute(
        db.select(Transaction.sender_id, Transaction.recipient_id, Transaction.amount).where(*conditions)
    ).all()
    net = Decimal("0")
    for sender_id, _recipient_id, amount in rows:
        signed = Decimal(str(amount))
        net += -signed if sender_id == user.id else signed
    return net


def statement_for_period(user: User, year: int, month: int) -> dict:
    """Derive a statement (opening/closing balance + transactions) for an SGT calendar month.

    ``User.balance`` is a live running total with no per-transaction snapshot, so the
    period's opening/closing balance is derived from it by re-reading the balance and
    querying transaction history back-to-back in this session. A transfer that commits
    between those reads could shift the derived figures by that transfer's amount; this
    is accepted for a read-only statement (unlike money-movement paths elsewhere, which
    use row locking) and is not expected to be user-visible in practice.
    """
    if month < 1 or month > 12:
        raise AuthError("Enter a valid month.", 400)

    period_start_utc, period_end_utc = sgt_month_bounds_utc(year, month)
    if period_start_utc > datetime.now(timezone.utc):
        raise AuthError("Cannot generate a statement for a future period.", 400)

    account_created_at = user.created_at
    if account_created_at is not None:
        if account_created_at.tzinfo is None:
            account_created_at = account_created_at.replace(tzinfo=timezone.utc)
        if period_end_utc <= account_created_at:
            raise AuthError("This account did not exist yet during the requested period.", 400)

    db.session.refresh(user)
    live_balance = Decimal(str(user.balance))
    net_after = _signed_net_amount(user, start=period_end_utc, end=None)
    closing_balance = live_balance - net_after

    period_transactions = (
        db.session.execute(
            db.select(Transaction)
            .where(
                or_(Transaction.sender_id == user.id, Transaction.recipient_id == user.id),
                Transaction.created_at >= period_start_utc,
                Transaction.created_at < period_end_utc,
            )
            .order_by(Transaction.created_at.asc(), Transaction.id.asc())
        )
        .scalars()
        .all()
    )
    net_within = Decimal("0")
    for txn in period_transactions:
        if txn.status != "completed":
            continue
        signed = Decimal(str(txn.amount))
        net_within += -signed if txn.sender_id == user.id else signed
    opening_balance = closing_balance - net_within

    return {
        "period_start": period_start_utc,
        "period_end": period_end_utc,
        "opening_balance": opening_balance,
        "closing_balance": closing_balance,
        "transactions": period_transactions,
    }


def payup_amount_used_today(user: User) -> Decimal:
    """Sum of the user's completed PayUp transfers since midnight SGT."""
    day_start = sgt_day_start_utc()
    total = db.session.execute(
        db.select(func.coalesce(func.sum(Transaction.amount), 0)).where(
            Transaction.sender_id == user.id,
            Transaction.transaction_type == "payup",
            Transaction.status == "completed",
            Transaction.created_at >= day_start,
        )
    ).scalar_one()
    return Decimal(str(total))


def evaluate_payup_risk(
    user: User,
    amount: Decimal,
    *,
    used_today: Decimal | None = None,
) -> PayupRiskDecision:
    """Evaluate the complete server-side quick-transfer eligibility policy."""
    try:
        normalized_amount = Decimal(str(amount)).quantize(Decimal("0.01"))
        daily_used = (
            Decimal(str(used_today))
            if used_today is not None
            else payup_amount_used_today(user)
        )
        daily_limit = Decimal(str(user.payup_daily_limit))
        quick_transfer_cap = Decimal(
            str(current_app.config["PAYUP_QUICK_TRANSFER_CAP"])
        )
        quick_daily_cap = Decimal(str(current_app.config["PAYUP_QUICK_DAILY_CAP"]))
        session_max_age = int(
            current_app.config["PAYUP_QUICK_SESSION_MAX_AGE_SECONDS"]
        )
        sensitive_event_cooldown = int(
            current_app.config["PAYUP_SENSITIVE_EVENT_COOLDOWN_SECONDS"]
        )
        session_age = authenticated_session_age_seconds()
        session_stable = authenticated_session_risk_is_stable()
        recent_sensitive_event = _has_recent_payup_sensitive_event(
            user,
            cooldown_seconds=sensitive_event_cooldown,
        )
    except (ArithmeticError, KeyError, SQLAlchemyError, TypeError, ValueError):
        return PayupRiskDecision(PAYUP_RISK_BLOCK, ("risk_state_unavailable",))

    if (
        not normalized_amount.is_finite()
        or normalized_amount <= 0
        or daily_used < 0
        or daily_limit <= 0
        or quick_transfer_cap <= 0
        or quick_daily_cap <= 0
    ):
        return PayupRiskDecision(PAYUP_RISK_BLOCK, ("risk_state_invalid",))
    if user.payup_enabled is not True:
        return PayupRiskDecision(PAYUP_RISK_BLOCK, ("payup_disabled",))
    if not has_enrolled_mfa_method(user):
        return PayupRiskDecision(PAYUP_RISK_BLOCK, ("mfa_not_enrolled",))
    if not session_stable:
        return PayupRiskDecision(PAYUP_RISK_BLOCK, ("session_risk",))
    if session_age is None:
        return PayupRiskDecision(PAYUP_RISK_BLOCK, ("session_state_unavailable",))

    projected_daily = daily_used + normalized_amount
    if projected_daily > daily_limit:
        return PayupRiskDecision(PAYUP_RISK_BLOCK, ("daily_limit_exceeded",))
    if session_age > session_max_age:
        return PayupRiskDecision(PAYUP_RISK_BLOCK, ("stale_session",))
    if recent_sensitive_event:
        return PayupRiskDecision(PAYUP_RISK_BLOCK, ("recent_sensitive_event",))

    step_up_reasons: list[str] = []
    if normalized_amount > quick_transfer_cap:
        step_up_reasons.append("quick_transfer_cap")
    if projected_daily > quick_daily_cap:
        step_up_reasons.append("quick_daily_cap")
    if step_up_reasons:
        return PayupRiskDecision(
            PAYUP_RISK_STEP_UP,
            tuple(sorted(set(step_up_reasons))),
        )
    return PayupRiskDecision(PAYUP_RISK_ALLOW, ())


def payup_requires_step_up(user: User, amount: Decimal) -> bool:
    """Compatibility helper for templates and existing callers."""
    return evaluate_payup_risk(user, amount).requires_step_up


def _has_recent_payup_sensitive_event(
    user: User,
    *,
    cooldown_seconds: int,
) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=cooldown_seconds)
    sensitive_outcomes = {
        "approved",
        "completed",
        "requested",
        "success",
        "verified",
    }
    matching_event = db.session.execute(
        db.select(SecurityAuditEvent.id)
        .where(
            SecurityAuditEvent.user_id == user.id,
            SecurityAuditEvent.created_at >= cutoff,
            or_(
                and_(
                    SecurityAuditEvent.event_type.in_(
                        _PAYUP_SENSITIVE_EVENT_TYPES
                    ),
                    SecurityAuditEvent.outcome.in_(sensitive_outcomes),
                ),
                and_(
                    SecurityAuditEvent.event_type == "profile_update",
                    SecurityAuditEvent.outcome == "success",
                    SecurityAuditEvent.event_metadata["updated_fields"]
                    .as_string()
                    .in_(("profile_email", "profile_phone", "profile_email_phone")),
                ),
            ),
        )
        .limit(1)
    ).scalar_one_or_none()
    return matching_event is not None


def _resolve_daily_limit_choice(
    choice: str,
    custom_value: str | None,
    *,
    presets: tuple[str, ...],
    minimum: Decimal,
    maximum: Decimal,
    precision: Decimal,
) -> Decimal:
    choice_text = str(choice or "").strip()
    if choice_text in presets:
        return Decimal(choice_text).quantize(precision)
    if choice_text == "custom":
        return _resolve_custom_daily_limit(
            custom_value, minimum=minimum, maximum=maximum, precision=precision
        )
    raise AuthError("Invalid limit selection.", 400)


def _resolve_custom_daily_limit(
    custom_value: str | None,
    *,
    minimum: Decimal,
    maximum: Decimal,
    precision: Decimal,
) -> Decimal:
    custom_text = str(custom_value or "").strip()
    if not custom_text:
        raise AuthError("Enter a custom amount.", 400)
    if "." in custom_text and len(custom_text.rsplit(".", 1)[1]) > 2:
        raise AuthError("Custom amount must use cents precision.", 400)
    try:
        amount = Decimal(custom_text)
    except InvalidOperation as exc:
        raise AuthError("Enter a valid custom amount.", 400) from exc
    if not amount.is_finite():
        raise AuthError("Enter a valid custom amount.", 400)

    amount = amount.quantize(precision)
    if amount < minimum:
        raise AuthError(f"Custom amount must be at least SGD {minimum}.", 400)
    if amount > maximum:
        raise AuthError(f"Custom amount must not exceed SGD {maximum}.", 400)
    return amount


def resolve_transfer_limit_choice(choice: str, custom_value: str | None) -> Decimal:
    """Resolve a TransferLimitsForm PayUp-limit selection into a validated Decimal amount."""
    return _resolve_daily_limit_choice(
        choice,
        custom_value,
        presets=PAYUP_DAILY_LIMIT_PRESETS,
        minimum=PAYUP_DAILY_LIMIT_MIN,
        maximum=PAYUP_DAILY_LIMIT_MAX,
        precision=PAYUP_DAILY_LIMIT_PRECISION,
    )


def resolve_local_transfer_limit_choice(choice: str, custom_value: str | None) -> Decimal:
    """Resolve a TransferLimitsForm Local Transfer-limit selection into a validated Decimal amount."""
    return _resolve_daily_limit_choice(
        choice,
        custom_value,
        presets=LOCAL_TRANSFER_DAILY_LIMIT_PRESETS,
        minimum=LOCAL_TRANSFER_DAILY_LIMIT_MIN,
        maximum=LOCAL_TRANSFER_DAILY_LIMIT_MAX,
        precision=LOCAL_TRANSFER_DAILY_LIMIT_PRECISION,
    )


def local_transfer_amount_used_today(user: User) -> Decimal:
    """Sum of the user's completed Local Transfers since midnight SGT."""
    day_start = sgt_day_start_utc()
    total = db.session.execute(
        db.select(func.coalesce(func.sum(Transaction.amount), 0)).where(
            Transaction.sender_id == user.id,
            Transaction.transaction_type == "local_transfer",
            Transaction.status == "completed",
            Transaction.created_at >= day_start,
        )
    ).scalar_one()
    return Decimal(str(total))


def _load_and_lock_payup_pending_transfer(sender: User, confirmation_token: str):
    from app.models import PayupPendingTransfer

    pending_tfr = db.session.execute(
        db.select(PayupPendingTransfer)
        .where(
            PayupPendingTransfer.token == payup_transfer_token_verifier(confirmation_token),
            PayupPendingTransfer.user_id == sender.id,
            PayupPendingTransfer.consumed_at.is_(None),
        )
        .with_for_update()
    ).scalar_one_or_none()

    if pending_tfr is None:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "confirmation_token_not_found", "transfer_channel": "payup"},
        )
        db.session.commit()
        raise AuthError(_TRANSFER_CONFIRMATION_EXPIRED_MESSAGE, 409)

    now = datetime.now(timezone.utc)
    expires_at = (
        pending_tfr.expires_at
        if pending_tfr.expires_at.tzinfo
        else pending_tfr.expires_at.replace(tzinfo=timezone.utc)
    )
    if expires_at < now:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "confirmation_token_expired", "transfer_channel": "payup"},
        )
        db.session.commit()
        raise AuthError(_TRANSFER_CONFIRMATION_EXPIRED_MESSAGE, 409)

    # Consume immediately once validated, before further checks, so a retried
    # confirm click cannot reprocess the same pending transfer.
    pending_tfr.consumed_at = now
    return pending_tfr


def _validate_payup_amount(sender: User, pending_tfr) -> Decimal:
    # normalize() strips trailing zeros (e.g. Decimal("10.10000") -> Decimal("10.1"))
    # so the exponent check below correctly catches sub-cent amounts.
    amount = Decimal(str(pending_tfr.amount)).normalize()

    if not amount.is_finite() or amount.as_tuple().exponent < -2:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={
                "reason": "invalid_amount_precision",
                "amount_band": _amount_audit_band(amount),
                "transfer_channel": "payup",
            },
        )
        db.session.commit()
        raise AuthError("Transfer amount must have at most two decimal places.", 400)
    amount = amount.quantize(Decimal("0.01"))

    if amount < MIN_TRANSACTION_AMOUNT or amount > MAX_TRANSACTION_AMOUNT:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={
                "reason": "amount_out_of_range",
                "amount_band": _amount_audit_band(amount),
                "transfer_channel": "payup",
            },
        )
        db.session.commit()
        raise AuthError("Transfer amount is out of the allowed range.", 400)

    return amount


def _validate_payup_recipient(sender: User, recipient_user_id: int) -> User:
    recipient_user = db.session.get(User, recipient_user_id)
    if not recipient_user:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "recipient_not_found", "transfer_channel": "payup"},
        )
        db.session.commit()
        raise AuthError("Recipient account not found.", 400)

    if recipient_user.id == sender.id:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "self_transfer", "transfer_channel": "payup"},
        )
        db.session.commit()
        raise AuthError("Cannot transfer to yourself.", 400)

    if (
        recipient_user.account_status != "active"
        or recipient_user.is_frozen
        or not recipient_user.phone_number
    ):
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "recipient_account_unavailable", "transfer_channel": "payup"},
        )
        db.session.commit()
        raise AuthError("Recipient account is not available to receive transfers.", 400)

    return recipient_user


def _payup_sender_has_nickname(sender: User) -> bool:
    nickname = str(getattr(sender, "payup_nickname", "") or "").strip()
    return (
        2 <= len(nickname) <= 128
        and not any(ord(char) < 32 or ord(char) == 127 for char in nickname)
    )


def execute_payup_transfer(
    *,
    sender: User,
    confirmation_token: str,
    authorized: bool,
) -> str:
    """Atomically debit sender and credit recipient for a phone-number PayUp transfer.

    Amount and recipient are read from the PayupPendingTransfer DB record identified
    by confirmation_token, consumed atomically with the transfer. The daily-limit and
    step-up decisions are recomputed here under lock rather than trusted from the
    caller, so a route-level pre-check cannot be raced into skipping MFA.
    """
    ensure_outbound_transfer_allowed(sender)
    if not _payup_sender_has_nickname(sender):
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "payup_nickname_required", "transfer_channel": "payup"},
        )
        db.session.commit()
        raise AuthError("Set your PayUp display nickname before sending by phone number.", 403)

    pending_tfr = _load_and_lock_payup_pending_transfer(sender, confirmation_token)
    amount = _validate_payup_amount(sender, pending_tfr)
    reference = (pending_tfr.reference or "")[:128]
    recipient_user = _validate_payup_recipient(sender, pending_tfr.recipient_user_id)

    locked_sender, locked_recipient = _lock_transfer_participants(sender.id, recipient_user.id)

    # Recompute the daily-limit and step-up decisions under the sender's row lock,
    # which serializes concurrent PayUp transfers from the same sender and makes
    # this check-then-insert sequence effectively atomic for that sender.
    used_today = payup_amount_used_today(locked_sender)
    daily_limit = Decimal(str(locked_sender.payup_daily_limit))
    risk = evaluate_payup_risk(
        locked_sender,
        amount,
        used_today=used_today,
    )
    if risk.blocked:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={
                "reason": risk.reasons[0],
                "risk_reasons": list(risk.reasons),
                "amount_band": _amount_audit_band(amount),
                "transfer_channel": "payup",
            },
        )
        db.session.commit()
        raise AuthError("PayUp could not authorize this transfer.", 403)

    requires_step_up = risk.requires_step_up
    if requires_step_up and not authorized:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={
                "reason": "payup_step_up_required",
                "risk_reasons": list(risk.reasons),
                "transfer_channel": "payup",
            },
        )
        db.session.commit()
        raise AuthError("Authenticator code is required for this transfer amount.", 403)

    if locked_sender.balance < amount:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={
                "reason": "insufficient_funds",
                "amount_band": _amount_audit_band(amount),
                "transfer_channel": "payup",
            },
        )
        db.session.commit()
        raise AuthError("Insufficient funds.", 400)

    txn_ref = str(uuid.uuid4())
    txn_created_at = datetime.now(timezone.utc)
    (
        txn_hash,
        integrity_key_id,
        integrity_algorithm,
        integrity_version,
    ) = sign_transaction_integrity(
        transaction_ref=txn_ref,
        sender_id=locked_sender.id,
        recipient_id=locked_recipient.id,
        payee_id=None,
        amount=amount,
        reference=reference,
        status="completed",
        transaction_type="payup",
        created_at=txn_created_at,
    )
    locked_sender.balance -= amount
    locked_recipient.balance += amount
    db.session.add(
        Transaction(
            transaction_ref=txn_ref,
            transaction_hash=txn_hash,
            transaction_integrity_key_id=integrity_key_id,
            transaction_integrity_algorithm=integrity_algorithm,
            transaction_integrity_version=integrity_version,
            sender_id=locked_sender.id,
            recipient_id=locked_recipient.id,
            payee_id=None,
            amount=amount,
            reference=reference,
            status="completed",
            transaction_type="payup",
            created_at=txn_created_at,
        )
    )
    pending_tfr.consumed_transaction_ref = txn_ref

    try:
        audit_outbound_transfer(
            sender,
            "success",
            metadata={
                "amount_band": _amount_audit_band(amount),
                "reference_present": bool(reference),
                "reference_length": len(reference),
                "transfer_channel": "payup",
                "step_up_used": requires_step_up,
                "risk_reasons": list(risk.reasons),
            },
            transaction_reference=txn_ref,
        )
    except AuditWriteError:
        db.session.rollback()
        raise
    # Ledger commit boundary: the balance debit/credit, the Transaction row,
    # the pending-transfer consumption, and the required success audit row
    # above are all committed together here, as one durable unit, before any
    # best-effort customer notification runs. A notification failure below
    # can never roll back or otherwise affect this already-completed transfer.
    db.session.commit()
    _safe_send_notification(
        "payup_sender_notification",
        send_transfer_notification,
        sender,
        direction="withdrawal",
        outcome="success",
        amount=amount,
        channel="PayUp",
        transaction_reference=txn_ref,
        counterparty_label=_payup_notification_label(locked_recipient),
    )
    _safe_send_notification(
        "payup_recipient_notification",
        send_transfer_notification,
        locked_recipient,
        direction="deposit",
        outcome="success",
        amount=amount,
        channel="PayUp",
        transaction_reference=txn_ref,
        counterparty_label=_payup_notification_label(locked_sender),
    )
    _safe_send_notification(
        "payup_daily_limit_notification",
        maybe_send_daily_limit_warning,
        sender,
        channel="PayUp",
        used_before=used_today,
        amount=amount,
        daily_limit=daily_limit,
    )
    return txn_ref


def _payup_notification_label(user: User) -> str:
    return str(getattr(user, "payup_nickname", "") or "").strip() or user.full_name or user.username


def _requires_durable_audit(action: str, outcome: str) -> bool:
    normalized_action = action.strip().casefold()
    normalized_outcome = outcome.strip().casefold()
    return (
        normalized_action
        in {
            "outbound_transfer",
            "scheduled_transfer_execution",
            "transaction_authorization",
        }
        and normalized_outcome in {"success", "approved", "completed", "executed"}
    )
