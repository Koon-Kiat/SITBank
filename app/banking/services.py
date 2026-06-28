from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, MutableMapping
from datetime import datetime, timezone
from decimal import Decimal

from flask import current_app
from marshmallow import ValidationError

from app.auth.services import AuthError, ensure_account_not_frozen
from app.extensions import db
from app.banking.schemas import MAX_TRANSACTION_AMOUNT, MIN_TRANSACTION_AMOUNT, PublicTransactionSchema
from app.models import Payee, Transaction, User
from app.security.audit import audit_event, audit_event_required, audit_reference


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
    idempotency_store: MutableMapping[tuple[str, str], str] | None = None,
) -> dict[str, object]:
    raw_payload = dict(payload)
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

    payload_hash = public_transaction_payload_hash(normalized)
    if idempotency_store is not None:
        _record_idempotency_key_use(
            idempotency_store,
            normalized["idempotency_key"],
            payload_hash,
            user=user,
        )
    audit_public_transaction_validation(
        "success",
        user=user,
        metadata={
            "transaction_amount": normalized.get("amount"),
            "transaction_currency": normalized.get("currency"),
            "payload_hash_ref": audit_reference("transaction_payload_hash", payload_hash),
        },
        idempotency_key=normalized.get("idempotency_key"),
        payee_account=normalized.get("payee"),
    )
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
    stepup_token: str | None = None,
    action: str = "transaction_authorization",
) -> None:
    from app.auth.services import verify_high_risk_authorization

    ensure_outbound_transfer_allowed(user)
    transfer_step_up_requirement(transfer_risk)
    verify_high_risk_authorization(user, totp_code, stepup_token, action)


def public_transaction_payload_hash(payload: Mapping[str, object]) -> str:
    canonical = {
        "amount": str(payload.get("amount")),
        "currency": str(payload.get("currency") or "").upper(),
        "payee": str(payload.get("payee") or "").upper(),
    }
    encoded = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
) -> None:
    audit_banking_action(
        "public_transaction_validation",
        outcome,
        user=user,
        metadata=metadata,
        idempotency_key=idempotency_key,
        payee_account=payee_account,
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
    requires_durable_audit = _requires_durable_audit(action, outcome)
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


def _record_idempotency_key_use(
    store: MutableMapping[tuple[str, str], str],
    idempotency_key: object,
    payload_hash: str,
    *,
    user: User | None,
) -> None:
    scope = f"user:{user.id}" if user is not None and user.id is not None else "anonymous"
    key = (scope, str(idempotency_key))
    existing_hash = store.get(key)
    if existing_hash is None:
        store[key] = payload_hash
        return
    if existing_hash != payload_hash:
        raise AuthError("Idempotency key already used for a different transaction request", 409)


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
    from app.models import PendingTransfer

    ensure_outbound_transfer_allowed(sender)

    # Defence-in-depth: service enforces payee ownership independently of the
    # route layer so direct callers and future refactors cannot bypass it.
    if payee.user_id != sender.id:
        raise AuthError("Transfer denied.", 403)

    recipient_user = User.query.filter_by(account_number=payee.account_number).first()
    if not recipient_user:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "recipient_not_found"},
            payee_account=payee.account_number,
        )
        db.session.commit()
        raise AuthError("Recipient account not found.", 400)

    if recipient_user.id == sender.id:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "self_transfer"},
        )
        db.session.commit()
        raise AuthError("Cannot transfer to yourself.", 400)

    # Block inbound transfers to revoked or unactivated accounts.
    # Locked accounts (security hold) may still receive funds.
    if recipient_user.account_status not in ("active", "locked"):
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "recipient_account_unavailable"},
        )
        db.session.commit()
        raise AuthError("Recipient account is not available to receive transfers.", 400)

    # Enforce payee cooldown in the service so callers that bypass the route
    # cannot skip the cooldown window.
    now = datetime.now(timezone.utc)
    cooldown_seconds = int(current_app.config.get("PAYEE_COOLDOWN_SECONDS", 60))
    payee_created = (
        payee.created_at
        if payee.created_at.tzinfo
        else payee.created_at.replace(tzinfo=timezone.utc)
    )
    if (now - payee_created).total_seconds() < cooldown_seconds:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "payee_in_cooldown"},
        )
        db.session.commit()
        raise AuthError("Payee is still in cooldown.", 400)

    # Atomically consume the pending transfer token with SELECT FOR UPDATE so
    # concurrent confirm requests cannot both proceed past this point.
    pending_tfr = db.session.execute(
        db.select(PendingTransfer)
        .where(
            PendingTransfer.token == confirmation_token,
            PendingTransfer.user_id == sender.id,
            PendingTransfer.payee_id == payee.id,
            PendingTransfer.consumed_at.is_(None),
        )
        .with_for_update()
    ).scalar_one_or_none()

    if pending_tfr is None:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "confirmation_token_not_found"},
        )
        db.session.commit()
        raise AuthError("Transfer confirmation has expired or was already used.", 409)

    expires_at = (
        pending_tfr.expires_at
        if pending_tfr.expires_at.tzinfo
        else pending_tfr.expires_at.replace(tzinfo=timezone.utc)
    )
    if expires_at < now:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "confirmation_token_expired"},
        )
        db.session.commit()
        raise AuthError("Transfer confirmation has expired or was already used.", 409)

    pending_tfr.consumed_at = now
    # normalize() strips trailing zeros (e.g. Decimal("10.10000") -> Decimal("10.1"))
    # so that the exponent check below correctly catches sub-cent amounts regardless
    # of the DB column scale used to store PendingTransfer.amount.
    amount = Decimal(str(pending_tfr.amount)).normalize()
    reference = (pending_tfr.reference or "")[:128]

    # Enforce two-decimal currency precision in the service.
    # Reject over-precision amounts; normalize accepted amounts to exactly 2dp.
    if not amount.is_finite() or amount.as_tuple().exponent < -2:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "invalid_amount_precision", "amount": str(amount)},
        )
        db.session.commit()
        raise AuthError("Transfer amount must have at most two decimal places.", 400)
    amount = amount.quantize(Decimal("0.01"))

    if amount < MIN_TRANSACTION_AMOUNT or amount > MAX_TRANSACTION_AMOUNT:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "amount_out_of_range", "amount": str(amount)},
        )
        db.session.commit()
        raise AuthError("Transfer amount is out of the allowed range.", 400)

    # Lock rows in consistent ascending ID order before SELECT FOR UPDATE so
    # concurrent transfers between the same two accounts cannot deadlock.
    lock_ids = sorted([sender.id, recipient_user.id])
    locked_rows = (
        User.query
        .filter(User.id.in_(lock_ids))
        .order_by(User.id.asc())
        .with_for_update()
        .all()
    )
    locked = {u.id: u for u in locked_rows}
    locked_sender = locked[sender.id]
    locked_recipient = locked[recipient_user.id]

    if locked_sender.balance < amount:
        audit_outbound_transfer(
            sender,
            "failure",
            metadata={"reason": "insufficient_funds", "amount": str(amount)},
            payee_account=audit_reference("payee_account", payee.account_number),
        )
        db.session.commit()
        raise AuthError("Insufficient funds.", 400)

    txn_ref = str(uuid.uuid4())
    txn_created_at = datetime.now(timezone.utc)
    txn_hash = _transaction_hash(
        txn_ref, locked_sender.id, locked_recipient.id, amount, reference, txn_created_at
    )
    locked_sender.balance -= amount
    locked_recipient.balance += amount
    db.session.add(
        Transaction(
            transaction_ref=txn_ref,
            transaction_hash=txn_hash,
            sender_id=locked_sender.id,
            recipient_id=locked_recipient.id,
            payee_id=payee.id,
            amount=amount,
            reference=reference,
            status="completed",
            created_at=txn_created_at,
        )
    )
    pending_tfr.consumed_transaction_ref = txn_ref

    # A09: do not log raw reference — replace with safe metadata that
    # cannot leak customer free-text into the security audit log.
    audit_outbound_transfer(
        sender,
        "success",
        metadata={
            "amount": str(amount),
            "reference_present": bool(reference),
            "reference_length": len(reference),
        },
        transaction_reference=audit_reference("transaction_reference", txn_ref),
        payee_account=audit_reference("payee_account", payee.account_number),
    )
    return txn_ref


def _transaction_hash(
    transaction_ref: str,
    sender_id: int,
    recipient_id: int,
    amount: Decimal,
    reference: str,
    created_at: datetime,
) -> str:
    """SHA-256 of the canonical transaction fields for tamper-evidence."""
    canonical = json.dumps(
        {
            "amount": str(amount),
            "created_at": created_at.isoformat(),
            "recipient_id": recipient_id,
            "reference": reference,
            "sender_id": sender_id,
            "transaction_ref": transaction_ref,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
