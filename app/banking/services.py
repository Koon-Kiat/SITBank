from __future__ import annotations

from collections.abc import Mapping

from marshmallow import ValidationError

from app.auth.services import AuthError, ensure_account_not_frozen
from app.banking.schemas import PublicTransactionSchema
from app.models import User
from app.security.audit import audit_event, audit_reference


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


def validate_public_transaction_payload(payload: Mapping[str, object], *, user: User | None = None) -> dict[str, object]:
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
    audit_public_transaction_validation(
        "success",
        user=user,
        metadata={
            "transaction_amount": normalized.get("amount"),
            "transaction_currency": normalized.get("currency"),
        },
        idempotency_key=normalized.get("idempotency_key"),
        payee_account=normalized.get("payee"),
    )
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
    audit_event(f"banking_{action}", outcome, user=user, metadata=event_metadata)


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
