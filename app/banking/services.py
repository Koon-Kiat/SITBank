from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, MutableMapping

from marshmallow import ValidationError

from app.auth.services import AuthError, ensure_account_not_frozen
from app.extensions import db
from app.banking.schemas import PublicTransactionSchema
from app.models import User
from app.security.audit import audit_event, audit_event_required, audit_reference


TRANSFER_RISK_NORMAL = "normal"
TRANSFER_RISK_NEW_PAYEE = "new_payee"
TRANSFER_RISK_LARGE_TRANSFER = "large_transfer"
TRANSFER_STEP_UP_STANDARD = "mfa_or_passkey"
TRANSFER_STEP_UP_PASSKEY = "passkey"
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
    normalized = _normalize_transfer_risk(transfer_risk)
    if normalized == TRANSFER_RISK_NORMAL:
        return TRANSFER_STEP_UP_STANDARD
    return TRANSFER_STEP_UP_PASSKEY


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
    from app.auth.webauthn_services import consume_step_up_token
    from app.security.sessions import require_stable_session_for_sensitive_action

    ensure_outbound_transfer_allowed(user)
    requirement = transfer_step_up_requirement(transfer_risk)
    if requirement == TRANSFER_STEP_UP_STANDARD:
        verify_high_risk_authorization(user, totp_code, stepup_token, action)
        return

    require_stable_session_for_sensitive_action(action)
    consume_step_up_token(user, action, stepup_token)
    audit_transaction_authorization(
        user,
        "passkey_step_up_success",
        metadata={"transfer_risk": _normalize_transfer_risk(transfer_risk)},
    )


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
