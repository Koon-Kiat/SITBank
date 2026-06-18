from __future__ import annotations

from collections.abc import Mapping

from marshmallow import ValidationError

from app.auth.services import AuthError, ensure_account_not_frozen
from app.banking.schemas import PublicTransactionSchema
from app.models import User
from app.security.audit import audit_system_event, audit_event


def ensure_outbound_transfer_allowed(user: User) -> None:
    try:
        ensure_account_not_frozen(user, "outbound transfers")
    except AuthError as exc:
        audit_event("banking_action", "denied", user=user, metadata={"action": "outbound_transfer", "reason": "account_frozen"})
        raise exc


def ensure_scheduled_transfer_execution_allowed(user: User) -> None:
    try:
        ensure_account_not_frozen(user, "scheduled transfer execution")
    except AuthError as exc:
        audit_event("banking_action", "denied", user=user, metadata={"action": "scheduled_transfer_execution", "reason": "account_frozen"})
        raise exc


def ensure_sensitive_profile_change_allowed(user: User) -> None:
    try:
        ensure_account_not_frozen(user, "sensitive profile changes")
    except AuthError as exc:
        audit_event("banking_action", "denied", user=user, metadata={"action": "sensitive_profile_change", "reason": "account_frozen"})
        raise exc


def before_outbound_transfer(user: User) -> None:
    ensure_outbound_transfer_allowed(user)
    audit_event("banking_action", "authorized", user=user, metadata={"action": "outbound_transfer"})


def before_scheduled_transfer_execution(user: User) -> None:
    ensure_scheduled_transfer_execution_allowed(user)
    audit_event("banking_action", "authorized", user=user, metadata={"action": "scheduled_transfer_execution"})


def before_sensitive_profile_change(user: User) -> None:
    ensure_sensitive_profile_change_allowed(user)
    audit_event("banking_action", "authorized", user=user, metadata={"action": "sensitive_profile_change"})


def validate_public_transaction_payload(payload: Mapping[str, object]) -> dict[str, object]:
    try:
        data = PublicTransactionSchema().load(dict(payload))
        audit_system_event("transaction_validation", "success", metadata={"keys": list(data.keys())})
        return data
    except ValidationError as exc:
        audit_system_event("transaction_validation", "failure", metadata={"errors": exc.messages})
        raise AuthError("Invalid transaction request", 400) from exc
