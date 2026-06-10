from __future__ import annotations

from collections.abc import Mapping

from marshmallow import ValidationError

from app.auth.services import AuthError, ensure_account_not_frozen
from app.banking.schemas import PublicTransactionSchema
from app.models import User


def ensure_outbound_transfer_allowed(user: User) -> None:
    ensure_account_not_frozen(user, "outbound transfers")


def ensure_scheduled_transfer_execution_allowed(user: User) -> None:
    ensure_account_not_frozen(user, "scheduled transfer execution")


def ensure_sensitive_profile_change_allowed(user: User) -> None:
    ensure_account_not_frozen(user, "sensitive profile changes")


def before_outbound_transfer(user: User) -> None:
    ensure_outbound_transfer_allowed(user)


def before_scheduled_transfer_execution(user: User) -> None:
    ensure_scheduled_transfer_execution_allowed(user)


def before_sensitive_profile_change(user: User) -> None:
    ensure_sensitive_profile_change_allowed(user)


def validate_public_transaction_payload(payload: Mapping[str, object]) -> dict[str, object]:
    try:
        return PublicTransactionSchema().load(dict(payload))
    except ValidationError as exc:
        raise AuthError("Invalid transaction request", 400) from exc
