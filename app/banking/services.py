from __future__ import annotations

from collections.abc import Mapping

from app.auth.services import AuthError, ensure_account_not_frozen
from app.models import User


FORBIDDEN_CLIENT_TRANSACTION_FIELDS = frozenset(
    {
        "account_id",
        "account_number",
        "approval_state",
        "approved_by",
        "credit_limit",
        "currency_normalized",
        "kyc_state",
        "limit",
        "maker_user_id",
        "risk_score",
        "status",
        "transaction_id",
        "transaction_status",
        "user_id",
    }
)


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


def validate_public_transaction_payload(payload: Mapping[str, object]) -> None:
    supplied_fields = {str(key).strip().casefold() for key in payload}
    if supplied_fields & FORBIDDEN_CLIENT_TRANSACTION_FIELDS:
        raise AuthError("Transaction request contains server-controlled fields", 400)
    if not str(payload.get("idempotency_key") or "").strip():
        raise AuthError("Idempotency key is required", 400)
