from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from flask import current_app


TRANSACTION_INTEGRITY_ALGORITHM = "hmac-sha256"
TRANSACTION_INTEGRITY_VERSION = 1


def sign_transaction_integrity(
    *,
    transaction_ref: str,
    sender_id: int,
    recipient_id: int,
    payee_id: int | None,
    amount: Decimal,
    reference: str,
    status: str,
    transaction_type: str,
    created_at: datetime,
) -> tuple[str, str, str, int]:
    """Return a versioned, key-identified ledger integrity signature."""
    key_id = str(current_app.config["TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID"])
    keyring = _validated_keyring()
    digest = _digest(
        keyring[key_id],
        _canonical_transaction_payload(
            transaction_ref=transaction_ref,
            sender_id=sender_id,
            recipient_id=recipient_id,
            payee_id=payee_id,
            amount=amount,
            reference=reference,
            status=status,
            transaction_type=transaction_type,
            created_at=created_at,
        ),
    )
    return (
        digest,
        key_id,
        TRANSACTION_INTEGRITY_ALGORITHM,
        TRANSACTION_INTEGRITY_VERSION,
    )


def transaction_integrity_status(transaction: Any) -> str:
    """Return valid, legacy, or invalid without exposing integrity material."""
    metadata = (
        getattr(transaction, "transaction_integrity_key_id", None),
        getattr(transaction, "transaction_integrity_algorithm", None),
        getattr(transaction, "transaction_integrity_version", None),
    )
    if all(value is None for value in metadata):
        return "legacy"
    if any(value is None for value in metadata):
        return "invalid"

    key_id, algorithm, version = metadata
    if (
        algorithm != TRANSACTION_INTEGRITY_ALGORITHM
        or version != TRANSACTION_INTEGRITY_VERSION
    ):
        return "invalid"
    try:
        keyring = _validated_keyring()
    except RuntimeError:
        return "invalid"
    if key_id not in keyring:
        return "invalid"

    expected = _digest(
        keyring[key_id],
        _canonical_transaction_payload(
            transaction_ref=transaction.transaction_ref,
            sender_id=int(transaction.sender_id),
            recipient_id=int(transaction.recipient_id),
            payee_id=(
                int(transaction.payee_id)
                if transaction.payee_id is not None
                else None
            ),
            amount=Decimal(str(transaction.amount)),
            reference=transaction.reference or "",
            status=transaction.status,
            transaction_type=transaction.transaction_type,
            created_at=transaction.created_at,
        ),
    )
    return (
        "valid"
        if hmac.compare_digest(str(transaction.transaction_hash or ""), expected)
        else "invalid"
    )


def validate_transaction_integrity_config() -> int:
    """Validate the dedicated ledger keyring and return its key count."""
    return len(_validated_keyring())


def _validated_keyring() -> dict[str, bytes]:
    keyring = current_app.config.get("TRANSACTION_LEDGER_HMAC_KEYS")
    active_key_id = str(
        current_app.config.get("TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID") or ""
    )
    if not isinstance(keyring, dict) or not keyring:
        raise RuntimeError("At least one transaction ledger HMAC key is required")
    if active_key_id not in keyring:
        raise RuntimeError(
            "TRANSACTION_LEDGER_HMAC_ACTIVE_KEY_ID must identify a configured key"
        )
    for key_id, key in keyring.items():
        if not str(key_id).strip() or not isinstance(key, bytes) or len(key) != 32:
            raise RuntimeError(
                "Every transaction ledger HMAC key must have an identifier and be 32 bytes"
            )
    return keyring


def _canonical_transaction_payload(
    *,
    transaction_ref: str,
    sender_id: int,
    recipient_id: int,
    payee_id: int | None,
    amount: Decimal,
    reference: str,
    status: str,
    transaction_type: str,
    created_at: datetime,
) -> str:
    normalized_amount = Decimal(str(amount)).quantize(Decimal("0.01"))
    payload = {
        "amount": format(normalized_amount, "f"),
        "created_at": _canonical_timestamp(created_at),
        "payee_id": payee_id,
        "recipient_id": int(recipient_id),
        "reference": str(reference),
        "sender_id": int(sender_id),
        "status": str(status),
        "transaction_ref": str(transaction_ref),
        "transaction_type": str(transaction_type),
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _canonical_timestamp(created_at: datetime) -> str:
    if created_at.tzinfo is not None:
        created_at = created_at.astimezone(timezone.utc).replace(tzinfo=None)
    return created_at.isoformat(timespec="microseconds")


def _digest(key: bytes, canonical_payload: str) -> str:
    signing_input = (
        f"sitbank-transaction-integrity-v{TRANSACTION_INTEGRITY_VERSION}:"
        f"{canonical_payload}"
    ).encode("utf-8")
    return hmac.new(key, signing_input, hashlib.sha256).hexdigest()
