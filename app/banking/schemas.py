from __future__ import annotations

import re
from decimal import Decimal

from marshmallow import RAISE, Schema, ValidationError, fields, post_load, pre_load, validate, validates_schema


MIN_TRANSACTION_AMOUNT = Decimal("0.01")
MAX_TRANSACTION_AMOUNT = Decimal("50000.00")
SUPPORTED_TRANSACTION_CURRENCIES = frozenset({"SGD"})
IDEMPOTENCY_KEY_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
PAYEE_IDENTIFIER_PATTERN = r"^[A-Z0-9][A-Z0-9 ._:/+-]{2,79}$"
DECIMAL_AMOUNT_PATTERN = re.compile(r"^[+-]?\d+(?:\.(\d+))?$")


class PublicTransactionSchema(Schema):
    class Meta:
        unknown = RAISE

    idempotency_key = fields.Str(
        required=True,
        validate=[
            validate.Length(equal=36),
            validate.Regexp(IDEMPOTENCY_KEY_PATTERN, error="Idempotency key must be a UUID"),
        ],
    )
    amount = fields.Decimal(
        required=True,
        as_string=True,
        places=2,
        allow_nan=False,
        validate=validate.Range(
            min=MIN_TRANSACTION_AMOUNT,
            max=MAX_TRANSACTION_AMOUNT,
        ),
    )
    currency = fields.Str(
        required=True,
        validate=[
            validate.Length(equal=3),
            validate.Regexp(r"^[A-Za-z]{3}$", error="Currency must be a three-letter code"),
        ],
    )
    payee = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=80),
            validate.Regexp(
                PAYEE_IDENTIFIER_PATTERN,
                error="Payee identifier contains unsupported characters",
            ),
        ],
    )

    @pre_load
    def normalize_input(self, data, **_kwargs):
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        for key in ("idempotency_key", "currency", "payee"):
            if key in normalized and normalized[key] is not None:
                normalized[key] = str(normalized[key]).strip()
        if "currency" in normalized and normalized["currency"] is not None:
            normalized["currency"] = str(normalized["currency"]).upper()
        if "payee" in normalized and normalized["payee"] is not None:
            normalized["payee"] = " ".join(str(normalized["payee"]).upper().split())
        if "amount" in normalized and normalized["amount"] is not None:
            amount_text = str(normalized["amount"]).strip()
            amount_match = DECIMAL_AMOUNT_PATTERN.fullmatch(amount_text)
            if amount_match and len(amount_match.group(1) or "") > 2:
                raise ValidationError({"amount": ["Amount must use at most two decimal places"]})
        return normalized

    @validates_schema
    def validate_business_rules(self, data, **_kwargs):
        amount = data.get("amount")
        if amount is None:
            return
        if not amount.is_finite():
            raise ValidationError({"amount": ["Amount must be finite"]})
        if amount.as_tuple().exponent < -2:
            raise ValidationError({"amount": ["Amount must use at most two decimal places"]})
        currency = str(data.get("currency", "")).strip().upper()
        if currency and currency not in SUPPORTED_TRANSACTION_CURRENCIES:
            raise ValidationError({"currency": ["Unsupported currency"]})

    @post_load
    def normalize(self, data, **_kwargs):
        data["idempotency_key"] = data["idempotency_key"].strip()
        data["currency"] = data["currency"].upper()
        data["payee"] = data["payee"].upper()
        return data
