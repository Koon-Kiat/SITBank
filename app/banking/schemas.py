from __future__ import annotations

from marshmallow import RAISE, Schema, fields, post_load, validate


class PublicTransactionSchema(Schema):
    class Meta:
        unknown = RAISE

    idempotency_key = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=128),
    )
    amount = fields.Decimal(
        required=True,
        as_string=True,
        places=2,
        validate=validate.Range(min=0.01),
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
        validate=validate.Length(min=1, max=160),
    )

    @post_load
    def normalize(self, data, **_kwargs):
        data["idempotency_key"] = data["idempotency_key"].strip()
        data["currency"] = data["currency"].strip().upper()
        data["payee"] = data["payee"].strip()
        return data
