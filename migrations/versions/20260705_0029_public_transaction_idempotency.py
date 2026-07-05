"""Add durable public transaction idempotency reservations.

Revision ID: 20260705_0029
Revises: 20260705_0028
Create Date: 2026-07-05 16:00:00
"""

import sqlalchemy as sa
from alembic import op


revision = "20260705_0029"
down_revision = "20260705_0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "public_transaction_idempotency",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("hmac_key_id", sa.String(length=32), nullable=False),
        sa.Column("key_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("key_verifier", sa.String(length=64), nullable=False),
        sa.Column("payload_verifier", sa.String(length=64), nullable=False),
        sa.Column(
            "status",
            sa.String(length=24),
            server_default="reserved",
            nullable=False,
        ),
        sa.Column("result_reference", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('reserved', 'completed', 'failed')",
            name="ck_public_transaction_idempotency_status",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "user_id",
            "key_fingerprint",
            name="uq_public_transaction_idempotency_user_key",
        ),
    )
    op.create_index(
        "ix_public_transaction_idempotency_user_id",
        "public_transaction_idempotency",
        ["user_id"],
    )
    op.create_index(
        "ix_public_transaction_idempotency_expires_at",
        "public_transaction_idempotency",
        ["expires_at"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "Downgrade would discard durable public transaction replay state and "
        "requires an explicit security-reviewed migration"
    )
