"""Add PayUp nicknames and registration credit ledger.

Revision ID: 20260705_0030
Revises: 20260705_0029
Create Date: 2026-07-05 18:00:00
"""

import sqlalchemy as sa
from alembic import op


revision = "20260705_0030"
down_revision = "20260705_0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("payup_nickname", sa.String(length=128), nullable=True))
    op.create_table(
        "registration_credits",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("credit_ref", sa.String(length=36), nullable=False),
        sa.Column("credit_hash", sa.String(length=64), nullable=False),
        sa.Column("credit_integrity_key_id", sa.String(length=32), nullable=False),
        sa.Column("credit_integrity_algorithm", sa.String(length=32), nullable=False),
        sa.Column("credit_integrity_version", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("amount", sa.Numeric(precision=12, scale=2), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="completed", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("amount = 100.00", name="ck_registration_credits_amount_fixed"),
        sa.CheckConstraint("status IN ('completed')", name="ck_registration_credits_status"),
        sa.CheckConstraint(
            "credit_integrity_key_id IS NOT NULL "
            "AND credit_integrity_algorithm = 'hmac-sha256' "
            "AND credit_integrity_version = 1",
            name="ck_registration_credits_integrity_metadata",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", name="uq_registration_credits_user_id"),
    )
    op.create_index("ix_registration_credits_credit_ref", "registration_credits", ["credit_ref"], unique=True)
    op.create_index("ix_registration_credits_credit_hash", "registration_credits", ["credit_hash"], unique=True)
    op.create_index("ix_registration_credits_user_id", "registration_credits", ["user_id"])
    op.create_index("ix_registration_credits_created_at", "registration_credits", ["created_at"])


def downgrade() -> None:
    raise RuntimeError(
        "Downgrade would discard registration credit ledger evidence and "
        "requires an explicit security-reviewed migration"
    )
