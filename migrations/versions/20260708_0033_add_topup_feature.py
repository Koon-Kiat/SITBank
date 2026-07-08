"""Add self-service top-up: QR/TOTP approval requests and credit ledger.

Revision ID: 20260708_0033
Revises: 20260707_0032
Create Date: 2026-07-08 00:33:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260708_0033"
down_revision = "20260707_0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "topup_approval_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("selector", sa.String(length=64), nullable=False),
        sa.Column("verifier_hmac", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("amount", sa.Numeric(precision=12, scale=2), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("credit_ref", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'completed', 'expired', 'failed')",
            name="ck_topup_approval_requests_status",
        ),
        sa.CheckConstraint(
            "amount >= 0.01 AND amount <= 50000.00",
            name="ck_topup_approval_requests_amount_bounds",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_topup_approval_requests_selector",
        "topup_approval_requests",
        ["selector"],
        unique=True,
    )
    op.create_index(
        "ix_topup_approval_requests_user_id", "topup_approval_requests", ["user_id"]
    )
    op.create_index(
        "ix_topup_approval_requests_status", "topup_approval_requests", ["status"]
    )
    op.create_index(
        "ix_topup_approval_requests_expires_at", "topup_approval_requests", ["expires_at"]
    )
    op.create_index(
        "ix_topup_approval_requests_created_at", "topup_approval_requests", ["created_at"]
    )

    op.create_table(
        "topup_credits",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("credit_ref", sa.String(length=36), nullable=False),
        sa.Column("credit_hash", sa.String(length=64), nullable=False),
        sa.Column("credit_integrity_key_id", sa.String(length=32), nullable=False),
        sa.Column("credit_integrity_algorithm", sa.String(length=32), nullable=False),
        sa.Column("credit_integrity_version", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("amount", sa.Numeric(precision=12, scale=2), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "amount >= 0.01 AND amount <= 50000.00",
            name="ck_topup_credits_amount_bounds",
        ),
        sa.CheckConstraint("status IN ('completed')", name="ck_topup_credits_status"),
        sa.CheckConstraint(
            "credit_integrity_key_id IS NOT NULL AND credit_integrity_algorithm = 'hmac-sha256' "
            "AND credit_integrity_version = 1",
            name="ck_topup_credits_integrity_metadata",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_topup_credits_credit_ref", "topup_credits", ["credit_ref"], unique=True
    )
    op.create_index(
        "ix_topup_credits_credit_hash", "topup_credits", ["credit_hash"], unique=True
    )
    op.create_index("ix_topup_credits_user_id", "topup_credits", ["user_id"])
    op.create_index("ix_topup_credits_created_at", "topup_credits", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_topup_credits_created_at", table_name="topup_credits")
    op.drop_index("ix_topup_credits_user_id", table_name="topup_credits")
    op.drop_index("ix_topup_credits_credit_hash", table_name="topup_credits")
    op.drop_index("ix_topup_credits_credit_ref", table_name="topup_credits")
    op.drop_table("topup_credits")

    op.drop_index(
        "ix_topup_approval_requests_created_at", table_name="topup_approval_requests"
    )
    op.drop_index(
        "ix_topup_approval_requests_expires_at", table_name="topup_approval_requests"
    )
    op.drop_index(
        "ix_topup_approval_requests_status", table_name="topup_approval_requests"
    )
    op.drop_index(
        "ix_topup_approval_requests_user_id", table_name="topup_approval_requests"
    )
    op.drop_index(
        "ix_topup_approval_requests_selector", table_name="topup_approval_requests"
    )
    op.drop_table("topup_approval_requests")
