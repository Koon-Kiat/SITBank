"""Add customer password reset and recovery tables.

Revision ID: 20260619_0005
Revises: 20260618_0004
Create Date: 2026-06-19 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260619_0005"
down_revision = "20260618_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("selector", sa.String(length=64), nullable=False),
        sa.Column("verifier_hmac", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("purpose", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exchanged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_ip", sa.String(length=64), nullable=False),
        sa.Column("requested_user_agent", sa.String(length=256), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_password_reset_tokens_selector", "password_reset_tokens", ["selector"], unique=True)
    op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"], unique=False)
    op.create_index("ix_password_reset_tokens_expires_at", "password_reset_tokens", ["expires_at"], unique=False)

    op.create_table(
        "recovery_codes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("code_hmac", sa.String(length=64), nullable=False),
        sa.Column("purpose", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_recovery_codes_user_id", "recovery_codes", ["user_id"], unique=False)
    op.create_index("ix_recovery_codes_code_hmac", "recovery_codes", ["code_hmac"], unique=True)

    op.create_table(
        "manual_recovery_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("identifier_ref", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("requested_ip", sa.String(length=64), nullable=False),
        sa.Column("requested_user_agent", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_manual_recovery_requests_identifier_ref", "manual_recovery_requests", ["identifier_ref"], unique=False)
    op.create_index("ix_manual_recovery_requests_user_id", "manual_recovery_requests", ["user_id"], unique=False)
    op.create_index("ix_manual_recovery_requests_created_at", "manual_recovery_requests", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_manual_recovery_requests_created_at", table_name="manual_recovery_requests")
    op.drop_index("ix_manual_recovery_requests_user_id", table_name="manual_recovery_requests")
    op.drop_index("ix_manual_recovery_requests_identifier_ref", table_name="manual_recovery_requests")
    op.drop_table("manual_recovery_requests")

    op.drop_index("ix_recovery_codes_code_hmac", table_name="recovery_codes")
    op.drop_index("ix_recovery_codes_user_id", table_name="recovery_codes")
    op.drop_table("recovery_codes")

    op.drop_index("ix_password_reset_tokens_expires_at", table_name="password_reset_tokens")
    op.drop_index("ix_password_reset_tokens_user_id", table_name="password_reset_tokens")
    op.drop_index("ix_password_reset_tokens_selector", table_name="password_reset_tokens")
    op.drop_table("password_reset_tokens")
