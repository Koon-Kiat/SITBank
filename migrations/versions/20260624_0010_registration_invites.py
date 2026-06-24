"""Add invite-only registration controls.

Revision ID: 20260624_0010
Revises: 20260624_0009
Create Date: 2026-06-24 00:10:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260624_0010"
down_revision = "20260624_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "registration_invites",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("intended_email_normalized", sa.String(length=255), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_by_user_id", sa.Integer(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by_user_id", sa.Integer(), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["revoked_by_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["used_by_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_registration_invites_created_by_user_id",
        "registration_invites",
        ["created_by_user_id"],
        unique=False,
    )
    op.create_index(
        "ix_registration_invites_expires_at",
        "registration_invites",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_registration_invites_intended_email_normalized",
        "registration_invites",
        ["intended_email_normalized"],
        unique=False,
    )
    op.create_index(
        "ix_registration_invites_revoked_by_user_id",
        "registration_invites",
        ["revoked_by_user_id"],
        unique=False,
    )
    op.create_index(
        "ix_registration_invites_token_hash",
        "registration_invites",
        ["token_hash"],
        unique=True,
    )
    op.create_index(
        "ix_registration_invites_used_by_user_id",
        "registration_invites",
        ["used_by_user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_registration_invites_used_by_user_id", table_name="registration_invites")
    op.drop_index("ix_registration_invites_token_hash", table_name="registration_invites")
    op.drop_index("ix_registration_invites_revoked_by_user_id", table_name="registration_invites")
    op.drop_index("ix_registration_invites_intended_email_normalized", table_name="registration_invites")
    op.drop_index("ix_registration_invites_expires_at", table_name="registration_invites")
    op.drop_index("ix_registration_invites_created_by_user_id", table_name="registration_invites")
    op.drop_table("registration_invites")
