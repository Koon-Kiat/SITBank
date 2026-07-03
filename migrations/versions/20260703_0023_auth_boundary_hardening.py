"""Harden customer identity and MFA lifecycle state.

Revision ID: 20260703_0023
Revises: 20260703_0022
Create Date: 2026-07-03 12:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260703_0023"
down_revision = "20260703_0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("registration_email_canonical", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("mfa_pending_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("mfa_pending_session_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "recovery_codes",
        sa.Column(
            "hmac_version",
            sa.Integer(),
            nullable=False,
            server_default="2",
        ),
    )
    op.execute(sa.text("UPDATE recovery_codes SET hmac_version = 1"))

    op.create_index(
        "ix_users_registration_email_canonical",
        "users",
        ["registration_email_canonical"],
        unique=True,
        postgresql_where=sa.text("registration_email_canonical IS NOT NULL"),
        sqlite_where=sa.text("registration_email_canonical IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_users_registration_email_canonical", table_name="users")
    with op.batch_alter_table("recovery_codes") as batch_op:
        batch_op.drop_column("hmac_version")
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("mfa_pending_session_hash")
        batch_op.drop_column("mfa_pending_started_at")
        batch_op.drop_column("registration_email_canonical")
