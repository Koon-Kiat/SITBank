"""Harden manual recovery workflow controls.

Revision ID: 20260624_0009
Revises: 20260622_0008
Create Date: 2026-06-24 00:00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


revision = "20260624_0009"
down_revision = "20260622_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("manual_recovery_requests") as batch_op:
        batch_op.add_column(sa.Column("request_count", sa.Integer(), nullable=False, server_default="1"))
        batch_op.add_column(sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("last_submitted_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))

    dialect = op.get_context().dialect.name
    if dialect == "postgresql":
        op.execute(
            text(
                """
                UPDATE manual_recovery_requests
                SET updated_at = COALESCE(updated_at, created_at),
                    last_submitted_at = COALESCE(last_submitted_at, created_at),
                    expires_at = COALESCE(expires_at, created_at + interval '7 days'),
                    status_changed_at = COALESCE(status_changed_at, created_at)
                """
            )
        )
    else:
        op.execute(
            text(
                """
                UPDATE manual_recovery_requests
                SET updated_at = COALESCE(updated_at, created_at),
                    last_submitted_at = COALESCE(last_submitted_at, created_at),
                    expires_at = COALESCE(expires_at, datetime(created_at, '+7 days')),
                    status_changed_at = COALESCE(status_changed_at, created_at)
                """
            )
        )

    with op.batch_alter_table("manual_recovery_requests") as batch_op:
        batch_op.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch_op.alter_column("last_submitted_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch_op.alter_column("expires_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch_op.alter_column("status_changed_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch_op.create_index("ix_manual_recovery_requests_expires_at", ["expires_at"], unique=False)
        batch_op.create_index("ix_manual_recovery_requests_status", ["status"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("manual_recovery_requests") as batch_op:
        batch_op.drop_index("ix_manual_recovery_requests_status")
        batch_op.drop_index("ix_manual_recovery_requests_expires_at")
        batch_op.drop_column("completed_at")
        batch_op.drop_column("status_changed_at")
        batch_op.drop_column("expires_at")
        batch_op.drop_column("last_submitted_at")
        batch_op.drop_column("updated_at")
        batch_op.drop_column("request_count")
