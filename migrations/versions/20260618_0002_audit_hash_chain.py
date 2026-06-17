"""Add tamper-evident hash-chain fields to security audit events.

Revision ID: 20260618_0002
Revises: 20260610_0001
Create Date: 2026-06-18 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260618_0002"
down_revision = "20260610_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("security_audit_events") as batch_op:
        batch_op.add_column(sa.Column("previous_event_hash", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("event_hash", sa.String(length=64), nullable=True))
        batch_op.add_column(
            sa.Column(
                "hash_algorithm",
                sa.String(length=32),
                nullable=False,
                server_default="sha256-v1",
            )
        )
    op.create_index(
        "ix_security_audit_events_event_hash",
        "security_audit_events",
        ["event_hash"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_security_audit_events_event_hash", table_name="security_audit_events")
    with op.batch_alter_table("security_audit_events") as batch_op:
        batch_op.drop_column("hash_algorithm")
        batch_op.drop_column("event_hash")
        batch_op.drop_column("previous_event_hash")
