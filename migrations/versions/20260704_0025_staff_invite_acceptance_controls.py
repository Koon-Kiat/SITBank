"""Add staff invite acceptance restart controls.

Revision ID: 20260704_0025
Revises: 20260703_0024
Create Date: 2026-07-04 04:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260704_0025"
down_revision = "20260703_0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("staff_invites") as batch_op:
        batch_op.add_column(sa.Column("acceptance_session_hash", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("acceptance_started_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(
            sa.Column(
                "acceptance_start_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch_op.add_column(sa.Column("acceptance_locked_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("staff_invites") as batch_op:
        batch_op.drop_column("acceptance_locked_at")
        batch_op.drop_column("acceptance_start_count")
        batch_op.drop_column("acceptance_started_at")
        batch_op.drop_column("acceptance_session_hash")
