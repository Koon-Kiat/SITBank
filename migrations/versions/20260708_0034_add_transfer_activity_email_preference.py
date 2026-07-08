"""Add transfer activity email preference.

Revision ID: 20260708_0034
Revises: 20260708_0033
Create Date: 2026-07-08 00:34:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260708_0034"
down_revision = "20260708_0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "transfer_activity_email_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "transfer_activity_email_enabled")
