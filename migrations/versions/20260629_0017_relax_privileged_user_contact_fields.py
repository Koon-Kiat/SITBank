"""Relax customer-only contact fields for privileged users.

Revision ID: 20260629_0017
Revises: 20260628_0016
Create Date: 2026-06-29 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260629_0017"
down_revision = "20260628_0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_context().dialect.name != "postgresql":
        return

    op.execute(sa.text("ALTER TABLE users ALTER COLUMN phone_number DROP NOT NULL"))
    op.execute(sa.text("ALTER TABLE users ALTER COLUMN account_number DROP NOT NULL"))


def downgrade() -> None:
    # The intended model already allowed these fields to be nullable by the
    # previous revision; this migration repairs production schema drift.
    return
