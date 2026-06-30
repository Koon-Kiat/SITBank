"""Allow staff invites without personal email contact.

Revision ID: 20260630_0018
Revises: 20260629_0017
Create Date: 2026-06-30 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260630_0018"
down_revision = "20260629_0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_context().dialect.name != "postgresql":
        return

    op.alter_column(
        "staff_invites",
        "personal_email_normalized",
        existing_type=sa.String(length=255),
        nullable=True,
    )


def downgrade() -> None:
    # Do not synthesize personal email contacts for privileged invites.
    return
