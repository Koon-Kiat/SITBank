"""Default new audit hash-chain rows to keyed HMAC.

Revision ID: 20260620_0006
Revises: 20260619_0005
Create Date: 2026-06-20 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260620_0006"
down_revision = "20260619_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_context().dialect.name == "sqlite":
        return
    op.alter_column(
        "security_audit_events",
        "hash_algorithm",
        existing_type=sa.String(length=32),
        existing_nullable=False,
        server_default="hmac-sha256-v1",
    )


def downgrade() -> None:
    if op.get_context().dialect.name == "sqlite":
        return
    op.alter_column(
        "security_audit_events",
        "hash_algorithm",
        existing_type=sa.String(length=32),
        existing_nullable=False,
        server_default="sha256-v1",
    )
