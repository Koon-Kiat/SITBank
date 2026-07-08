"""Add known_devices table for new-device-login detection.

Revision ID: 20260709_0036
Revises: 20260708_0035
Create Date: 2026-07-09 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260709_0036"
down_revision = "20260708_0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "known_devices",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("device_token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_known_devices_user_id", "known_devices", ["user_id"])
    op.create_index("ix_known_devices_expires_at", "known_devices", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_known_devices_expires_at", table_name="known_devices")
    op.drop_index("ix_known_devices_user_id", table_name="known_devices")
    op.drop_table("known_devices")
