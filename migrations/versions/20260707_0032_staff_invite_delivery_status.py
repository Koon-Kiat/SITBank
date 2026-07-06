"""Add conservative staff invite delivery status.

Revision ID: 20260707_0032
Revises: 20260706_0031
Create Date: 2026-07-07 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260707_0032"
down_revision = "20260706_0031"
branch_labels = None
depends_on = None


_DELIVERY_STATUS_CHECK = "delivery_status IN ('unconfirmed', 'queued', 'failed')"


def upgrade() -> None:
    if op.get_context().as_sql:
        op.add_column(
            "staff_invites",
            sa.Column(
                "delivery_status",
                sa.String(length=32),
                nullable=False,
                server_default="unconfirmed",
            ),
        )
        if op.get_context().dialect.name == "postgresql":
            op.create_check_constraint(
                "ck_staff_invites_delivery_status",
                "staff_invites",
                _DELIVERY_STATUS_CHECK,
            )
        else:
            op.execute(
                "-- SQLite offline SQL cannot add the staff invite delivery check constraint portably."
            )
        return

    with op.batch_alter_table("staff_invites") as batch_op:
        batch_op.add_column(
            sa.Column(
                "delivery_status",
                sa.String(length=32),
                nullable=False,
                server_default="unconfirmed",
            )
        )
        batch_op.create_check_constraint(
            "ck_staff_invites_delivery_status",
            _DELIVERY_STATUS_CHECK,
        )


def downgrade() -> None:
    if op.get_context().as_sql:
        if op.get_context().dialect.name == "postgresql":
            op.drop_constraint(
                "ck_staff_invites_delivery_status",
                "staff_invites",
                type_="check",
            )
        else:
            op.execute(
                "-- SQLite offline SQL cannot drop the staff invite delivery check constraint portably."
            )
        op.drop_column("staff_invites", "delivery_status")
        return

    with op.batch_alter_table("staff_invites") as batch_op:
        batch_op.drop_constraint("ck_staff_invites_delivery_status", type_="check")
        batch_op.drop_column("delivery_status")
