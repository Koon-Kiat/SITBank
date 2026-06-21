"""Record optional passkey policy metadata.

Revision ID: 20260621_0007
Revises: 20260620_0006
Create Date: 2026-06-21 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260621_0007"
down_revision = "20260620_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column(
                "mfa_step_up_preference",
                sa.String(length=32),
                nullable=False,
                server_default="totp",
            )
        )
    with op.batch_alter_table("webauthn_credentials") as batch_op:
        batch_op.add_column(
            sa.Column(
                "credential_kind",
                sa.String(length=32),
                nullable=False,
                server_default="security_key",
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("webauthn_credentials") as batch_op:
        batch_op.drop_column("credential_kind")
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("mfa_step_up_preference")
