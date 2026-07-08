"""Allow 'account_recovery' in support_tickets.category so the manual
recovery flow can surface a linked staff support ticket.

Revision ID: 20260709_0038
Revises: 20260709_0037
Create Date: 2026-07-09 00:38:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260709_0038"
down_revision = "20260709_0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # See 20260703_0022_add_payup_support.py for why this is Postgres-only:
    # SQLite cannot ALTER an existing CHECK constraint, and the application
    # layer only ever writes a validated category value.
    if op.get_context().dialect.name == "postgresql":
        op.execute(sa.text(
            "ALTER TABLE support_tickets DROP CONSTRAINT ck_support_tickets_category"
        ))
        op.execute(sa.text(
            "ALTER TABLE support_tickets ADD CONSTRAINT ck_support_tickets_category"
            " CHECK (category IN ('enquiry', 'security_concern', 'other', 'account_recovery'))"
        ))


def downgrade() -> None:
    # Lossy if any 'account_recovery' rows exist: re-adding the narrower
    # constraint will fail until those rows are removed or recategorized.
    if op.get_context().dialect.name == "postgresql":
        op.execute(sa.text(
            "ALTER TABLE support_tickets DROP CONSTRAINT ck_support_tickets_category"
        ))
        op.execute(sa.text(
            "ALTER TABLE support_tickets ADD CONSTRAINT ck_support_tickets_category"
            " CHECK (category IN ('enquiry', 'security_concern', 'other'))"
        ))
