"""Add PostgreSQL TRUNCATE trigger for security audit events."""

from __future__ import annotations

from alembic import op


revision = "20260618_0004"
down_revision = "20260618_0003"
branch_labels = None
depends_on = None


def _is_postgresql() -> bool:
    return op.get_context().dialect.name == "postgresql"


def upgrade() -> None:
    if not _is_postgresql():
        return

    op.execute(
        """
        DROP TRIGGER IF EXISTS security_audit_events_reject_truncate
        ON security_audit_events;
        """
    )
    op.execute(
        """
        CREATE TRIGGER security_audit_events_reject_truncate
        BEFORE TRUNCATE ON security_audit_events
        FOR EACH STATEMENT
        EXECUTE FUNCTION security_audit_events_reject_mutation();
        """
    )


def downgrade() -> None:
    if not _is_postgresql():
        return

    op.execute(
        """
        DROP TRIGGER IF EXISTS security_audit_events_reject_truncate
        ON security_audit_events;
        """
    )
