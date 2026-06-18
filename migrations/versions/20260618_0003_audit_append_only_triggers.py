"""Add PostgreSQL append-only triggers for security audit events."""

from __future__ import annotations

from alembic import op


revision = "20260618_0003"
down_revision = "20260618_0002"
branch_labels = None
depends_on = None


def _is_postgresql() -> bool:
    return op.get_context().dialect.name == "postgresql"


def upgrade() -> None:
    if not _is_postgresql():
        return

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security_audit_events_reject_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'security_audit_events is append-only'
                USING ERRCODE = '42501';
        END;
        $$;
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS security_audit_events_reject_update
        ON security_audit_events;
        """
    )
    op.execute(
        """
        CREATE TRIGGER security_audit_events_reject_update
        BEFORE UPDATE ON security_audit_events
        FOR EACH ROW
        EXECUTE FUNCTION security_audit_events_reject_mutation();
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS security_audit_events_reject_delete
        ON security_audit_events;
        """
    )
    op.execute(
        """
        CREATE TRIGGER security_audit_events_reject_delete
        BEFORE DELETE ON security_audit_events
        FOR EACH ROW
        EXECUTE FUNCTION security_audit_events_reject_mutation();
        """
    )


def downgrade() -> None:
    if not _is_postgresql():
        return

    op.execute(
        """
        DROP TRIGGER IF EXISTS security_audit_events_reject_update
        ON security_audit_events;
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS security_audit_events_reject_delete
        ON security_audit_events;
        """
    )
    op.execute("DROP FUNCTION IF EXISTS security_audit_events_reject_mutation();")
