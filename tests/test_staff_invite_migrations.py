from __future__ import annotations

from pathlib import Path

from app.models import StaffInvite


MIGRATIONS = Path("migrations/versions")
ACCEPTANCE_CONTROLS_MIGRATION = (
    MIGRATIONS / "20260704_0026_staff_invite_acceptance_controls.py"
)


def test_staff_invite_schema_has_no_personal_email_binding():
    assert "personal_email_normalized" not in StaffInvite.__table__.c


def test_staff_invite_acceptance_control_model_columns_are_bounded():
    assert StaffInvite.__table__.c.acceptance_session_hash.type.length == 64
    assert StaffInvite.__table__.c.acceptance_session_hash.nullable is True
    assert StaffInvite.__table__.c.acceptance_started_at.nullable is True
    assert StaffInvite.__table__.c.acceptance_start_count.nullable is False
    assert StaffInvite.__table__.c.acceptance_locked_at.nullable is True


def test_staff_invite_acceptance_controls_migration_is_portable_and_non_secret():
    text = ACCEPTANCE_CONTROLS_MIGRATION.read_text(encoding="utf-8")

    assert 'revision = "20260704_0026"' in text
    assert 'down_revision = "20260704_0025"' in text
    assert 'op.batch_alter_table("staff_invites")' in text
    assert '"acceptance_session_hash"' in text
    assert '"acceptance_started_at"' in text
    assert '"acceptance_start_count"' in text
    assert '"acceptance_locked_at"' in text
    assert 'server_default="0"' in text
    assert "token" not in text.casefold()
    assert "postgresql" not in text.casefold()


def test_migrations_have_no_personal_email_binding_or_portability_backfill():
    texts = [
        path.read_text(encoding="utf-8")
        for path in MIGRATIONS.glob("*.py")
        if path.name != "__init__.py"
    ]
    combined = "\n".join(texts)

    assert "personal_email_normalized" not in combined
    assert "staff_invite_portability" not in combined
