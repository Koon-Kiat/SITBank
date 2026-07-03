from pathlib import Path

from app.models import StaffInvite


MIGRATION = Path("migrations/versions/20260701_0019_password_history_and_staff_invite_portability.py")
ACCEPTANCE_CONTROLS_MIGRATION = Path(
    "migrations/versions/20260704_0025_staff_invite_acceptance_controls.py"
)


def test_staff_invite_personal_email_model_is_nullable():
    assert StaffInvite.__table__.c.personal_email_normalized.nullable is True


def test_staff_invite_acceptance_control_model_columns_are_bounded():
    assert StaffInvite.__table__.c.acceptance_session_hash.type.length == 64
    assert StaffInvite.__table__.c.acceptance_session_hash.nullable is True
    assert StaffInvite.__table__.c.acceptance_started_at.nullable is True
    assert StaffInvite.__table__.c.acceptance_start_count.nullable is False
    assert StaffInvite.__table__.c.acceptance_locked_at.nullable is True


def test_portable_staff_invite_nullability_migration_uses_batch_mode():
    text = MIGRATION.read_text(encoding="utf-8")

    assert 'down_revision = "20260630_0018"' in text
    assert 'op.batch_alter_table("staff_invites"' in text
    assert "copy_from=_staff_invites_table()" in text
    assert '"personal_email_normalized"' in text
    assert "nullable=True" in text
    assert "op.get_bind().dialect" not in text
    assert "postgresql" not in text.casefold()
    assert "UPDATE staff_invites" not in text


def test_staff_invite_acceptance_controls_migration_is_portable_and_non_secret():
    text = ACCEPTANCE_CONTROLS_MIGRATION.read_text(encoding="utf-8")

    assert 'revision = "20260704_0025"' in text
    assert 'down_revision = "20260703_0024"' in text
    assert 'op.batch_alter_table("staff_invites")' in text
    assert '"acceptance_session_hash"' in text
    assert '"acceptance_started_at"' in text
    assert '"acceptance_start_count"' in text
    assert '"acceptance_locked_at"' in text
    assert 'server_default="0"' in text
    assert "token" not in text.casefold()
    assert "postgresql" not in text.casefold()
