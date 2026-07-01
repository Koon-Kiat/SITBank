from pathlib import Path

from app.models import StaffInvite


MIGRATION = Path("migrations/versions/20260701_0019_password_history_and_staff_invite_portability.py")


def test_staff_invite_personal_email_model_is_nullable():
    assert StaffInvite.__table__.c.personal_email_normalized.nullable is True


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
