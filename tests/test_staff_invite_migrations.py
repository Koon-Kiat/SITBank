from pathlib import Path

from app.models import StaffInvite


MIGRATIONS = Path("migrations/versions")


def test_staff_invite_schema_has_no_personal_email_binding():
    assert "personal_email_normalized" not in StaffInvite.__table__.c


def test_migrations_have_no_personal_email_binding_or_portability_backfill():
    texts = [
        path.read_text(encoding="utf-8")
        for path in MIGRATIONS.glob("*.py")
        if path.name != "__init__.py"
    ]
    combined = "\n".join(texts)

    assert "personal_email_normalized" not in combined
    assert "staff_invite_portability" not in combined
