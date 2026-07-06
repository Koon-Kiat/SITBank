from __future__ import annotations

from pathlib import Path

from app.models import StaffInvite


MIGRATIONS = Path("migrations/versions")
ACCEPTANCE_CONTROLS_MIGRATION = (
    MIGRATIONS / "20260704_0026_staff_invite_acceptance_controls.py"
)
DELIVERY_STATUS_MIGRATION = (
    MIGRATIONS / "20260707_0032_staff_invite_delivery_status.py"
)


def test_staff_invite_schema_has_no_personal_email_binding():
    assert "personal_email_normalized" not in StaffInvite.__table__.c
    assert "acceptance_session_hash" in StaffInvite.__table__.c
    assert "acceptance_verify_locked_at" in StaffInvite.__table__.c
    assert "delivery_status" in StaffInvite.__table__.c


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


def test_staff_invite_delivery_status_is_allowlisted_and_migrates_conservatively():
    column = StaffInvite.__table__.c.delivery_status
    text = DELIVERY_STATUS_MIGRATION.read_text(encoding="utf-8")

    assert column.type.length == 32
    assert column.nullable is False
    assert column.server_default.arg == "unconfirmed"
    assert 'revision = "20260707_0032"' in text
    assert 'down_revision = "20260706_0031"' in text
    assert "ck_staff_invites_delivery_status" in text
    assert "delivery_status IN ('unconfirmed', 'queued', 'failed')" in text
    assert 'server_default="unconfirmed"' in text
    assert "raw invite" not in text.casefold()


def test_migrations_have_no_personal_email_binding_or_portability_backfill():
    texts = [
        path.read_text(encoding="utf-8")
        for path in MIGRATIONS.glob("*.py")
        if path.name != "__init__.py"
    ]
    combined = "\n".join(texts)

    assert "personal_email_normalized" not in combined
    assert "staff_invite_portability" not in combined


def test_security_boundary_migration_hardens_invites_payup_and_recovery_codes():
    migration = (MIGRATIONS / "20260704_0027_security_boundary_hardening.py").read_text(
        encoding="utf-8"
    )

    assert 'revision = "20260704_0027"' in migration
    assert 'down_revision = "20260704_0026"' in migration
    assert "acceptance_verify_count" in migration
    assert "acceptance_verify_locked_at" in migration
    assert "ck_users_payup_daily_limit_bounds" in migration
    assert "payup_daily_limit >= 100.00" in migration
    assert "payup_daily_limit <= 10000.00" in migration
    assert "UPDATE recovery_codes SET used_at = CURRENT_TIMESTAMP" in migration
    assert "hmac_version < 2" in migration


def test_payup_nickname_registration_credit_migration_is_chained_and_fail_closed():
    migration = (MIGRATIONS / "20260705_0030_payup_nickname_registration_credit.py").read_text(
        encoding="utf-8"
    )

    assert 'revision = "20260705_0030"' in migration
    assert 'down_revision = "20260705_0029"' in migration
    assert '"payup_nickname"' in migration
    assert "String(length=128)" in migration
    assert '"registration_credits"' in migration
    assert "amount = 100.00" in migration
    assert "uq_registration_credits_user_id" in migration
    assert "credit_integrity_algorithm = 'hmac-sha256'" in migration
    assert "credit_integrity_version = 1" in migration
    assert "Downgrade would discard registration credit ledger evidence" in migration
