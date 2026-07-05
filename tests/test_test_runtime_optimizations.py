from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.extensions import db
from app.models import AuthAttemptCounter, User
from conftest import _restore_test_app_state


def test_admin_worker_fixture_resets_database_rate_state_outbox_and_config(
    admin_app,
):
    baseline = copy.deepcopy(dict(admin_app.config))
    now = datetime.now(timezone.utc)
    user = User(
        username="fixture-isolation",
        email="fixture.isolation@sit.singaporetech.edu.sg",
        password_hash="clearly-fake-test-hash",
        account_type="staff",
        account_status="active",
        full_name="Fixture Isolation",
        phone_number="89990001",
        workplace_email_verified_at=now,
        mfa_enabled=True,
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(
        AuthAttemptCounter(
            scope="fixture_isolation",
            principal_hash="a" * 64,
            failure_count=1,
            window_started_at=now,
            window_expires_at=now + timedelta(minutes=5),
            created_at=now,
            updated_at=now,
        )
    )
    db.session.commit()
    admin_app.config["FIXTURE_ISOLATION_MUTATION"] = "must-reset"
    admin_app.extensions["password_reset_outbox"].append(
        {"subject": "clearly fake", "body": "clearly fake"}
    )

    _restore_test_app_state(admin_app, baseline)

    assert db.session.query(User).count() == 0
    assert db.session.query(AuthAttemptCounter).count() == 0
    assert "FIXTURE_ISOLATION_MUTATION" not in admin_app.config
    assert admin_app.extensions["password_reset_outbox"] == []


def test_unit_totp_helpers_are_deterministic_and_do_not_sleep():
    for path in (
        Path("tests/test_admin_staff_invites.py"),
        Path("tests/test_admin_maker_checker.py"),
        Path("tests/test_admin_dashboard_operations.py"),
    ):
        source = path.read_text(encoding="utf-8")
        assert "app.auth.services.time.time" in source
        assert "time.sleep(" not in source
        assert ".at(_FIXED_TOTP_TIME)" in source


def test_full_suite_commands_remain_unscoped():
    workflow = Path(".github/workflows/ci-deploy.yml").read_text(
        encoding="utf-8"
    )
    local_runner = Path("scripts/ci-local").read_text(encoding="utf-8")
    for source in (workflow, local_runner):
        assert "-m 'not security'" not in source
        assert '-m "not security"' not in source
        assert "--ignore=tests" not in source
    assert "pytest -q -n auto" in workflow
