from __future__ import annotations

import os
from datetime import datetime, timezone

import click
import pytest

from app.ops.commands import (
    _malformed_account_number_count,
    _validate_demo_reset_preflight,
    _validate_fresh_encrypted_backup,
)


def _configure_reset_target(app, target: str) -> None:
    app.config.update(
        DEPLOYMENT_TARGET=target,
        SQLALCHEMY_MIGRATION_DATABASE_URI="postgresql://migration.invalid/sitbank_db",
    )


def test_staging_reset_preflight_requires_disposable_data_and_exact_confirmation(app):
    _configure_reset_target(app, "staging")

    with pytest.raises(click.ClickException, match="disposable"):
        _validate_demo_reset_preflight(
            app,
            target="staging",
            execute=True,
            confirm="RESET STAGING DEMO DATABASE",
            disposable_data_confirmed=False,
            staging_verified=False,
            approved=False,
            backup_file=None,
        )
    with pytest.raises(click.ClickException, match="exactly match"):
        _validate_demo_reset_preflight(
            app,
            target="staging",
            execute=True,
            confirm="reset staging demo database",
            disposable_data_confirmed=True,
            staging_verified=False,
            approved=False,
            backup_file=None,
        )


def test_production_reset_requires_staging_approval_and_fresh_encrypted_backup(
    app,
    tmp_path,
):
    _configure_reset_target(app, "production")
    backup = tmp_path / "sitbank-production-sitbank_db-20260704T010203Z.pgdump.age"
    backup.write_bytes(b"clearly-fake-encrypted-backup")
    backup.chmod(0o600)
    fresh_timestamp = datetime.now(timezone.utc).timestamp()
    os.utime(backup, (fresh_timestamp, fresh_timestamp))

    for overrides, expected in (
        ({"staging_verified": False}, "staging-verified"),
        ({"approved": False}, "approved"),
        ({"backup_file": None}, "backup-file"),
    ):
        arguments = {
            "target": "production",
            "execute": True,
            "confirm": "RESET PRODUCTION DEMO DATABASE",
            "disposable_data_confirmed": True,
            "staging_verified": True,
            "approved": True,
            "backup_file": backup,
        }
        arguments.update(overrides)
        with pytest.raises(click.ClickException, match=expected):
            _validate_demo_reset_preflight(app, **arguments)

    _validate_demo_reset_preflight(
        app,
        target="production",
        execute=True,
        confirm="RESET PRODUCTION DEMO DATABASE",
        disposable_data_confirmed=True,
        staging_verified=True,
        approved=True,
        backup_file=backup,
    )


def test_production_backup_validation_rejects_wrong_type_target_and_age(
    tmp_path,
):
    wrong_suffix = tmp_path / "sitbank-production.sql"
    wrong_suffix.write_bytes(b"fake")
    wrong_suffix.chmod(0o600)
    with pytest.raises(click.ClickException, match=r"\.pgdump\.age"):
        _validate_fresh_encrypted_backup(wrong_suffix)

    wrong_target = tmp_path / "sitbank-staging-sitbank_db.pgdump.age"
    wrong_target.write_bytes(b"fake")
    wrong_target.chmod(0o600)
    with pytest.raises(click.ClickException, match="production target"):
        _validate_fresh_encrypted_backup(wrong_target)

    stale = tmp_path / "sitbank-production-sitbank_db-stale.pgdump.age"
    stale.write_bytes(b"fake")
    stale.chmod(0o600)
    stale_timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    stale.touch()
    os.utime(stale, (stale_timestamp, stale_timestamp))
    with pytest.raises(click.ClickException, match="last 24 hours"):
        _validate_fresh_encrypted_backup(stale)


def test_reset_cli_dry_run_never_drops_schema(app):
    _configure_reset_target(app, "staging")

    result = app.test_cli_runner().invoke(
        args=[
            "reset-demo-database",
            "--target",
            "staging",
            "--disposable-data-confirmed",
        ]
    )

    assert result.exit_code == 0
    assert result.output.strip() == (
        "Demo database reset preflight passed: target=staging execute=false"
    )


def test_reset_cli_executes_drop_upgrade_and_current_schema_verification(
    app,
    monkeypatch,
):
    from app.ops import commands

    _configure_reset_target(app, "staging")
    events: list[object] = []

    class FakeEngine:
        def dispose(self):
            events.append("dispose")

    class FakeMetadata:
        def reflect(self, *, bind):
            events.append(("reflect", bind))

        def drop_all(self, *, bind):
            events.append(("drop_all", bind))

    engine = FakeEngine()
    monkeypatch.setattr(
        commands,
        "create_engine",
        lambda url: events.append(url) or engine,
    )
    monkeypatch.setattr(commands, "MetaData", FakeMetadata)
    monkeypatch.setattr(commands, "upgrade_database", lambda: events.append("upgrade"))
    monkeypatch.setattr(
        commands,
        "_malformed_account_number_count",
        lambda _engine: events.append("verify") or 0,
    )

    result = app.test_cli_runner().invoke(
        args=[
            "reset-demo-database",
            "--target",
            "staging",
            "--execute",
            "--disposable-data-confirmed",
            "--confirm",
            "RESET STAGING DEMO DATABASE",
        ]
    )

    assert result.exit_code == 0
    assert events == [
        "postgresql://migration.invalid/sitbank_db",
        ("reflect", engine),
        ("drop_all", engine),
        "dispose",
        "upgrade",
        "verify",
    ]
    assert "schema=current malformed_account_numbers=0" in result.output


def test_reset_schema_verifier_accepts_empty_current_schema(app):
    from app.extensions import db

    assert _malformed_account_number_count(db.engine) == 0
