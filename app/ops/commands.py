from __future__ import annotations

from urllib.parse import urlparse

import click
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask import Flask
from sqlalchemy import text

from app.extensions import db
from app.security.fido_mds import validate_fido_metadata_config
from app.security.passwords import validate_common_password_dictionary, validate_password_hash_config
from app.security.session_hmac import validate_session_hmac_config
from app.ops.db_privileges import verify_runtime_database_privileges


def register_ops_commands(app: Flask) -> None:
    @app.cli.command("verify-migration-baseline")
    def verify_migration_baseline() -> None:
        """Verify an existing schema before adopting the initial revision."""

        def include_object(obj, name, type_, reflected, compare_to):
            del obj, reflected, compare_to
            return not (type_ == "table" and name == "alembic_version")

        with db.engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={
                    "compare_type": True,
                    "include_object": include_object,
                },
            )
            differences = compare_metadata(context, db.metadata)

        if differences:
            for difference in differences:
                click.echo(f"Schema difference: {difference!r}", err=True)
            raise click.ClickException(
                "Database schema does not match the migration baseline"
            )

        click.echo("Database schema matches migration baseline 20260610_0001")

    @app.cli.command("production-check")
    def production_check() -> None:
        """Validate real production dependencies and security prerequisites."""
        failures: list[str] = []

        try:
            db.session.execute(text("SELECT 1"))
        except Exception as exc:
            failures.append(f"PostgreSQL check failed: {exc}")

        try:
            app.extensions["redis"].ping()
        except Exception as exc:
            failures.append(f"Redis check failed: {exc}")

        try:
            entries = validate_common_password_dictionary()
        except Exception as exc:
            failures.append(f"Common password dictionary check failed: {exc}")
        else:
            click.echo(f"Common password dictionary entries: {entries}")
            if entries < 100000:
                failures.append("Common password dictionary must contain at least 100000 entries")

        try:
            validate_password_hash_config()
        except Exception as exc:
            failures.append(f"Password hash configuration check failed: {exc}")

        try:
            session_hmac_keys = validate_session_hmac_config()
        except Exception as exc:
            failures.append(f"Session HMAC configuration check failed: {exc}")
        else:
            click.echo(f"Configured session HMAC keys: {session_hmac_keys}")

        try:
            approved_aaguids = validate_fido_metadata_config()
        except Exception as exc:
            failures.append(f"FIDO metadata configuration check failed: {exc}")
        else:
            click.echo(f"Approved FIDO authenticator AAGUIDs: {approved_aaguids}")

        if int(app.config.get("PASSWORD_PBKDF2_ITERATIONS", 0)) < 600000:
            failures.append("PASSWORD_PBKDF2_ITERATIONS must be 600000 or higher")
        if app.config.get("APP_ENV") != "production":
            failures.append("APP_ENV must be production")
        if app.config.get("SQLALCHEMY_MIGRATION_DATABASE_URI"):
            failures.append("DATABASE_MIGRATION_URL must not be configured for the runtime app")
        if len(str(app.config.get("WTF_CSRF_SECRET_KEY", ""))) < 32:
            failures.append("WTF_CSRF_SECRET_KEY must be at least 32 characters")
        if int(app.config.get("WEBAUTHN_REQUIRED_CREDENTIALS", 0)) < 2:
            failures.append("WEBAUTHN_REQUIRED_CREDENTIALS must be at least 2")
        if int(app.config.get("TRUSTED_PROXY_COUNT", -1)) != 1:
            failures.append("TRUSTED_PROXY_COUNT must be 1 for the single Nginx proxy boundary")
        if not app.config.get("SESSION_COOKIE_SECURE"):
            failures.append("SESSION_COOKIE_SECURE must be enabled")
        if not app.config.get("SESSION_COOKIE_HTTPONLY"):
            failures.append("SESSION_COOKIE_HTTPONLY must be enabled")
        if app.config.get("SESSION_COOKIE_SAMESITE") != "Strict":
            failures.append("SESSION_COOKIE_SAMESITE must be Strict")
        if app.config.get("WTF_CSRF_ENABLED") is False:
            failures.append("WTF_CSRF_ENABLED must not be disabled")
        if app.config.get("WTF_CSRF_CHECK_DEFAULT") is False:
            failures.append("WTF_CSRF_CHECK_DEFAULT must be enabled")
        if not app.config.get("TALISMAN_FORCE_HTTPS"):
            failures.append("TALISMAN_FORCE_HTTPS must be enabled")
        if str(app.config.get("RATELIMIT_STORAGE_URI", "")).startswith("memory://"):
            failures.append("Rate limiting must use Redis-backed storage in production")
        rp_origin = str(app.config.get("WEBAUTHN_RP_ORIGIN", ""))
        rp_id = str(app.config.get("WEBAUTHN_RP_ID", ""))
        parsed_origin = urlparse(rp_origin)
        if parsed_origin.scheme != "https":
            failures.append("WEBAUTHN_RP_ORIGIN must use HTTPS")
        if parsed_origin.hostname != rp_id:
            failures.append("WEBAUTHN_RP_ORIGIN hostname must match WEBAUTHN_RP_ID")
        if int(app.config.get("TOTP_LOGIN_VALID_WINDOW", -1)) > 1:
            failures.append("TOTP_LOGIN_VALID_WINDOW must be 0 or 1")
        if int(app.config.get("TOTP_HIGH_RISK_VALID_WINDOW", -1)) != 0:
            failures.append("TOTP_HIGH_RISK_VALID_WINDOW must be 0")

        if failures:
            for failure in failures:
                click.echo(failure, err=True)
            raise click.ClickException("Production readiness checks failed")

        click.echo("Production readiness checks passed")

    @app.cli.command("verify-runtime-db-privileges")
    def verify_runtime_db_privileges() -> None:
        """Verify the runtime database role cannot mutate schema objects."""
        runtime_url = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "")
        migration_url = str(app.config.get("SQLALCHEMY_MIGRATION_DATABASE_URI") or "")
        try:
            result = verify_runtime_database_privileges(
                runtime_url=runtime_url,
                migration_url=migration_url,
            )
        except Exception as exc:
            raise click.ClickException(str(exc)) from exc

        click.echo(
            "Runtime database privilege checks passed: "
            f"runtime_role={result.runtime_role} "
            f"migration_role={result.migration_role} "
            f"probe_table={result.probe_table} "
            f"extension_probe={result.extension_probe}"
        )
