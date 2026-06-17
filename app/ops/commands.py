from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import click
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask import Flask
from sqlalchemy import text

from app.extensions import db
from app.models import User
from app.security.alerts import build_security_alert_report
from app.security.audit import audit_log_anchor, audit_system_event, verify_audit_hash_chain
from app.security.crypto import (
    is_enveloped_mfa_secret,
    mfa_envelope_kek_id,
    rewrap_mfa_dek,
)
from app.security.fido_mds import validate_fido_metadata_config
from app.security.passwords import validate_common_password_dictionary, validate_password_hash_config
from app.security.session_hmac import validate_session_hmac_config
from app.ops.db_privileges import apply_runtime_audit_table_privileges, verify_runtime_database_privileges


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

        mfa_kek_keys = app.config.get("MFA_KEK_KEYS")
        mfa_kek_active_id = app.config.get("MFA_KEK_ACTIVE_ID")
        if not isinstance(mfa_kek_keys, dict) or not mfa_kek_keys:
            failures.append("MFA_KEK_KEYS_JSON must configure at least one MFA KEK")
        elif mfa_kek_active_id not in mfa_kek_keys:
            failures.append("MFA_KEK_ACTIVE_ID must identify a configured MFA KEK")
        else:
            click.echo(f"Configured MFA KEKs: {len(mfa_kek_keys)}")

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
            f"audit_table={result.audit_table} "
            f"extension_probe={result.extension_probe}"
        )

    @app.cli.command("apply-runtime-db-privileges")
    def apply_runtime_db_privileges() -> None:
        """Apply runtime database grants that are narrower than default table DML."""
        runtime_url = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "")
        migration_url = str(app.config.get("SQLALCHEMY_MIGRATION_DATABASE_URI") or "")
        try:
            result = apply_runtime_audit_table_privileges(
                runtime_url=runtime_url,
                migration_url=migration_url,
            )
        except Exception as exc:
            raise click.ClickException(str(exc)) from exc

        click.echo(
            "Runtime database privilege application passed: "
            f"runtime_role={result.runtime_role} "
            f"migration_role={result.migration_role} "
            f"audit_table={result.audit_table} "
            "audit_update_delete=revoked"
        )

    @app.cli.command("verify-audit-log-chain")
    def verify_audit_log_chain() -> None:
        """Verify the tamper-evident security audit hash chain."""
        result = verify_audit_hash_chain()
        click.echo(json.dumps(result, separators=(",", ":"), sort_keys=True))
        if not result["valid"]:
            raise click.ClickException("Security audit hash chain verification failed")

    @app.cli.command("export-audit-log-anchor")
    @click.option(
        "--output",
        "output_path",
        type=click.Path(dir_okay=False, path_type=Path),
        help="Optional path for the sanitized anchor JSON.",
    )
    def export_audit_log_anchor(output_path: Path | None) -> None:
        """Export a sanitized anchor for the current audit hash-chain head."""
        anchor = audit_log_anchor()
        payload = json.dumps(anchor, separators=(",", ":"), sort_keys=True)
        if output_path is not None:
            output_path.write_text(payload + "\n", encoding="utf-8")
        click.echo(payload)

    @app.cli.command("check-security-alerts")
    @click.option("--report-only", is_flag=True, help="Exit zero even when active alerts are found.")
    @click.option("--no-delivery", is_flag=True, help="Skip configured webhook delivery and only print JSON.")
    def check_security_alerts(report_only: bool, no_delivery: bool) -> None:
        """Evaluate recent audit events against security alert thresholds."""
        report = build_security_alert_report(deliver=not no_delivery)
        click.echo(json.dumps(report, separators=(",", ":"), sort_keys=True))
        if report.get("alert_count", 0) and not report_only:
            raise click.ClickException("Security alerts active")
        delivery = report.get("delivery", {})
        if delivery.get("attempted") and delivery.get("delivered") is False and not report_only:
            raise click.ClickException("Security alert delivery failed")

    @app.cli.command("rewrap-mfa-deks")
    @click.option("--from-kek-id", required=True, help="Existing KEK id wrapping the target DEKs.")
    @click.option("--to-kek-id", required=True, help="Configured KEK id to rewrap matching DEKs under.")
    @click.option("--dry-run", is_flag=True, help="Validate and report without writing changes.")
    def rewrap_mfa_deks(from_kek_id: str, to_kek_id: str, dry_run: bool) -> None:
        """Rewrap envelope DEKs without re-encrypting TOTP secret ciphertext."""

        if from_kek_id == to_kek_id:
            raise click.ClickException("from-kek-id and to-kek-id must be different")
        if from_kek_id not in app.config["MFA_KEK_KEYS"]:
            raise click.ClickException("Source MFA KEK id is not configured")
        if to_kek_id not in app.config["MFA_KEK_KEYS"]:
            raise click.ClickException("Target MFA KEK id is not configured")
        audit_system_event(
            "mfa_dek_rewrap",
            "started",
            metadata={"from_kek_id": from_kek_id, "to_kek_id": to_kek_id, "dry_run": dry_run},
        )

        scanned = 0
        updated = 0
        skipped_legacy = 0
        skipped_other_kek = 0
        failures = 0
        try:
            users = _users_with_mfa_secret()
            for user in users:
                scanned += 1
                try:
                    if not is_enveloped_mfa_secret(
                        user.mfa_secret_nonce,
                        user.mfa_secret_ciphertext,
                    ):
                        skipped_legacy += 1
                        continue
                    current_kek_id = mfa_envelope_kek_id(
                        user.mfa_secret_nonce,
                        user.mfa_secret_ciphertext,
                    )
                    if current_kek_id != from_kek_id:
                        skipped_other_kek += 1
                        continue
                    if not dry_run:
                        user.mfa_secret_nonce, user.mfa_secret_ciphertext = rewrap_mfa_dek(
                            user.mfa_secret_nonce,
                            user.mfa_secret_ciphertext,
                            user.id,
                            from_kek_id=from_kek_id,
                            to_kek_id=to_kek_id,
                        )
                    updated += 1
                except Exception:
                    failures += 1

            if failures:
                db.session.rollback()
                raise click.ClickException("MFA DEK rewrap failed; no changes were committed")
            if dry_run:
                db.session.rollback()
            else:
                db.session.commit()
        except Exception as exc:
            db.session.rollback()
            audit_system_event(
                "mfa_dek_rewrap",
                "failure",
                metadata={
                    "from_kek_id": from_kek_id,
                    "to_kek_id": to_kek_id,
                    "dry_run": dry_run,
                    "scanned": scanned,
                    "updated": updated,
                    "skipped_legacy": skipped_legacy,
                    "skipped_other_kek": skipped_other_kek,
                    "failures": failures,
                    "reason": type(exc).__name__,
                },
            )
            if isinstance(exc, click.ClickException):
                raise
            raise click.ClickException("MFA DEK rewrap failed") from exc

        audit_system_event(
            "mfa_dek_rewrap",
            "success",
            metadata={
                "from_kek_id": from_kek_id,
                "to_kek_id": to_kek_id,
                "dry_run": dry_run,
                "scanned": scanned,
                "updated": updated,
                "skipped_legacy": skipped_legacy,
                "skipped_other_kek": skipped_other_kek,
                "failures": failures,
            },
        )
        click.echo(
            "MFA DEK rewrap complete: "
            f"scanned={scanned} updated={updated} skipped_legacy={skipped_legacy} "
            f"skipped_other_kek={skipped_other_kek} failures={failures} dry_run={dry_run}"
        )


def _users_with_mfa_secret() -> list[User]:
    return list(
        db.session.execute(
            db.select(User).where(
                User.mfa_secret_nonce.is_not(None),
                User.mfa_secret_ciphertext.is_not(None),
            )
        ).scalars()
    )
