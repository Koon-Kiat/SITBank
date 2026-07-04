from __future__ import annotations

import hmac
import json
import os
import stat as stat_module
from datetime import datetime, timezone
from pathlib import Path

import click
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask import Flask
from flask_migrate import upgrade as upgrade_database
from sqlalchemy import MetaData, and_, column, create_engine, func, select, table

from app.admin.bootstrap_root import RootAdminBootstrapError, bootstrap_root_admin
from app.extensions import db
from app.models import User
from app.security.alerts import (
    build_security_alert_report,
    deliver_security_alerts,
    rebaseline_database_integrity_state,
)
from app.security.audit import (
    AuditWriteError,
    audit_log_anchor,
    audit_system_event,
    audit_system_event_required,
    refresh_audit_log_anchor,
    verify_audit_hash_chain,
    write_audit_log_anchor,
)
from app.security.crypto import (
    is_enveloped_mfa_secret,
    mfa_envelope_kek_id,
    rewrap_mfa_dek,
)
from app.security.production_guard import validate_production_security_prerequisites
from app.ops.db_privileges import (
    apply_admin_runtime_database_privileges,
    apply_runtime_audit_table_privileges,
    verify_runtime_database_privileges,
)


# Click command declarations are intentionally colocated registration metadata.
def register_ops_commands(app: Flask) -> None:  # NOSONAR
    @app.cli.group("admin")
    def admin_cli() -> None:
        """Admin-only management commands."""

    @app.cli.group("security")
    def security_cli() -> None:
        """Security and privacy operations commands."""

    @admin_cli.command("bootstrap-root")
    @click.option(
        "--email",
        "workplace_email",
        prompt="Root admin workplace email",
        help="Allowlisted workplace email from ROOT_ADMIN_EMAILS.",
    )
    @click.option(
        "--username",
        prompt="Username",
        help="Root admin username to create or set.",
    )
    @click.option(
        "--full-name",
        prompt="Full name",
        help="Root admin display name.",
    )
    @click.option(
        "--reset-existing",
        is_flag=True,
        help="Rotate password and TOTP for an existing allowlisted root admin.",
    )
    def bootstrap_root_admin_command(
        workplace_email: str,
        username: str,
        full_name: str,
        reset_existing: bool,
    ) -> None:
        """Create the first allowlisted root admin from the server shell."""

        password = click.prompt(
            "Root admin password",
            hide_input=True,
            confirmation_prompt=True,
        )
        try:
            result = bootstrap_root_admin(
                workplace_email=workplace_email,
                username=username,
                full_name=full_name,
                password=password,
                reset_existing=reset_existing,
            )
        except RootAdminBootstrapError as exc:
            raise click.ClickException(str(exc)) from exc

        action = "created" if result.created else "updated"
        click.echo(f"Root admin account {action}: {result.workplace_email}")
        click.echo("")
        click.secho(
            "ONE-TIME SENSITIVE TOTP SETUP OUTPUT",
            fg="yellow",
            bold=True,
            err=True,
        )
        click.echo("Add this account to an authenticator app now. Do not store this output in logs, tickets, or chat.")
        click.echo(f"Manual entry secret: {result.manual_entry_secret}")
        click.echo(f"Provisioning URI: {result.otpauth_uri}")
        click.echo("")
        click.echo("The password was accepted from a hidden prompt and was not printed.")

    @app.cli.command("verify-migration-baseline")
    def verify_migration_baseline() -> None:
        """Verify the current database schema matches SQLAlchemy metadata."""

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

        click.echo("Database schema matches current migration metadata")

    @app.cli.command("reset-demo-database")
    @click.option(
        "--target",
        type=click.Choice(["staging", "production"], case_sensitive=True),
        required=True,
    )
    @click.option("--execute", is_flag=True, help="Apply the destructive reset after preflight.")
    @click.option("--confirm", help="Exact environment-specific destructive confirmation phrase.")
    @click.option(
        "--disposable-data-confirmed",
        is_flag=True,
        help="Confirm that the target contains only disposable project/demo data.",
    )
    @click.option(
        "--staging-verified",
        is_flag=True,
        help="Confirm the equivalent reset completed and was verified in staging.",
    )
    @click.option(
        "--approved",
        is_flag=True,
        help="Confirm the required manual production approval was obtained.",
    )
    @click.option(
        "--backup-file",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Fresh encrypted production backup created by sitbank-backup-encrypted.",
    )
    def reset_demo_database_command(
        target: str,
        execute: bool,
        confirm: str | None,
        disposable_data_confirmed: bool,
        staging_verified: bool,
        approved: bool,
        backup_file: Path | None,
    ) -> None:
        """Destructively recreate an explicitly disposable staging/production DB."""

        _validate_demo_reset_preflight(
            app,
            target=target,
            execute=execute,
            confirm=confirm,
            disposable_data_confirmed=disposable_data_confirmed,
            staging_verified=staging_verified,
            approved=approved,
            backup_file=backup_file,
        )
        if not execute:
            click.echo(
                f"Demo database reset preflight passed: target={target} execute=false"
            )
            return

        migration_url = str(
            app.config.get("SQLALCHEMY_MIGRATION_DATABASE_URI") or ""
        )
        engine = create_engine(migration_url)
        try:
            metadata = MetaData()
            metadata.reflect(bind=engine)
            metadata.drop_all(bind=engine)
        finally:
            engine.dispose()

        upgrade_database()
        malformed = _malformed_account_number_count(db.engine)
        if malformed:
            raise click.ClickException(
                "Reset verification failed: malformed account numbers remain"
            )
        click.echo(
            f"Demo database reset completed: target={target} "
            "schema=current malformed_account_numbers=0"
        )

    @app.cli.command("production-check")
    def production_check() -> None:
        """Validate real production dependencies and security prerequisites."""
        app_mode = str(app.config.get("APP_MODE") or "customer")
        result = validate_production_security_prerequisites(app, app_mode=app_mode)

        for name, value in sorted(result.details.items()):
            click.echo(f"{name}: {value}")
        if result.failures:
            for failure in result.failures:
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
                audit_hmac_key=str(app.config.get("SECURITY_AUDIT_HMAC_KEY") or ""),
            )
        except Exception as exc:
            _deliver_ops_failure_alert(
                "runtime_db_privilege_verification_failed",
                "verify-runtime-db-privileges",
                exc,
            )
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
            _deliver_ops_failure_alert(
                "audit_append_only_protection_failed",
                "apply-runtime-db-privileges",
                exc,
            )
            raise click.ClickException(str(exc)) from exc

        click.echo(
            "Runtime database privilege application passed: "
            f"runtime_role={result.runtime_role} "
            f"migration_role={result.migration_role} "
            f"audit_table={result.audit_table} "
            "audit_update_delete_truncate=revoked"
        )

    @app.cli.command("apply-admin-runtime-db-privileges")
    def apply_admin_runtime_db_privileges() -> None:
        """Create/update the admin runtime role and grant fail-closed DB access."""
        migration_url = str(app.config.get("SQLALCHEMY_MIGRATION_DATABASE_URI") or "")
        try:
            result = apply_admin_runtime_database_privileges(
                admin_url=_env_or_file("ADMIN_DATABASE_URL"),
                migration_url=migration_url,
            )
        except Exception as exc:
            _deliver_ops_failure_alert(
                "admin_runtime_db_privilege_application_failed",
                "apply-admin-runtime-db-privileges",
                exc,
            )
            raise click.ClickException(str(exc)) from exc

        click.echo(
            "Admin runtime database privilege application passed: "
            f"admin_role={result.admin_role} "
            f"migration_role={result.migration_role} "
            f"database={result.database} "
            f"schema={result.schema}"
        )

    @app.cli.command("verify-audit-log-chain")
    @click.option(
        "--anchor",
        "anchor_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Sanitized anchor JSON to compare against the current chain head.",
    )
    @click.option(
        "--alert-on-failure",
        is_flag=True,
        help="Send the configured security alert webhook when verification fails.",
    )
    def verify_audit_log_chain(anchor_path: Path | None, alert_on_failure: bool) -> None:
        """Verify the tamper-evident security audit hash chain."""
        if anchor_path is None:
            configured_anchor_path = str(app.config.get("SECURITY_AUDIT_ANCHOR_PATH") or "").strip()
            anchor_path = Path(configured_anchor_path) if configured_anchor_path else None
        anchor = _load_audit_anchor(anchor_path) if anchor_path is not None else None
        result = verify_audit_hash_chain(anchor=anchor)
        if not result["valid"] and alert_on_failure:
            result["alert_delivery"] = deliver_security_alerts(
                [_audit_chain_failure_alert(result)]
            )
        click.echo(json.dumps(result, separators=(",", ":"), sort_keys=True))
        if not result["valid"]:
            raise click.ClickException("Security audit hash chain verification failed")

    @app.cli.command("export-audit-log-anchor")
    @click.option(
        "--output",
        "output_path",
        type=click.Path(dir_okay=False, path_type=Path),
        help="Path for the sanitized anchor JSON. Defaults to SECURITY_AUDIT_ANCHOR_PATH when configured.",
    )
    def export_audit_log_anchor(output_path: Path | None) -> None:
        """Export a sanitized anchor for the current audit hash-chain head."""
        if output_path is None:
            configured_anchor_path = str(app.config.get("SECURITY_AUDIT_ANCHOR_PATH") or "").strip()
            output_path = Path(configured_anchor_path) if configured_anchor_path else None
        anchor = write_audit_log_anchor(output_path) if output_path is not None else audit_log_anchor()
        payload = json.dumps(anchor, separators=(",", ":"), sort_keys=True)
        click.echo(payload)

    @app.cli.command("refresh-audit-log-anchor")
    def refresh_audit_log_anchor_command() -> None:
        """Refresh a configured anchor after fail-closed chain validation."""
        configured_path = str(
            app.config.get("SECURITY_AUDIT_ANCHOR_PATH") or ""
        ).strip()
        if not configured_path:
            raise click.ClickException("SECURITY_AUDIT_ANCHOR_PATH is required")
        try:
            result = refresh_audit_log_anchor(Path(configured_path))
        except Exception as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo(json.dumps(result, separators=(",", ":"), sort_keys=True))

    @app.cli.command("rebaseline-security-alert-state")
    @click.option(
        "--intentional-reset",
        is_flag=True,
        help="Acknowledge that the current database state is an approved reset.",
    )
    @click.option(
        "--reason",
        required=True,
        help="Non-empty operator reason; only a keyed reference and length are retained.",
    )
    def rebaseline_security_alert_state_command(
        intentional_reset: bool,
        reason: str,
    ) -> None:
        """Safely replace database-regression state after an approved reset."""
        try:
            result = rebaseline_database_integrity_state(
                intentional_reset=intentional_reset,
                reason=reason,
            )
        except Exception as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo(json.dumps(result, separators=(",", ":"), sort_keys=True))

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

    @app.cli.command("expire-manual-recovery-requests")
    @click.option("--limit", type=int, default=None, help="Maximum number of stale requests to expire.")
    def expire_manual_recovery_requests_command(limit: int | None) -> None:
        """Expire stale manual account recovery requests."""
        from app.auth.password_reset import expire_manual_recovery_requests

        expired_count = expire_manual_recovery_requests(limit=limit)
        click.echo(json.dumps({"expired_count": expired_count}, separators=(",", ":"), sort_keys=True))

    @app.cli.command("cleanup-security-state")
    @click.option("--limit", type=int, default=None, help="Maximum rows per state table to clean.")
    @click.option(
        "--confirm",
        is_flag=True,
        help="Apply cleanup. Without this flag the compatibility command is dry-run only.",
    )
    def cleanup_security_state_command(limit: int | None, confirm: bool) -> None:
        """Compatibility wrapper for confirm-gated retention cleanup."""
        result = _run_audited_retention_cleanup(limit=limit, confirm=confirm)
        click.echo(json.dumps(result, separators=(",", ":"), sort_keys=True))

    @security_cli.command("run-retention-cleanup")
    @click.option(
        "--limit",
        type=int,
        default=None,
        help="Maximum rows per approved state table.",
    )
    @click.option(
        "--confirm",
        is_flag=True,
        help="Apply the cleanup. Without this flag the command is a dry-run.",
    )
    def run_retention_cleanup_command(limit: int | None, confirm: bool) -> None:
        """Review or apply approved temporary security-state retention cleanup."""
        result = _run_audited_retention_cleanup(limit=limit, confirm=confirm)
        click.echo(json.dumps(result, separators=(",", ":"), sort_keys=True))

    def _run_audited_retention_cleanup(
        *,
        limit: int | None,
        confirm: bool,
    ) -> dict:
        from app.security.retention import RetentionCleanupError, run_retention_cleanup

        requested_metadata = {
            "mode": "confirmed" if confirm else "dry_run",
            "dry_run": not confirm,
            "batch_limit_requested": limit,
        }
        if confirm:
            try:
                audit_system_event_required(
                    "retention_cleanup",
                    "started",
                    metadata=requested_metadata,
                )
            except AuditWriteError as exc:
                raise click.ClickException(
                    "Retention cleanup refused because audit evidence is unavailable"
                ) from exc
        try:
            result = run_retention_cleanup(
                limit=limit,
                dry_run=not confirm,
                confirm=confirm,
            )
        except RetentionCleanupError as exc:
            if confirm:
                audit_system_event(
                    "retention_cleanup",
                    "failed",
                    metadata={
                        **requested_metadata,
                        "error_type": type(exc).__name__,
                    },
                )
            raise click.ClickException(str(exc)) from exc

        completed_metadata = {
            "mode": result["mode"],
            "dry_run": result["dry_run"],
            "retention_days": result["retention_days"],
            "batch_limit": result["batch_limit"],
            "category_counts": result["category_counts"],
            "scheduling": result["scheduling"],
        }
        if confirm:
            try:
                audit_system_event_required(
                    "retention_cleanup",
                    "completed",
                    metadata=completed_metadata,
                )
            except AuditWriteError as exc:
                raise click.ClickException(
                    "Retention cleanup completed with started audit evidence, "
                    "but completion evidence failed"
                ) from exc
        else:
            audit_system_event(
                "retention_cleanup",
                "dry_run",
                metadata=completed_metadata,
            )
        return result

    @app.cli.command("rewrap-mfa-deks")
    @click.option("--from-kek-id", required=True, help="Existing KEK id wrapping the target DEKs.")
    @click.option("--to-kek-id", required=True, help="Configured KEK id to rewrap matching DEKs under.")
    @click.option("--dry-run", is_flag=True, help="Validate and report without writing changes.")
    def rewrap_mfa_deks(from_kek_id: str, to_kek_id: str, dry_run: bool) -> None:
        """Rewrap envelope DEKs without re-encrypting TOTP secret ciphertext."""

        _validate_mfa_rewrap_preflight(app, from_kek_id, to_kek_id, dry_run)
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
            db.select(User)
            .where(
                User.mfa_secret_nonce.is_not(None),
                User.mfa_secret_ciphertext.is_not(None),
            )
            .order_by(User.id.asc())
        ).scalars()
    )


def _validate_demo_reset_preflight(
    app: Flask,
    *,
    target: str,
    execute: bool,
    confirm: str | None,
    disposable_data_confirmed: bool,
    staging_verified: bool,
    approved: bool,
    backup_file: Path | None,
) -> None:
    configured_target = str(
        app.config.get("DEPLOYMENT_TARGET") or ""
    ).strip().casefold()
    if configured_target != target:
        raise click.ClickException(
            "Reset target does not match DEPLOYMENT_TARGET"
        )
    if not app.config.get("SQLALCHEMY_MIGRATION_DATABASE_URI"):
        raise click.ClickException(
            "DATABASE_MIGRATION_URL or DATABASE_MIGRATION_URL_FILE is required"
        )
    if not disposable_data_confirmed:
        raise click.ClickException(
            "Refusing reset without --disposable-data-confirmed"
        )
    if not execute:
        return

    expected_confirmation = f"RESET {target.upper()} DEMO DATABASE"
    if not hmac.compare_digest(str(confirm or ""), expected_confirmation):
        raise click.ClickException(
            f"Confirmation must exactly match: {expected_confirmation}"
        )
    if target == "staging":
        return
    if not staging_verified:
        raise click.ClickException(
            "Production reset requires --staging-verified"
        )
    if not approved:
        raise click.ClickException("Production reset requires --approved")
    _validate_fresh_encrypted_backup(backup_file)


def _validate_fresh_encrypted_backup(backup_file: Path | None) -> None:
    if backup_file is None:
        raise click.ClickException(
            "Production reset requires --backup-file"
        )
    if backup_file.is_symlink() or not backup_file.is_file():
        raise click.ClickException(
            "Production backup must be a regular non-symlink file"
        )
    resolved_backup = backup_file.resolve(strict=True)
    workspace_roots = [Path.cwd().resolve()]
    workspace_roots.extend(
        Path(value).resolve()
        for name in ("GITHUB_WORKSPACE", "RUNNER_WORKSPACE")
        if (value := os.environ.get(name))
    )
    if any(resolved_backup.is_relative_to(root) for root in workspace_roots):
        raise click.ClickException(
            "Production backup must not be stored inside a repository or CI workspace"
        )
    if not backup_file.name.endswith(".pgdump.age"):
        raise click.ClickException(
            "Production backup must be an encrypted .pgdump.age file"
        )
    if "production" not in backup_file.name.casefold():
        raise click.ClickException(
            "Production backup filename must identify the production target"
        )
    file_stat = backup_file.stat()
    if file_stat.st_size <= 0:
        raise click.ClickException("Production backup must not be empty")
    if os.name == "posix" and stat_module.S_IMODE(file_stat.st_mode) & 0o077:
        raise click.ClickException(
            "Production backup must not grant group or other permissions"
        )
    age_seconds = datetime.now(timezone.utc).timestamp() - file_stat.st_mtime
    if age_seconds < 0 or age_seconds > 24 * 60 * 60:
        raise click.ClickException(
            "Production backup must have been created within the last 24 hours"
        )


def _malformed_account_number_count(engine) -> int:
    users = table("users", column("account_number"))
    payees = table("payees", column("account_number"))

    def format_is_current(column):
        return and_(
            func.length(column) == 12,
            *[
                func.substr(column, position, 1).between("0", "9")
                for position in range(1, 13)
            ],
        )

    malformed_users = select(func.count()).select_from(users).where(
        users.c.account_number.is_not(None),
        ~format_is_current(users.c.account_number),
    )
    malformed_payees = select(func.count()).select_from(payees).where(
        ~format_is_current(payees.c.account_number),
    )
    with engine.connect() as connection:
        user_count = int(connection.execute(malformed_users).scalar_one() or 0)
        payee_count = int(connection.execute(malformed_payees).scalar_one() or 0)
    return user_count + payee_count


def _validate_mfa_rewrap_preflight(
    app: Flask,
    from_kek_id: str,
    to_kek_id: str,
    dry_run: bool,
) -> None:
    keys = app.config.get("MFA_KEK_KEYS")
    reason: str | None = None
    message: str | None = None
    if from_kek_id == to_kek_id:
        reason = "same_kek_id"
        message = "from-kek-id and to-kek-id must be different"
    elif not isinstance(keys, dict) or not keys:
        reason = "missing_keyring"
        message = "MFA KEK keyring is not configured"
    elif from_kek_id not in keys:
        reason = "missing_source_kek"
        message = (
            "Source MFA KEK id is not configured; keep the old KEK in "
            "MFA_KEK_KEYS_JSON until stored DEKs are rewrapped"
        )
    elif to_kek_id not in keys:
        reason = "missing_target_kek"
        message = (
            "Target MFA KEK id is not configured; add the new KEK id to "
            "MFA_KEK_KEYS_JSON before running rewrap-mfa-deks"
        )
    if message is None:
        return

    audit_system_event(
        "mfa_dek_rewrap",
        "failure",
        metadata={
            "from_kek_id": from_kek_id,
            "to_kek_id": to_kek_id,
            "dry_run": dry_run,
            "reason": reason,
            "stage": "preflight",
        },
    )
    raise click.ClickException(message)


def _utc_iso_or_none(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _aware_utc(value).isoformat()


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _load_audit_anchor(anchor_path: Path) -> dict:
    try:
        anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise click.ClickException(f"Audit anchor could not be read: {type(exc).__name__}") from exc
    if not isinstance(anchor, dict):
        raise click.ClickException("Audit anchor must be a JSON object")
    return anchor


def _env_or_file(name: str) -> str:
    value = os.getenv(name)
    file_path = os.getenv(f"{name}_FILE")
    if value and file_path:
        raise click.ClickException(f"{name} and {name}_FILE must not both be configured")
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    if value:
        return value
    raise click.ClickException(f"{name} or {name}_FILE is required")


def _audit_chain_failure_alert(result: dict) -> dict:
    alert_type = (
        "audit_anchor_mismatch"
        if result.get("anchor_errors")
        else "audit_chain_verification_failed"
    )
    return {
        "alert_type": alert_type,
        "severity": "critical",
        "count": max(1, len(result.get("errors", []))),
        "window_seconds": 0,
        "source": "verify-audit-log-chain",
        "latest_event_id": result.get("latest_event_id"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _deliver_ops_failure_alert(alert_type: str, source: str, exc: Exception) -> None:
    deliver_security_alerts(
        [
            {
                "alert_type": alert_type,
                "severity": "critical",
                "count": 1,
                "window_seconds": 0,
                "source": source,
                "error_type": type(exc).__name__,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
        ]
    )
