from __future__ import annotations

import subprocess
from pathlib import Path

from app import create_app
from conftest import TestConfig


BACKUP_SCRIPT = Path("ops/backups/sitbank-backup-encrypted")
RESTORE_PREFLIGHT = Path("ops/backups/sitbank-restore-preflight")
CUTOVER_SCRIPT = Path("ops/deploy/sitbank-database-cutover")
BOOTSTRAP_SCRIPT = Path("ops/deploy/bootstrap-container-ec2")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _tracked_files() -> list[str]:
    return subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        text=True,
    ).splitlines()


def test_encrypted_backup_script_exists_and_uses_recipient_encryption():
    backup = _text(BACKUP_SCRIPT)

    assert backup.startswith("#!/usr/bin/env bash")
    assert "set -Eeuo pipefail" in backup
    assert "pg_dump --format=custom" in backup
    assert "age --recipients-file" in backup
    assert "SITBANK_BACKUP_AGE_RECIPIENTS_FILE" in backup
    assert "recipients file must contain public recipients only" in backup
    assert "AGE-SECRET-KEY" in backup
    assert "encrypted_backup_created" in backup


def test_backup_script_keeps_plaintext_temporary_and_removes_it():
    backup = _text(BACKUP_SCRIPT)

    assert "temporary_dir=\"$(mktemp -d" in backup
    assert "chmod 0700 \"${temporary_dir}\"" in backup
    assert "temporary_dump=\"${temporary_dir}/database.pgdump\"" in backup
    assert "trap cleanup EXIT" in backup
    assert "rm -f -- \"${temporary_dump:-}\"" in backup
    assert "rm -f -- \"${temporary_dump}\"" in backup
    assert "install -o root -g root -m 0600 \"${temporary_encrypted}\" \"${destination}\"" in backup
    assert ".pgdump.age" in backup
    assert "database-${timestamp}.dump" not in backup


def test_backup_script_does_not_print_database_passwords_or_embed_private_keys():
    backup = _text(BACKUP_SCRIPT)
    private_age_marker = "AGE-SECRET" + "-KEY-"
    private_pgp_marker = "BEGIN PGP " + "PRIVATE KEY BLOCK"

    assert "set -x" not in backup
    assert "PGPASSWORD" not in backup
    assert "echo \"${database_url}" not in backup
    assert "echo ${database_url}" not in backup
    assert private_pgp_marker not in backup
    assert private_age_marker not in backup


def test_restore_preflight_requires_explicit_guarded_restore_inputs():
    restore = _text(RESTORE_PREFLIGHT)

    assert restore.startswith("#!/usr/bin/env bash")
    assert "Preflight-only restore guard" in restore
    assert "--environment is required; restore never defaults to production" in restore
    assert "Production restore requires --confirm-production-restore" in restore
    assert "SITBANK_RESTORE_ALLOWED_USERS" in restore
    assert "SITBANK_RESTORE_AGE_IDENTITY_FILE" in restore
    assert "--target-database is required" in restore
    assert "Encrypted backup file must not be world-readable" in restore
    assert "Decryption identity must not be group-readable or world-readable" in restore
    assert "restore_preflight_passed" in restore


def test_bootstrap_installs_backup_tools_and_keeps_lf_artifacts():
    bootstrap = _text(BOOTSTRAP_SCRIPT)
    attributes = _text(Path(".gitattributes"))

    assert "apt-get install -y age ca-certificates curl gnupg" in bootstrap
    assert "ops/backups/sitbank-backup-encrypted" in bootstrap
    assert "ops/backups/sitbank-restore-preflight" in bootstrap
    assert "/usr/local/sbin/sitbank-backup-encrypted" in bootstrap
    assert "/usr/local/sbin/sitbank-restore-preflight" in bootstrap
    assert "ops/backups/* text eol=lf" in attributes
    assert b"\r\n" not in BACKUP_SCRIPT.read_bytes()
    assert b"\r\n" not in RESTORE_PREFLIGHT.read_bytes()


def test_database_cutover_uses_encrypted_backup_and_no_persistent_plaintext_dump():
    cutover = _text(CUTOVER_SCRIPT)

    assert "BACKUP_HELPER" in cutover
    assert "sitbank-backup-encrypted" in cutover
    assert "create_encrypted_backup" in cutover
    assert "--database-name" in cutover
    assert "pg_dump --format=custom" not in cutover
    assert "${BACKUP_DIR}/database-${timestamp}.dump" not in cutover
    assert "mktemp /tmp/sitbank-db.XXXXXX.dump" not in cutover


def test_restore_and_backup_are_not_exposed_by_flask_routes(app):
    customer_rules = {
        f"{rule.endpoint} {rule.rule}"
        for rule in app.url_map.iter_rules()
    }
    admin_app = create_app(TestConfig, app_mode="admin")
    admin_rules = {
        f"{rule.endpoint} {rule.rule}"
        for rule in admin_app.url_map.iter_rules()
    }
    route_text = "\n".join(sorted(customer_rules | admin_rules)).casefold()

    for forbidden in (
        "backup",
        "restore",
        "pg_dump",
        "pg_restore",
        "database-cutover",
    ):
        assert forbidden not in route_text


def test_repository_does_not_commit_database_dumps_or_backup_private_keys():
    tracked = _tracked_files()
    forbidden_suffixes = (".dump", ".backup", ".pgdump")
    private_age_marker = "AGE-SECRET" + "-KEY-"
    private_pgp_marker = "BEGIN PGP " + "PRIVATE KEY BLOCK"
    private_ssh_marker = "BEGIN OPENSSH " + "PRIVATE KEY"
    forbidden_key_markers = (
        private_age_marker,
        private_pgp_marker,
        private_ssh_marker,
    )

    assert not [path for path in tracked if path.endswith(forbidden_suffixes)]
    assert not [
        path
        for path in tracked
        if path.endswith(".sql") and not path.startswith("migrations/")
    ]

    for path_text in tracked:
        path = Path(path_text)
        if path.suffix.lower() not in {".py", ".md", ".sh", ".yml", ".yaml", ".conf", ".service", ".timer", ""}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for marker in forbidden_key_markers:
            assert marker not in text, f"{marker} must not be committed in {path}"
