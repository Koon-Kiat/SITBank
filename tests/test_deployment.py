from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import importlib.util
from pathlib import Path

import pytest
import yaml
from flask import request

from ops.deploy.render_container_bundle import (
    NON_SECRET_DEFAULTS,
    SECRET_INPUTS,
    build_container_bundle,
    build_container_environment,
    build_deployment_environment,
    write_container_bundle,
)
from ops.runtime_contract import (
    ADMIN_SECRET_FILE_ENVIRONMENT,
    ADMIN_SECRET_FILES,
    APP_SECRET_FILE_ENVIRONMENT,
    APP_SECRET_FILES,
    CONFIG_SECRET_INPUTS,
    DEPLOYMENT_SECRET_INPUTS,
    DEPLOYMENT_SECRET_FILES,
    NON_SECRET_DEFAULTS as CONTRACT_NON_SECRET_DEFAULTS,
    NON_SECRET_RUNTIME_ENVIRONMENT,
    PRODUCTION_NON_SECRET_RUNTIME_ENVIRONMENT,
    PRODUCTION_SECRET_INPUTS,
    PRODUCTION_SECRET_FILES,
    STAGING_DATA_SERVICE_SECRETS,
)


ACTION_USES_PIN_RE = re.compile(r"[^@]+@[0-9a-f]{40}")
PYTHON_SLIM_TRIXIE_DIGEST_RE = re.compile(
    r"python:3\.12(?:\.\d+)?-slim-trixie@sha256:[0-9a-f]{64}"
)

DEPLOYMENT_VALUES = {
    "PROD_ADMIN_DATABASE_URL": "postgresql+psycopg2://bank_admin:secret@127.0.0.1/bank",
    "PROD_ADMIN_PASSWORD_PEPPER_B64": "ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg=",
    "PROD_ADMIN_SECRET_KEY": "admin-secret-key-with-enough-length-for-production",
    "PROD_ADMIN_SESSION_HMAC_ACTIVE_KEY_B64": "NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY=",
    "PROD_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID": "2026-06-admin",
    "PROD_ADMIN_SESSION_LOOKUP_HMAC_KEY": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    "PROD_ADMIN_WTF_CSRF_SECRET_KEY": "admin-csrf-secret-with-enough-length-for-production",
    "PROD_DATABASE_MIGRATION_URL": "postgresql+psycopg2://bank_owner:secret@127.0.0.1/bank",
    "PROD_DATABASE_URL": "postgresql+psycopg2://bank:secret@127.0.0.1/bank",
    "PROD_MFA_KEK_ACTIVE_ID": "2026-06-mfa",
    "PROD_MFA_KEK_KEYS_JSON": '{"2026-06-mfa":"NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ="}',
    "PROD_PASSWORD_PEPPER_B64": "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=",
    "PROD_PUBLIC_HOST": "sitbank.duckdns.org",
    "PROD_SECRET_KEY": "secret-key-with-$-and-enough-length-for-production",
    "PROD_SECURITY_AUDIT_HMAC_KEY": "audit-hmac-key-with-enough-length-for-production",
    "PROD_SECURITY_ALERT_WEBHOOK_URL": "https://hooks.example.test/sitbank-security-alerts",
    "PROD_SESSION_HMAC_ACTIVE_KEY_B64": "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI=",
    "PROD_SESSION_HMAC_ACTIVE_KEY_ID": "2026-06",
    "PROD_SESSION_LOOKUP_HMAC_KEY": "OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk=",
    "PROD_PASSWORD_RESET_EMAIL_FROM": "security@sitbank.example",
    "PROD_SMTP_HOST": "smtp.example.test",
    "PROD_SMTP_USERNAME": "smtp-user",
    "PROD_SMTP_PASSWORD": "smtp-password",
    "PROD_WTF_CSRF_SECRET_KEY": "csrf-secret-with-enough-length-for-production",
}


def _set_deployment_values(monkeypatch):
    for name, value in DEPLOYMENT_VALUES.items():
        monkeypatch.setenv(name, value)


def _set_prefixed_deployment_values(monkeypatch, prefix: str, public_host: str):
    for name, value in DEPLOYMENT_VALUES.items():
        target_name = name.replace("PROD_", f"{prefix}_", 1)
        if name == "PROD_PUBLIC_HOST":
            value = public_host
        monkeypatch.setenv(target_name, value)


def _load_db_privileges_module():
    module_path = Path("app/ops/db_privileges.py")
    spec = importlib.util.spec_from_file_location("_db_privileges_under_test", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def _load_create_dast_session_module():
    module_path = Path("ops/container/create_dast_session.py")
    spec = importlib.util.spec_from_file_location("_create_dast_session_under_test", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def test_production_check_rejects_short_payee_cooldown(monkeypatch):
    from app import create_app
    from app.extensions import db
    import app.security.production_guard as production_guard
    from config import MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS
    from conftest import TestConfig

    flask_app = create_app(TestConfig)
    flask_app.config.update(
        APP_ENV="production",
        TRUSTED_PROXY_COUNT=1,
        WTF_CSRF_ENABLED=True,
        TALISMAN_FORCE_HTTPS=True,
        PAYEE_COOLDOWN_SECONDS=60,
        MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS=MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS,
    )
    monkeypatch.setattr(production_guard, "validate_common_password_dictionary", lambda: 100000)
    monkeypatch.setattr(production_guard, "validate_password_hash_config", lambda: None)
    monkeypatch.setattr(production_guard, "validate_session_hmac_config", lambda: 1)
    monkeypatch.setattr(
        production_guard,
        "validate_security_alert_config",
        lambda require_delivery=True: {
            "enabled": True,
            "min_severity": "high",
            "dedupe_ttl_seconds": 300,
        },
    )
    monkeypatch.setattr(production_guard, "validate_audit_integrity_config", lambda: 32)

    with flask_app.app_context():
        db.create_all()
        result = flask_app.test_cli_runner().invoke(args=["production-check"])

    assert result.exit_code != 0
    assert "Payee cooldown configuration check failed" in result.output
    assert "PAYEE_COOLDOWN_SECONDS" in result.output
    assert str(MIN_PRODUCTION_PAYEE_COOLDOWN_SECONDS) in result.output
    assert "DATABASE_URL" not in result.output


def _nginx_location_bodies(config: str, selector: str) -> list[str]:
    return re.findall(
        rf"location\s+{re.escape(selector)}\s*\{{(.*?)\n\s*\}}",
        config,
        flags=re.DOTALL,
    )


def _nginx_server_block(config: str, server_name: str) -> str:
    marker = f"server_name {server_name};"
    blocks = []
    search_from = 0
    while True:
        marker_index = config.find(marker, search_from)
        if marker_index == -1:
            break
        start = config.rfind("\nserver {", 0, marker_index)
        if start == -1:
            start = 0
        else:
            start += 1
        end = config.find("\nserver {", marker_index)
        block = config[start:] if end == -1 else config[start:end]
        blocks.append(block)
        search_from = marker_index + len(marker)
    assert blocks, f"Missing Nginx server block for {server_name}"
    for block in blocks:
        if "listen 443 ssl http2;" in block:
            return block
    return blocks[0]


def _nginx_http_server_block(config: str, server_name: str) -> str:
    marker = f"server_name {server_name};"
    blocks = []
    search_from = 0
    while True:
        marker_index = config.find(marker, search_from)
        if marker_index == -1:
            break
        start = config.rfind("\nserver {", 0, marker_index)
        if start == -1:
            start = 0
        else:
            start += 1
        end = config.find("\nserver {", marker_index)
        block = config[start:] if end == -1 else config[start:end]
        blocks.append(block)
        search_from = marker_index + len(marker)
    assert blocks, f"Missing Nginx server block for {server_name}"
    for block in blocks:
        if "listen 80;" in block and "listen 443" not in block:
            return block
    raise AssertionError(f"Missing Nginx HTTP server block for {server_name}")


def _nginx_https_server_prelocation(config: str, *, server_name: str | None = None) -> str:
    server = _nginx_server_block(config, server_name) if server_name else config
    https_start = server.index("listen 443 ssl http2;")
    first_location = server.index("\n    location ", https_start)
    return server[https_start:first_location]


def _assert_nginx_owns_duplicate_edge_security_headers(
    nginx: str,
    *,
    hsts_add_header: str,
    server_name: str | None = None,
) -> None:
    https_server = _nginx_https_server_prelocation(nginx, server_name=server_name)
    hide_directives = (
        "proxy_hide_header X-Content-Type-Options;",
        "proxy_hide_header X-Frame-Options;",
        "proxy_hide_header Referrer-Policy;",
        "proxy_hide_header Permissions-Policy;",
        "proxy_hide_header Strict-Transport-Security;",
    )
    add_header_directives = (
        'add_header X-Content-Type-Options "nosniff" always;',
        'add_header X-Frame-Options "DENY" always;',
        'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        'add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;',
        hsts_add_header,
    )

    first_add_header = min(https_server.index(directive) for directive in add_header_directives)
    for directive in hide_directives:
        assert directive in https_server
        assert https_server.count(directive) == 1
        assert https_server.index(directive) < first_add_header
    for directive in add_header_directives:
        assert directive in https_server
        assert https_server.count(directive) == 1
    app_owned_or_unused_headers = (
        "Content-Security-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
    )
    for header in app_owned_or_unused_headers:
        assert f"proxy_hide_header {header};" not in https_server
        assert f"add_header {header}" not in https_server


def _config_secret_inputs() -> set[str]:
    tree = ast.parse(Path("config.py").read_text(encoding="utf-8"))
    secret_readers = {
        "_optional_url",
        "_optional_env_or_file",
        "_required_b64_32_bytes",
        "_required_b64_32_bytes_decoded",
        "_required_keyring",
        "_required_secret",
        "_configured_secret",
        "_required_session_hmac_keys",
        "_required_url",
    }
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id not in secret_readers:
            continue
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            names.add(node.args[0].value)
    return names


def _service_secret_targets(service: dict) -> dict[str, str]:
    targets = {}
    for secret in service.get("secrets", []):
        if isinstance(secret, str):
            targets[secret] = secret
        else:
            targets[secret["source"]] = secret["target"]
    return targets


def _extract_bash_array(script: str, name: str) -> list[str]:
    match = re.search(rf"(?:local\s+)?{re.escape(name)}=\((.*?)\)", script, flags=re.DOTALL)
    assert match, f"Missing bash array: {name}"
    return re.findall(r"[A-Za-z0-9_.-]+", match.group(1))


def _workflow_uses(workflow_text: str) -> list[str]:
    return re.findall(r"^\s*uses:\s*([^\s#]+)", workflow_text, flags=re.MULTILINE)


def _assert_pinned_actions(actions: list[str], *, context: str) -> None:
    assert actions, f"{context} must use at least one pinned action"
    for action in actions:
        if action.startswith("./.github/workflows/"):
            assert action.endswith(".yml"), (
                f"{context} has an invalid local reusable workflow reference: {action}"
            )
            continue
        assert ACTION_USES_PIN_RE.fullmatch(action), f"{context} is not pinned: {action}"


def _assert_sets_equal(actual: set[str], expected: set[str], *, context: str) -> None:
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    assert not missing and not unexpected, (
        f"{context} drifted; missing={missing or 'none'}; "
        f"unexpected={unexpected or 'none'}"
    )


def _project_docs_text() -> str:
    paths = [Path("README.md"), Path("SECURITY.md")]
    docs_dir = Path("docs")
    if docs_dir.exists():
        paths.extend(sorted(docs_dir.rglob("*.md")))
    return "\n".join(path.read_text(encoding="utf-8") for path in paths if path.exists())


def _dockerfile_stage_images(dockerfile: str) -> dict[str, str]:
    return {
        stage: image
        for image, stage in re.findall(
            r"^FROM\s+(\S+)\s+AS\s+([A-Za-z0-9_-]+)$",
            dockerfile,
            flags=re.MULTILINE,
        )
    }


def test_runtime_privilege_verifier_quotes_create_probe_table_name():
    db_privileges = _load_db_privileges_module()
    probe_table = "sitbank_privilege_probe_deadbeef"

    create_probe_table_name = db_privileges._create_probe_table_name(probe_table)
    qualified_create_probe = db_privileges._qualified_table_name(
        "public",
        create_probe_table_name,
    )

    assert create_probe_table_name == "sitbank_privilege_probe_deadbeef_create"
    assert qualified_create_probe == '"public"."sitbank_privilege_probe_deadbeef_create"'
    assert '"sitbank_privilege_probe_deadbeef"_create' not in qualified_create_probe

    source = Path("app/ops/db_privileges.py").read_text(encoding="utf-8")
    assert "_qualified_table_name(schema, create_probe_table_name)" in source
    assert "_quote_identifier(probe_table)}_create" not in source
    for privilege_probe in (
        '"CREATE TABLE"',
        '"ALTER TABLE"',
        '"DROP TABLE"',
        '"CREATE EXTENSION"',
        '"UPDATE security_audit_events"',
        '"DELETE security_audit_events"',
        '"TRUNCATE security_audit_events"',
    ):
        assert privilege_probe in source
    assert "apply_runtime_audit_table_privileges" in source
    assert "apply_admin_runtime_database_privileges" in source
    assert "ADMIN_DATABASE_URL is required for admin privilege application" in source
    assert "ADMIN_DATABASE_URL role must already exist" in source
    assert "CREATE ROLE" not in source
    assert "ALTER ROLE" not in source
    assert "create_engine(admin_url)" in source
    assert "ADMIN_DATABASE_URL did not authenticate as the configured role" in source
    assert "GRANT SELECT, INSERT ON ALL TABLES" in source
    assert "ALTER DEFAULT PRIVILEGES FOR ROLE" in source
    assert "REVOKE UPDATE, DELETE, TRUNCATE ON TABLE" in source
    assert "GRANT SELECT, INSERT ON TABLE" in source
    assert "previous_event_hash" in source
    assert "event_hash" in source
    assert "hash_algorithm" in source


def test_dast_session_creator_requires_loopback_or_explicit_smoke_host():
    create_dast_session = _load_create_dast_session_module()

    create_dast_session.DastClient("http://127.0.0.1:5000")
    create_dast_session.DastClient("http://localhost:5000")
    create_dast_session.DastClient(
        "http://sitbank-smoke:5000",
        allowed_hosts={"sitbank-smoke"},
    )

    with pytest.raises(ValueError, match="host is not allowed"):
        create_dast_session.DastClient("http://sitbank-smoke:5000")

    with pytest.raises(ValueError, match="host is not allowed"):
        create_dast_session.DastClient(
            "http://unexpected-smoke:5000",
            allowed_hosts={"sitbank-smoke"},
        )


def test_dast_session_creator_matches_registration_contract():
    source = Path("ops/container/create_dast_session.py").read_text(encoding="utf-8")

    assert "create_dast_user(" in source
    assert "hash_password(password)" in source
    assert "@sit.singaporetech.edu.sg" in source
    assert "create_registration_invite" not in source
    assert '"invite_token"' not in source
    assert 'full_name=f"DAST User {suffix}"' in source
    assert 'phone_number=f"9{secrets.randbelow(9000000) + 1000000}"' in source
    assert '"account_number"' not in source


def test_registration_field_migration_backfills_existing_users_deterministically():
    migration = Path(
        "migrations/versions/20260622_0008_add_user_registration_fields.py"
    ).read_text(encoding="utf-8")

    assert "SET phone_number = ''" not in migration
    assert "floor(random()" not in migration
    assert "abs(random())" not in migration
    assert "row_number() OVER (ORDER BY id)" in migration
    assert "SET full_name = username" in migration


def test_container_bundle_separates_secrets_from_non_secret_environment(monkeypatch):
    _set_deployment_values(monkeypatch)

    environment, secrets = build_container_bundle()

    assert set(environment) == set(PRODUCTION_NON_SECRET_RUNTIME_ENVIRONMENT)
    assert environment["APP_ENV"] == "production"
    assert "WEBAUTHN_RP_ID" not in environment
    assert "WEBAUTHN_RP_ORIGIN" not in environment
    assert environment["PASSWORD_RESET_BASE_URL"] == "https://sitbank.duckdns.org"
    assert environment["PASSWORD_RESET_EMAIL_BACKEND"] == "smtp"
    assert environment["PASSWORD_RESET_EMAIL_FROM"] == DEPLOYMENT_VALUES["PROD_PASSWORD_RESET_EMAIL_FROM"]
    assert environment["PAYEE_COOLDOWN_SECONDS"] == "43200"
    assert environment["SMTP_HOST"] == DEPLOYMENT_VALUES["PROD_SMTP_HOST"]
    assert environment["SESSION_HMAC_ACTIVE_KEY_ID"] == "2026-06"
    assert environment["ADMIN_SESSION_HMAC_ACTIVE_KEY_ID"] == "2026-06-admin"
    assert environment["ADMIN_SESSION_KEY_PREFIX"] == "admin-session:"
    assert environment["ADMIN_RATELIMIT_KEY_PREFIX"] == "ospbank:admin:ratelimit:"
    assert environment["MFA_KEK_ACTIVE_ID"] == "2026-06-mfa"
    assert environment["COMMON_PASSWORDS_PATH"] == "/run/config/common-passwords.txt"
    assert environment["SECURITY_ALERT_STATE_PATH"] == "/run/state/security-alert-state.json"
    assert environment["SECURITY_AUDIT_ANCHOR_PATH"] == "/var/lib/sitbank/security-audit.anchor"
    assert "SECRET_KEY" not in environment
    assert "DATABASE_MIGRATION_URL" not in environment
    assert "DATABASE_MIGRATION_URL_FILE" not in environment
    assert secrets["secret_key"] == DEPLOYMENT_VALUES["PROD_SECRET_KEY"]
    assert secrets["database_url"] == DEPLOYMENT_VALUES["PROD_DATABASE_URL"]
    assert secrets["session_lookup_hmac_key"] == DEPLOYMENT_VALUES["PROD_SESSION_LOOKUP_HMAC_KEY"]
    assert secrets["admin_database_url"] == DEPLOYMENT_VALUES["PROD_ADMIN_DATABASE_URL"]
    assert secrets["admin_session_lookup_hmac_key"] == DEPLOYMENT_VALUES["PROD_ADMIN_SESSION_LOOKUP_HMAC_KEY"]
    assert secrets["admin_secret_key"] == DEPLOYMENT_VALUES["PROD_ADMIN_SECRET_KEY"]
    assert secrets["database_migration_url"] == DEPLOYMENT_VALUES["PROD_DATABASE_MIGRATION_URL"]
    assert secrets["mfa_kek_keys_json"] == DEPLOYMENT_VALUES["PROD_MFA_KEK_KEYS_JSON"]
    assert secrets["security_audit_hmac_key"] == DEPLOYMENT_VALUES["PROD_SECURITY_AUDIT_HMAC_KEY"]
    assert secrets["smtp_username"] == DEPLOYMENT_VALUES["PROD_SMTP_USERNAME"]
    assert secrets["smtp_password"] == DEPLOYMENT_VALUES["PROD_SMTP_PASSWORD"]
    assert '"2026-06":"MjIy' in secrets["session_hmac_keys_json"]
    assert '"2026-06-admin":"NjY2' in secrets["admin_session_hmac_keys_json"]


def test_container_bundle_accepts_staging_prefix(monkeypatch):
    _set_prefixed_deployment_values(
        monkeypatch,
        "STAGING",
        "staging.sitbank.example",
    )

    environment, secrets = build_container_bundle("STAGING")

    assert environment["APP_ENV"] == "production"
    assert "WEBAUTHN_RP_ID" not in environment
    assert "WEBAUTHN_RP_ORIGIN" not in environment
    assert environment["PASSWORD_RESET_BASE_URL"] == "https://staging.sitbank.example"
    assert environment["PAYEE_COOLDOWN_SECONDS"] == "43200"
    assert environment["SESSION_HMAC_ACTIVE_KEY_ID"] == "2026-06"
    assert environment["ADMIN_SESSION_HMAC_ACTIVE_KEY_ID"] == "2026-06-admin"
    assert environment["MFA_KEK_ACTIVE_ID"] == "2026-06-mfa"
    assert environment["SECURITY_AUDIT_ANCHOR_PATH"] == "/run/state/security-audit.anchor"
    assert secrets["secret_key"] == DEPLOYMENT_VALUES["PROD_SECRET_KEY"]
    assert secrets["database_url"] == DEPLOYMENT_VALUES["PROD_DATABASE_URL"]
    assert secrets["session_lookup_hmac_key"] == DEPLOYMENT_VALUES["PROD_SESSION_LOOKUP_HMAC_KEY"]
    assert secrets["database_migration_url"] == DEPLOYMENT_VALUES["PROD_DATABASE_MIGRATION_URL"]
    assert secrets["security_audit_hmac_key"] == DEPLOYMENT_VALUES["PROD_SECURITY_AUDIT_HMAC_KEY"]


def test_deployment_profiles_keep_production_and_staging_isolated(monkeypatch):
    _set_deployment_values(monkeypatch)
    _set_prefixed_deployment_values(
        monkeypatch,
        "STAGING",
        "staging-sitbank.duckdns.org",
    )

    production = build_deployment_environment("PROD")
    staging = build_deployment_environment("STAGING")

    assert production["DEPLOYMENT_TARGET"] == "production"
    assert production["CONFIG_ROOT"] == "/etc/sitbank"
    assert production["COMPOSE_DIR"] == "/opt/sitbank"
    assert production["SYSTEMD_SERVICE"] == "sitbank-container.service"
    assert production["COMPOSE_PROJECT_NAME"] == "sitbank"
    assert production["APP_CONTAINER_NAME"] == "sitbank-app"
    assert production["APP_BIND_PORT"] == "5000"
    assert production["ADMIN_APP_CONTAINER_NAME"] == "sitbank-admin"
    assert production["ADMIN_APP_BIND_HOST"] == "127.0.0.1"
    assert production["ADMIN_APP_BIND_PORT"] == "5002"
    assert production["ADMIN_PUBLIC_HOST"] == "admin-sitbank.duckdns.org"
    assert production["POSTGRES_VOLUME_NAME"] == "none"
    assert "REDIS_VOLUME_NAME" not in production

    assert staging["DEPLOYMENT_TARGET"] == "staging"
    assert staging["CONFIG_ROOT"] == "/etc/sitbank-staging"
    assert staging["SECRET_ROOT"] == "/etc/sitbank-staging/secrets"
    assert staging["COMPOSE_DIR"] == "/opt/sitbank-staging"
    assert staging["SYSTEMD_SERVICE"] == "sitbank-staging-container.service"
    assert staging["COMPOSE_PROJECT_NAME"] == "sitbank-staging"
    assert staging["APP_CONTAINER_NAME"] == "sitbank-staging-app"
    assert staging["APP_BIND_PORT"] == "5001"
    assert staging["POSTGRES_CONTAINER_NAME"] == "sitbank-staging-postgres"
    assert staging["POSTGRES_VOLUME_NAME"] == "sitbank-staging-postgres-data"
    assert "REDIS_CONTAINER_NAME" not in staging
    assert "REDIS_VOLUME_NAME" not in staging
    assert staging["PUBLIC_HOST"] == "staging-sitbank.duckdns.org"

    for key in (
        "CONFIG_ROOT",
        "SECRET_ROOT",
        "COMPOSE_DIR",
        "SYSTEMD_SERVICE",
        "COMPOSE_PROJECT_NAME",
        "APP_CONTAINER_NAME",
        "APP_BIND_PORT",
    ):
        assert production[key] != staging[key]


def test_container_bundle_rejects_unknown_prefix(monkeypatch):
    _set_deployment_values(monkeypatch)

    with pytest.raises(RuntimeError, match="Deployment prefix"):
        build_container_bundle("DEV")


def test_container_bundle_rejects_missing_multiline_and_partial_rotation(monkeypatch):
    _set_deployment_values(monkeypatch)
    monkeypatch.delenv("PROD_DATABASE_URL")
    with pytest.raises(RuntimeError, match="PROD_DATABASE_URL"):
        build_container_bundle()

    monkeypatch.setenv("PROD_DATABASE_URL", DEPLOYMENT_VALUES["PROD_DATABASE_URL"])
    monkeypatch.setenv("PROD_SECRET_KEY", "line-one\nline-two")
    with pytest.raises(RuntimeError, match="control characters"):
        build_container_bundle()

    monkeypatch.setenv("PROD_SECRET_KEY", DEPLOYMENT_VALUES["PROD_SECRET_KEY"])
    monkeypatch.setenv("PROD_SESSION_HMAC_PREVIOUS_KEY_ID", "2026-03")
    monkeypatch.delenv("PROD_SESSION_HMAC_PREVIOUS_KEY_B64", raising=False)
    with pytest.raises(RuntimeError, match="must be configured together"):
        build_container_bundle()


def test_container_bundle_keyring_validation_normalizes_ids_and_rejects_duplicates(monkeypatch):
    _set_deployment_values(monkeypatch)
    key = DEPLOYMENT_VALUES["PROD_MFA_KEK_KEYS_JSON"].split('"')[3]

    monkeypatch.setenv("PROD_MFA_KEK_KEYS_JSON", f'{{" 2026-06-mfa ":"{key}"}}')
    environment, secrets = build_container_bundle()

    assert environment["MFA_KEK_ACTIVE_ID"] == "2026-06-mfa"
    assert secrets["mfa_kek_keys_json"] == f'{{" 2026-06-mfa ":"{key}"}}'

    monkeypatch.setenv(
        "PROD_MFA_KEK_KEYS_JSON",
        f'{{"2026-06-mfa":"{key}"," 2026-06-mfa ":"{key}"}}',
    )
    with pytest.raises(RuntimeError, match="duplicate key identifiers"):
        build_container_bundle()


def test_container_bundle_builds_two_key_rotation_ring(monkeypatch):
    _set_deployment_values(monkeypatch)
    monkeypatch.setenv("PROD_SESSION_HMAC_PREVIOUS_KEY_ID", "2026-03")
    monkeypatch.setenv(
        "PROD_SESSION_HMAC_PREVIOUS_KEY_B64",
        "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=",
    )

    _, secrets = build_container_bundle()

    assert '"2026-03":"MzMz' in secrets["session_hmac_keys_json"]
    assert '"2026-06":"MjIy' in secrets["session_hmac_keys_json"]


def test_runtime_secret_inventory_matches_config_and_renderer():
    assert SECRET_INPUTS == PRODUCTION_SECRET_INPUTS
    assert NON_SECRET_DEFAULTS == CONTRACT_NON_SECRET_DEFAULTS
    _assert_sets_equal(
        _config_secret_inputs(),
        set(CONFIG_SECRET_INPUTS),
        context="Runtime secret readers in config.py vs ops/runtime_contract.py",
    )


def test_bundle_renderer_runs_directly_without_pythonpath():
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)

    result = subprocess.run(
        [sys.executable, "ops/deploy/render_container_bundle.py", "--help"],
        check=False,
        capture_output=True,
        env=env,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()


def test_compose_secret_mounts_match_runtime_contract():
    expected_app_secrets = {name: name for name in APP_SECRET_FILES}
    expected_admin_environment = {
        **ADMIN_SECRET_FILE_ENVIRONMENT,
        "SECURITY_AUDIT_HMAC_KEY_FILE": "/run/secrets/security_audit_hmac_key",
        "SECURITY_ALERT_WEBHOOK_URL_FILE": "/run/secrets/security_alert_webhook_url",
        "SMTP_USERNAME_FILE": "/run/secrets/smtp_username",
        "SMTP_PASSWORD_FILE": "/run/secrets/smtp_password",
    }
    expected_admin_secrets = {
        **{name: name for name in ADMIN_SECRET_FILES},
        "security_audit_hmac_key": "security_audit_hmac_key",
        "security_alert_webhook_url": "security_alert_webhook_url",
        "smtp_username": "smtp_username",
        "smtp_password": "smtp_password",
    }
    for path, secret_root, base_extra_secrets in (
        (
            Path("compose.prod.yml"),
            "/etc/sitbank/secrets",
            {},
        ),
        (
            Path("compose.staging.yml"),
            "/etc/sitbank-staging/secrets",
            STAGING_DATA_SERVICE_SECRETS,
        ),
    ):
        compose = yaml.safe_load(path.read_text(encoding="utf-8"))
        app = compose["services"]["app"]

        assert app["environment"] == APP_SECRET_FILE_ENVIRONMENT, (
            f"{path} app secret _FILE environment must match runtime contract"
        )
        assert "DATABASE_MIGRATION_URL_FILE" not in app["environment"]
        assert _service_secret_targets(app) == expected_app_secrets, (
            f"{path} app service secrets must match runtime contract"
        )

        extra_secrets = dict(base_extra_secrets)
        admin = compose["services"].get("admin")
        if path.name == "compose.prod.yml":
            assert admin is not None
        expected_path_admin_environment = dict(expected_admin_environment)
        if path.name == "compose.staging.yml" and admin is not None:
            expected_path_admin_environment["ADMIN_SESSION_HMAC_ACTIVE_KEY_ID"] = "2026-06-admin"
        if admin is not None:
            assert admin["environment"] == expected_path_admin_environment, (
                f"{path} admin secret _FILE environment must match runtime contract"
            )
            assert _service_secret_targets(admin) == expected_admin_secrets, (
                f"{path} admin service secrets must match runtime contract"
            )
            extra_secrets.update(expected_admin_secrets)

        expected_top_level = (
            set(PRODUCTION_SECRET_FILES)
            if path.name == "compose.prod.yml"
            else set(DEPLOYMENT_SECRET_FILES) | set(extra_secrets)
        )
        _assert_sets_equal(
            set(compose["secrets"]),
            expected_top_level,
            context=f"{path} top-level Compose secrets vs runtime contract",
        )
        expected_secret_files = {
            **{secret_name: secret_name for secret_name in DEPLOYMENT_SECRET_FILES},
            **extra_secrets,
        }
        for secret_name in expected_top_level:
            assert (
                compose["secrets"][secret_name]["file"]
                == f"{secret_root}/{expected_secret_files[secret_name]}"
            ), f"{path} secret {secret_name} must map to its contract file"


def test_smoke_fixture_and_deployment_wrapper_match_runtime_contract():
    smoke_test = Path("ops/container/smoke-test.sh").read_text(encoding="utf-8")
    deploy_script = Path("ops/deploy/sitbank-container-deploy").read_text(encoding="utf-8")

    for env_name, secret_path in APP_SECRET_FILE_ENVIRONMENT.items():
        assert f"--env {env_name}={secret_path}" in smoke_test, (
            f"ops/container/smoke-test.sh is missing {env_name}={secret_path}"
        )
    for secret_name in DEPLOYMENT_SECRET_FILES:
        assert f"${{work_dir}}/secrets/{secret_name}" in smoke_test, (
            f"ops/container/smoke-test.sh is missing secret fixture {secret_name}"
        )

    assert "--env DATABASE_MIGRATION_URL_FILE=/run/secrets/database_migration_url" in smoke_test
    assert "--env PAYEE_COOLDOWN_SECONDS=43200" in smoke_test
    assert "--env SECURITY_AUDIT_ANCHOR_PATH=/run/state/security-audit.anchor" in smoke_test
    assert '--tmpfs "/run/state:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0750"' in smoke_test
    assert ':/run/secrets/database_migration_url:ro' not in smoke_test
    assert '"${secrets_mount_source}:/run/secrets:ro"' in smoke_test

    _assert_sets_equal(
        set(_extract_bash_array(deploy_script, "allowed_environment")),
        set(NON_SECRET_RUNTIME_ENVIRONMENT),
        context="sitbank-container-deploy allowed_environment vs runtime contract",
    )
    for admin_env in (
        "ADMIN_RATELIMIT_KEY_PREFIX",
        "ADMIN_SESSION_HMAC_ACTIVE_KEY_ID",
        "ADMIN_SESSION_KEY_PREFIX",
    ):
        assert admin_env in deploy_script
    _assert_sets_equal(
        set(_extract_bash_array(deploy_script, "required_secrets")),
        set(DEPLOYMENT_SECRET_FILES),
        context="sitbank-container-deploy required_secrets vs runtime contract",
    )
    assert "DATABASE_MIGRATION_URL_FILE=/run/secrets/database_migration_url" in deploy_script
    assert (
        '--volume "${SECRET_DIR}/database_migration_url:/run/secrets/database_migration_url:ro"'
        in deploy_script
    )
    assert "show_dependency_diagnostics" in deploy_script
    assert 'logs --no-color --tail 120 postgres' in deploy_script
    assert 'logs --no-color --tail 120 postgres redis' not in deploy_script
    assert "dependencies_prepared=1" in deploy_script
    assert 'if [[ "${target}" == "staging" ]]; then' in deploy_script
    assert re.search(
        r'\[\[ "\$\{target\}" == "staging" \]\].*?'
        r"allowed_environment\+=\(\s*ADMIN_SESSION_HMAC_ACTIVE_KEY_ID\s*\)",
        deploy_script,
        flags=re.DOTALL,
    )


def test_local_ci_command_documents_required_local_checks():
    ci_local = Path("scripts/ci-local").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")

    for expected in (
        "Full parallel test suite",
        '"pytest"',
        '"-n"',
        '"auto"',
        '"--durations=30"',
        '"--durations-min=0.5"',
        '"compileall"',
        '"pip", "check"',
        '"bandit"',
        '"pip_audit"',
        '"requirements.lock"',
        '"requirements-dev.lock"',
        '"ops/security/check_dependency_locks.py"',
        '"ops/security/scan_repository_secrets.py"',
        '"--history"',
        '"git", "diff", "--check"',
        "ops/deploy/sitbank-container-deploy",
        "ops/container/validate-compose.sh",
        "== {name} ==",
        "Python/test checks",
        "Git Bash syntax checks",
        "Docker/Compose checks",
        "PASS:",
        "SKIP:",
        "No Docker result was recorded",
    ):
        assert expected in ci_local
    assert "Docker is unavailable; skipped Docker/Compose-only local checks" in ci_local
    assert "scripts/ci-local" in readme
    assert "ops/runtime_contract.py" in readme
    assert "-m security" in readme
    assert "-m deployment" in readme
    assert '-m "not slow"' in readme
    assert "Pull requests and protected CI still run the full pytest suite" in readme


def test_environment_only_bundle_does_not_export_long_lived_secrets(
    monkeypatch,
    tmp_path,
):
    _set_deployment_values(monkeypatch)
    for name in (
        "PROD_DATABASE_MIGRATION_URL",
        "PROD_DATABASE_URL",
        "PROD_MFA_KEK_KEYS_JSON",
        "PROD_PASSWORD_PEPPER_B64",
        "PROD_SECRET_KEY",
        "PROD_SECURITY_AUDIT_HMAC_KEY",
        "PROD_SECURITY_ALERT_WEBHOOK_URL",
        "PROD_SESSION_HMAC_ACTIVE_KEY_B64",
        "PROD_SESSION_LOOKUP_HMAC_KEY",
        "PROD_WTF_CSRF_SECRET_KEY",
    ):
        monkeypatch.delenv(name)

    environment = build_container_environment()
    output = tmp_path / "runtime"
    write_container_bundle(output, include_secrets=False)

    assert environment["SESSION_HMAC_ACTIVE_KEY_ID"] == "2026-06"
    assert environment["MFA_KEK_ACTIVE_ID"] == "2026-06-mfa"
    assert (output / "container.env").is_file()
    assert (output / "deployment.env").is_file()
    assert not (output / "secrets").exists()


def test_environment_only_bundle_accepts_staging_prefix(monkeypatch, tmp_path):
    _set_prefixed_deployment_values(
        monkeypatch,
        "STAGING",
        "staging.sitbank.example",
    )
    for name in (
        "STAGING_DATABASE_MIGRATION_URL",
        "STAGING_DATABASE_URL",
        "STAGING_MFA_KEK_KEYS_JSON",
        "STAGING_PASSWORD_PEPPER_B64",
        "STAGING_SECRET_KEY",
        "STAGING_SECURITY_AUDIT_HMAC_KEY",
        "STAGING_SECURITY_ALERT_WEBHOOK_URL",
        "STAGING_SESSION_HMAC_ACTIVE_KEY_B64",
        "STAGING_SESSION_LOOKUP_HMAC_KEY",
        "STAGING_WTF_CSRF_SECRET_KEY",
    ):
        monkeypatch.delenv(name)

    output = tmp_path / "runtime"
    write_container_bundle(output, "STAGING", include_secrets=False)

    environment = (output / "container.env").read_text(encoding="utf-8")
    deployment = (output / "deployment.env").read_text(encoding="utf-8")
    assert "ADMIN_SESSION_HMAC_ACTIVE_KEY_ID='2026-06-admin'" in environment
    assert "MFA_KEK_ACTIVE_ID='2026-06-mfa'" in environment
    assert "WEBAUTHN_RP_ID" not in environment
    assert "WEBAUTHN_RP_ORIGIN" not in environment
    assert "APP_BIND_PORT='5001'" in deployment
    assert "COMPOSE_PROJECT_NAME='sitbank-staging'" in deployment
    assert "CONFIG_ROOT='/etc/sitbank-staging'" in deployment
    assert not (output / "secrets").exists()


def test_container_bundle_writer_quotes_dollar_values_and_separates_files(
    monkeypatch,
    tmp_path,
):
    _set_deployment_values(monkeypatch)
    output = tmp_path / "runtime"

    write_container_bundle(output)

    environment = (output / "container.env").read_text(encoding="utf-8")
    assert "MFA_ISSUER_NAME='SITBank'" in environment
    assert "PROD_SECRET_KEY" not in environment
    assert (output / "secrets" / "secret_key").read_text(encoding="utf-8") == (
        DEPLOYMENT_VALUES["PROD_SECRET_KEY"]
    )


def test_dockerfile_and_compose_enforce_hardened_runtime():
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    compose_text = Path("compose.prod.yml").read_text(encoding="utf-8")
    staging_compose_text = Path("compose.staging.yml").read_text(encoding="utf-8")
    smoke_test = Path("ops/container/smoke-test.sh").read_text(encoding="utf-8")
    compose_validation = Path(
        "ops/container/validate-compose.sh"
    ).read_text(encoding="utf-8")
    compose_validation_override = Path(
        "ops/container/compose-validation.override.yml"
    ).read_text(encoding="utf-8")
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(
        encoding="utf-8"
    )
    deploy_script = Path("ops/deploy/sitbank-container-deploy").read_text(
        encoding="utf-8"
    )
    runtime_script = Path("ops/deploy/sitbank-container-runtime").read_text(
        encoding="utf-8"
    )
    database_cutover = Path("ops/deploy/sitbank-database-cutover").read_text(
        encoding="utf-8"
    )
    compose = yaml.safe_load(compose_text)
    app = compose["services"]["app"]
    admin = compose["services"]["admin"]
    staging_compose = yaml.safe_load(staging_compose_text)
    staging_services = staging_compose["services"]
    staging_app = staging_services["app"]
    staging_admin = staging_services["admin"]

    assert compose["name"] == "sitbank"
    stage_images = _dockerfile_stage_images(dockerfile)
    assert set(stage_images) == {"builder", "runtime"}
    assert stage_images["builder"] == stage_images["runtime"]
    assert PYTHON_SLIM_TRIXIE_DIGEST_RE.fullmatch(stage_images["runtime"]), (
        "Dockerfile must use a Python 3.12 slim-trixie base image pinned by "
        f"sha256 digest, got {stage_images['runtime']}"
    )
    assert 'org.opencontainers.image.title="SITBank banking application"' in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "/health/ready" in dockerfile
    assert "admin_wsgi.py" in dockerfile
    assert "apt-get upgrade" not in dockerfile
    assert "--only-upgrade" in dockerfile
    for security_package in ("gpgv", "libgnutls30", "libssl3", "openssl", "perl-base"):
        assert security_package in dockerfile
    assert app["network_mode"] == "host"
    assert app["read_only"] is True
    assert app["user"] == "10001:10001"
    assert app["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in app["security_opt"]
    assert "ports" not in app
    assert app["pids_limit"] == 256
    assert app["mem_limit"] == "768m"
    assert app["restart"] == "unless-stopped"
    app_volume_by_target = {volume["target"]: volume for volume in app["volumes"]}
    admin_volume_by_target = {volume["target"]: volume for volume in admin["volumes"]}
    expected_prod_config_mounts = {
        "/run/config/common-passwords.txt": "/etc/sitbank/common-passwords.txt",
    }
    for target, source in expected_prod_config_mounts.items():
        assert app_volume_by_target[target]["source"] == source
        assert app_volume_by_target[target]["read_only"] is True
        assert admin_volume_by_target[target]["source"] == source
        assert admin_volume_by_target[target]["read_only"] is True
    assert all(
        volume["read_only"]
        for target, volume in app_volume_by_target.items()
        if target.startswith("/run/config/")
    )
    assert app_volume_by_target["/run/state"]["source"] == (
        "/var/lib/sitbank-container/security-alert-state"
    )
    assert app_volume_by_target["/run/state"]["read_only"] is False
    assert app_volume_by_target["/var/lib/sitbank"]["source"] == "/var/lib/sitbank"
    assert app_volume_by_target["/var/lib/sitbank"]["read_only"] is False
    assert admin_volume_by_target["/var/lib/sitbank"]["source"] == "/var/lib/sitbank"
    assert admin_volume_by_target["/var/lib/sitbank"]["read_only"] is False
    assert all(set(secret) == {"source", "target"} for secret in app["secrets"])
    assert all(
        value.startswith("/run/secrets/")
        for name, value in app["environment"].items()
        if name.endswith("_FILE")
    )
    assert "DATABASE_MIGRATION_URL_FILE" not in app["environment"]
    assert admin["network_mode"] == "host"
    assert admin["container_name"] == "sitbank-admin"
    assert admin["env_file"] == ["/etc/sitbank/container.env"]
    assert "ports" not in admin
    assert admin["command"][admin["command"].index("--bind") + 1] == "127.0.0.1:5002"
    assert admin["command"][-1] == "admin_wsgi:app"
    assert app.get("command", []) == [] or "wsgi:app" not in admin["command"]
    assert admin["read_only"] is True
    assert admin["user"] == "10001:10001"
    assert admin["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in admin["security_opt"]
    assert all(set(secret) == {"source", "target"} for secret in admin["secrets"])
    assert all(
        value.startswith("/run/secrets/")
        for name, value in admin["environment"].items()
        if name.endswith("_FILE")
    )
    assert "DATABASE_MIGRATION_URL_FILE" not in admin["environment"]
    assert "ADMIN_DATABASE_URL_FILE" in admin["environment"]
    assert "ADMIN_SESSION_LOOKUP_HMAC_KEY_FILE" in admin["environment"]
    for smtp_env in ("SMTP_USERNAME_FILE", "SMTP_PASSWORD_FILE"):
        assert admin["environment"][smtp_env] == app["environment"][smtp_env]
    admin_secret_targets = _service_secret_targets(admin)
    assert admin_secret_targets["smtp_username"] == "smtp_username"
    assert admin_secret_targets["smtp_password"] == "smtp_password"
    assert "/app/redis_compatibility_check.py:ro" not in smoke_test
    assert "python /app/redis_compatibility_check.py" not in smoke_test
    assert "ci_owner" in smoke_test
    assert "ci_app" in smoke_test
    assert "ci_admin" in smoke_test
    assert "CREATE ROLE ci_owner" in smoke_test
    assert "CREATE ROLE ci_app" in smoke_test
    assert "CREATE ROLE ci_admin" in smoke_test
    assert "Owner role exists: yes" in smoke_test
    assert "Runtime role exists: yes" in smoke_test
    assert "Admin role exists: yes" in smoke_test
    assert "Owner connection test: passed" in smoke_test
    assert "Runtime connection test: passed" in smoke_test
    assert "Admin connection test: passed" in smoke_test
    assert "DATABASE_MIGRATION_URL_FILE" in smoke_test
    assert "docker_bind_source" in smoke_test
    assert "docker network create" in smoke_test
    assert '--network "${network_name}"' in smoke_test
    assert "host.docker.internal" not in smoke_test
    assert "postgresql+psycopg2://ci_app:ci-app-password@%s:5432/ci" in smoke_test
    assert "postgresql+psycopg2://ci_admin:ci-admin-password@%s:5432/ci" in smoke_test
    assert "postgresql+psycopg2://ci_owner:ci-owner-password@%s:5432/ci" in smoke_test
    assert "SESSION_LOOKUP_HMAC_KEY_FILE=/run/secrets/session_lookup_hmac_key" in smoke_test
    assert "ADMIN_SESSION_LOOKUP_HMAC_KEY_FILE=/run/secrets/admin_session_lookup_hmac_key" in smoke_test
    assert '"${postgres_container}"' in smoke_test
    assert '"${redis_container}"' not in smoke_test
    assert '"${secrets_mount_source}:/run/secrets:ro"' in smoke_test
    assert '"${config_mount_source}:/run/config:ro"' in smoke_test
    assert '"${work_dir}/secrets:/run/secrets:ro"' not in smoke_test
    assert '"${work_dir}/secrets/database_migration_url"' in smoke_test
    assert ':/run/secrets/database_migration_url:ro' not in smoke_test
    assert "apply-runtime-db-privileges" in smoke_test
    assert "verify-runtime-db-privileges" in smoke_test
    assert "python -m flask --app admin_wsgi:app production-check" in smoke_test
    assert "admin_wsgi:app" in smoke_test
    assert "SITBank admin application did not become ready" in smoke_test
    assert smoke_test.index("db upgrade") < smoke_test.index("apply-runtime-db-privileges")
    assert smoke_test.index("apply-runtime-db-privileges") < smoke_test.index("verify-runtime-db-privileges")
    assert "/redis-check.py" not in smoke_test
    assert "--publish 127.0.0.1::5432" not in smoke_test
    assert "--publish 127.0.0.1::6379" not in smoke_test
    assert 'wait_for_healthy "${postgres_container}"' in smoke_test
    assert 'wait_for_healthy "${redis_container}"' not in smoke_test
    assert "wait_for_app_from_smoke_network" in smoke_test
    assert 'dast_base_url="http://${app_container}:5000"' in smoke_test
    assert '--base-url "${dast_base_url}"' in smoke_test
    assert '--allow-host "${app_container}"' in smoke_test
    assert "dump_container_diagnostics" in smoke_test
    assert "RUN_ZAP_DAST" in smoke_test
    assert "zaproxy/zap-stable:2.17.0@sha256:" in smoke_test
    assert "create_dast_session.py" in smoke_test
    assert "docker compose" in compose_validation
    assert "SITBANK_IMAGE" in compose_validation
    assert "compose.prod.yml" in compose_validation
    assert "compose.staging.yml" in compose_validation
    assert "production|staging|all" in compose_validation
    assert "--no-env-resolution" in compose_validation
    assert "--no-path-resolution" in compose_validation
    assert "compose-validation.override.yml" in compose_validation
    assert "env_file: !reset []" in compose_validation_override
    assert "compose-validation.override.yml" not in bootstrap
    assert "compose-validation.override.yml" not in deploy_script
    assert "compose-validation.override.yml" not in runtime_script
    assert "sudo" not in compose_validation
    assert "/etc/sitbank" not in compose_validation
    assert "docker port" in smoke_test
    assert "55432" not in smoke_test
    assert "56379" not in smoke_test

    assert staging_compose["name"] == "sitbank-staging"
    assert set(staging_services) == {"app", "admin", "postgres"}
    assert staging_app["container_name"] == "sitbank-staging-app"
    assert staging_app["ports"] == ["127.0.0.1:5001:5000"]
    assert "network_mode" not in staging_app
    assert staging_app["read_only"] is True
    assert staging_app["user"] == "10001:10001"
    assert staging_app["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in staging_app["security_opt"]
    assert staging_app["env_file"] == ["/etc/sitbank-staging/container.env"]
    assert "DATABASE_MIGRATION_URL_FILE" not in staging_app["environment"]
    staging_volume_by_target = {
        volume["target"]: volume for volume in staging_app["volumes"]
    }
    staging_admin_volume_by_target = {
        volume["target"]: volume for volume in staging_admin["volumes"]
    }
    expected_staging_config_mounts = {
        "/run/config/common-passwords.txt": "/etc/sitbank-staging/common-passwords.txt",
    }
    for target, source in expected_staging_config_mounts.items():
        assert staging_volume_by_target[target]["source"] == source
        assert staging_volume_by_target[target]["read_only"] is True
        assert staging_admin_volume_by_target[target]["source"] == source
        assert staging_admin_volume_by_target[target]["read_only"] is True
    assert all(
        volume["source"].startswith("/etc/sitbank-staging/")
        for target, volume in staging_volume_by_target.items()
        if target.startswith("/run/config/")
    )
    assert staging_admin["container_name"] == "sitbank-staging-admin"
    assert staging_admin["ports"] == ["127.0.0.1:5003:5000"]
    assert "127.0.0.1:5002:5000" not in staging_admin["ports"]
    assert "network_mode" not in staging_admin
    assert staging_admin["read_only"] is True
    assert staging_admin["user"] == "10001:10001"
    assert staging_admin["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in staging_admin["security_opt"]
    assert staging_admin["env_file"] == ["/etc/sitbank-staging/container.env"]
    assert "DATABASE_MIGRATION_URL_FILE" not in staging_admin["environment"]
    assert staging_admin["environment"]["ADMIN_SESSION_HMAC_ACTIVE_KEY_ID"] == "2026-06-admin"
    for smtp_env in ("SMTP_USERNAME_FILE", "SMTP_PASSWORD_FILE"):
        assert staging_admin["environment"][smtp_env] == staging_app["environment"][smtp_env]
    assert (
        staging_admin["command"][staging_admin["command"].index("--bind") + 1]
        == "0.0.0.0:5000"
    )
    assert staging_admin["command"][-1] == "admin_wsgi:app"
    assert all(set(secret) == {"source", "target"} for secret in staging_admin["secrets"])
    staging_admin_secret_targets = _service_secret_targets(staging_admin)
    assert staging_admin_secret_targets["smtp_username"] == "smtp_username"
    assert staging_admin_secret_targets["smtp_password"] == "smtp_password"
    assert staging_volume_by_target["/run/state"]["source"] == (
        "/var/lib/sitbank-staging-container/security-alert-state"
    )
    assert staging_volume_by_target["/run/state"]["read_only"] is False
    assert staging_admin_volume_by_target["/run/state"]["source"] == (
        "/var/lib/sitbank-staging-container/security-alert-state"
    )
    assert staging_admin_volume_by_target["/run/state"]["read_only"] is False
    assert all(
        secret["file"].startswith("/etc/sitbank-staging/secrets/")
        for secret in staging_compose["secrets"].values()
    )
    assert staging_services["postgres"]["container_name"] == (
        "sitbank-staging-postgres"
    )
    assert staging_services["postgres"]["environment"]["POSTGRES_USER"] == "sitbank_owner"
    assert (
        staging_services["postgres"]["environment"]["POSTGRES_PASSWORD_FILE"]
        == "/run/secrets/postgres_owner_password"
    )
    assert {secret["source"] if isinstance(secret, dict) else secret for secret in staging_services["postgres"]["secrets"]} == {
        "postgres_owner_password",
        "postgres_app_password",
    }
    assert any(
        volume["source"]
        == "/etc/sitbank-staging/postgres/init-sitbank-staging-roles.sh"
        for volume in staging_services["postgres"]["volumes"]
        if isinstance(volume, dict)
    )
    assert "ports" not in staging_services["postgres"]
    assert staging_app["command"][
        staging_app["command"].index("--bind") + 1
    ] == "0.0.0.0:5000"
    assert all(
        set(secret) == {"source", "target"}
        for secret in staging_app["secrets"]
    )
    assert staging_compose["volumes"]["sitbank-staging-postgres-data"]["name"] == (
        "sitbank-staging-postgres-data"
    )
    assert "/etc/sitbank-staging" not in compose_text
    assert "/etc/sitbank/" not in staging_compose_text
    assert "sitbank-staging-postgres-data" not in compose_text
    assert "sitbank-staging-redis-data" not in compose_text
    assert "--wait --wait-timeout 120" in deploy_script
    assert deploy_script.count("--retry-all-errors") == 3
    assert "show_app_diagnostics" in deploy_script
    assert "DATABASE_MIGRATION_URL_FILE=/run/secrets/database_migration_url" in deploy_script
    assert "Staging runtime database URL must use only the staging app role" in deploy_script
    assert "Staging migration database URL must use only the staging owner role" in deploy_script
    assert "Staging runtime and migration database URLs must be different" in deploy_script
    assert "Staging database URL must target only the staging PostgreSQL service" not in deploy_script
    assert "Staging admin runtime database URL must use only the staging admin role" in deploy_script
    assert "Staging admin runtime database URL must be distinct from app and migration URLs" in deploy_script
    assert "Staging admin session lookup HMAC key must be distinct from the customer key" in deploy_script
    assert 'unquote(database.username or "") != "sitbank_app"' in deploy_script
    assert 'unquote(migration.username or "") != "sitbank_owner"' in deploy_script
    assert 'unquote(admin_database.username or "") != "sitbank_admin"' in deploy_script
    assert "postgres_app_password" in deploy_script
    assert "postgres_owner_password" in deploy_script
    assert "admin_database_url" in deploy_script
    assert "admin_session_lookup_hmac_key" in deploy_script
    assert "apply-runtime-db-privileges" in deploy_script
    assert "apply-admin-runtime-db-privileges" in deploy_script
    assert "apply_admin_runtime_db_privileges" in deploy_script
    assert "verify-runtime-db-privileges" in deploy_script
    assert "validate_production_admin_isolation" in deploy_script
    assert "ADMIN_APP_BIND_PORT='5002'" in deploy_script
    assert "ADMIN_PUBLIC_HOST='admin-sitbank.duckdns.org'" in deploy_script
    assert "Admin runtime database URL is required for production" in deploy_script
    assert "Admin runtime database role must be distinct from customer runtime role" in deploy_script
    assert "Admin runtime database role must not be the migration/schema-owner role" in deploy_script
    assert "python -m flask --app admin_wsgi:app production-check" in deploy_script
    assert '"http://${APP_BIND_HOST}:5002/health/ready"' in deploy_script
    deploy_db_sequence = re.search(
        r"migration_run \\\n    python -m flask --app wsgi:app db upgrade"
        r".*?if \[\[ -n \"\$\{previous_image\}\" \]\]; then",
        deploy_script,
        flags=re.DOTALL,
    )
    assert deploy_db_sequence is not None
    deploy_db_sequence_text = deploy_db_sequence.group(0)
    assert deploy_db_sequence_text.index("db upgrade") < deploy_db_sequence_text.index("apply-runtime-db-privileges")
    assert deploy_db_sequence_text.index("apply-runtime-db-privileges") < deploy_db_sequence_text.index("apply_admin_runtime_db_privileges")
    assert deploy_db_sequence_text.index("apply_admin_runtime_db_privileges") < deploy_db_sequence_text.index("verify-runtime-db-privileges")
    assert deploy_db_sequence_text.index("verify-runtime-db-privileges") < deploy_db_sequence_text.index("production-check")
    assert "staging_migration_run" not in deploy_script
    assert deploy_script.count("migration_run \\") == 3
    assert (
        "Complete the production database role split and install the "
        "owner-role migration URL before retrying deployment."
        in deploy_script
    )
    assert "DATABASE_MIGRATION_URL must not be configured for the runtime app" in Path(
        "app/security/production_guard.py"
    ).read_text(encoding="utf-8")
    assert "adopt-existing)" in database_cutover
    assert "CUTOVER_MODE=adopt-existing" in database_cutover
    assert 'SOURCE_DATABASE=${TARGET_DATABASE}' in database_cutover
    assert 'GRANT CONNECT ON DATABASE "${TARGET_DATABASE}" TO "${source_role}";' in (
        database_cutover
    )
    assert 'DROP OWNED BY \\"${SOURCE_ROLE}\\";' in database_cutover
    assert "restart_previous_services" in database_cutover
    assert "Refusing to adopt a privileged PostgreSQL source role" in database_cutover
    show_app_diagnostics = re.search(
        r"show_app_diagnostics\(\) \{(.*?)\n\}",
        deploy_script,
        flags=re.DOTALL,
    )
    assert show_app_diagnostics is not None
    assert "logs --no-color --tail 80 app" in show_app_diagnostics.group(1)
    assert "logs --no-color --tail 80 admin" in show_app_diagnostics.group(1)
    assert '[[ "${target}" == "production" ]]' not in show_app_diagnostics.group(1)
    assert "runuser -u sitbank-container" in deploy_script
    assert "cannot traverse secret directory" in deploy_script
    assert '"${config_root}/secrets"' in bootstrap
    assert "init-sitbank-staging-roles.sh" in bootstrap
    assert '-g "${CONTAINER_GID}" -m 0750' in bootstrap

    app_python = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("app").rglob("*.py")
    )
    assert not re.search(r"\bperl\b", app_python, flags=re.IGNORECASE)
    assert not re.search(
        r"\b(tarfile|zipfile|unpack_archive)\b",
        app_python,
        flags=re.IGNORECASE,
    )


def test_workflow_builds_scans_signs_and_deploys_only_an_immutable_digest():
    workflow_text = Path(".github/workflows/ci-deploy.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)
    deploy_script = Path(
        "ops/deploy/sitbank-container-deploy"
    ).read_text(encoding="utf-8")
    runtime_script = Path(
        "ops/deploy/sitbank-container-runtime"
    ).read_text(encoding="utf-8")
    bootstrap = Path(
        "ops/deploy/bootstrap-container-ec2"
    ).read_text(encoding="utf-8")

    assert set(workflow["jobs"]) == {
        "resolve-source",
        "workflow-security",
        "dependency-review",
        "test",
        "image-test",
        "deployment-preflight",
        "publish",
        "release-verify",
        "deploy-staging",
        "verify-staging-tls",
        "deploy-production",
        "verify-production-tls",
    }
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["workflow-security"]["permissions"]["contents"] == "read"
    assert workflow["jobs"]["publish"]["permissions"]["packages"] == "write"
    assert "id-token" not in workflow["jobs"]["publish"]["permissions"]
    assert "attestations" not in workflow["jobs"]["publish"]["permissions"]
    assert workflow["jobs"]["release-verify"]["permissions"]["id-token"] == "write"
    assert workflow["jobs"]["release-verify"]["permissions"]["packages"] == "write"
    publish_condition = workflow["jobs"]["publish"]["if"]
    release_verify_condition = workflow["jobs"]["release-verify"]["if"]
    for condition in (publish_condition, release_verify_condition):
        assert "github.event_name != 'pull_request'" in condition
        assert "github.ref == 'refs/heads/main'" in condition
        assert "github.event_name == 'push'" in condition
        assert "github.event_name == 'workflow_dispatch'" in condition
        assert "inputs.target_environment == 'staging'" in condition
        assert "inputs.target_environment == 'production'" not in condition
    source_job = workflow["jobs"]["resolve-source"]
    source_step = next(
        step
        for step in source_job["steps"]
        if step["name"] == "Resolve candidate source to an immutable commit"
    )
    assert source_job["permissions"] == {"contents": "read"}
    assert source_job["outputs"]["source_sha"] == (
        "${{ steps.resolve.outputs.source_sha }}"
    )
    assert source_step["env"]["SOURCE_REF_INPUT"] == "${{ inputs.source_ref }}"
    assert "git rev-parse --verify" in source_step["run"]
    assert "refs/remotes/origin/" in source_step["run"]
    assert "refs/tags/" in source_step["run"]
    assert "source_ref_display" in source_step["run"]
    assert "refs/heads/main" in source_step["run"]
    dispatch_inputs = workflow[True]["workflow_dispatch"]["inputs"]
    assert dispatch_inputs["source_ref"]["required"] is True
    assert dispatch_inputs["source_ref"]["type"] == "string"
    assert dispatch_inputs["target_environment"]["options"] == ["staging"]
    assert dispatch_inputs["run_dast"]["required"] is True
    assert dispatch_inputs["run_dast"]["type"] == "boolean"
    assert dispatch_inputs["run_dast"]["default"] is True
    preflight_step = next(
        step
        for step in workflow["jobs"]["deployment-preflight"]["steps"]
        if step["name"] == "Validate release request"
    )
    preflight_run = preflight_step["run"]
    assert "staging|production" not in preflight_run
    assert "PROD_DEPLOY_ENABLED is not true" in preflight_run
    assert "Automatic production deployment will be skipped." in preflight_run
    assert "Missing required production deployment setting" not in preflight_run
    candidate_jobs = ("test", "publish")
    for job_name in candidate_jobs:
        checkout = next(
            step
            for step in workflow["jobs"][job_name]["steps"]
            if step["name"] == "Check out repository"
        )
        assert checkout["with"]["ref"] == (
            "${{ needs.resolve-source.outputs.source_sha }}"
        )
    release_trusted_checkout = next(
        step
        for step in workflow["jobs"]["release-verify"]["steps"]
        if step["name"] == "Check out trusted workflow repository state"
    )
    assert release_trusted_checkout["with"]["ref"] == "${{ github.workflow_sha }}"
    release_candidate_checkout = next(
        step
        for step in workflow["jobs"]["release-verify"]["steps"]
        if step["name"] == "Check out candidate source"
    )
    assert release_candidate_checkout["with"]["ref"] == (
        "${{ needs.publish.outputs.revision }}"
    )
    assert release_candidate_checkout["with"]["path"] == "candidate-source"
    trusted_jobs = ("deploy-staging", "deploy-production")
    for job_name in trusted_jobs:
        checkout = next(
            step
            for step in workflow["jobs"][job_name]["steps"]
            if step["name"] == "Check out repository"
        )
        assert checkout["with"]["ref"] == "${{ github.workflow_sha }}"
    assert workflow["jobs"]["release-verify"]["needs"] == "publish"
    release_verify_steps = [
        step["name"] for step in workflow["jobs"]["release-verify"]["steps"]
    ]
    assert release_verify_steps.index("Log in to GHCR") < release_verify_steps.index(
        "Sign and verify the tested immutable digest"
    )
    release_image_step = next(
        step
        for step in workflow["jobs"]["release-verify"]["steps"]
        if step["name"] == "Resolve verified image reference"
    )
    assert (
        release_image_step["env"]["IMAGE_DIGEST"]
        == "${{ needs.publish.outputs.digest }}"
    )
    release_smoke_step = next(
        step
        for step in workflow["jobs"]["release-verify"]["steps"]
        if step["name"] == "Smoke-test and DAST-scan the exact published digest"
    )
    release_compose_step = next(
        step
        for step in workflow["jobs"]["release-verify"]["steps"]
        if step["name"] == "Validate production and staging Compose models for the exact digest"
    )
    assert release_compose_step["run"] == (
        'bash candidate-source/ops/container/validate-compose.sh "${SITBANK_IMAGE}"'
    )
    assert release_smoke_step["run"] == (
        'bash candidate-source/ops/container/smoke-test.sh "${IMAGE}"'
    )
    release_dast_policy = (
        "${{ github.event_name != 'workflow_dispatch' || inputs.run_dast == true }}"
    )
    assert release_smoke_step["env"]["RUN_ZAP_DAST"] == release_dast_policy
    assert "github.event_name != 'workflow_dispatch'" in release_dast_policy
    assert "inputs.run_dast == true" in release_dast_policy
    image_smoke_step = next(
        step
        for step in workflow["jobs"]["image-test"]["steps"]
        if step["name"] == "Run container smoke test and scheduled authenticated DAST"
    )
    assert image_smoke_step["run"] == (
        "bash ops/container/smoke-test.sh sitbank:pr"
    )
    assert image_smoke_step["env"]["RUN_ZAP_DAST"] == (
        "${{ github.event_name == 'schedule' && 'true' || 'false' }}"
    )
    assert image_smoke_step["env"]["RUN_ZAP_DAST"] != "true"
    assert 'if [[ "${RUN_ZAP_DAST:-false}" == "true" ]]' in Path(
        "ops/container/smoke-test.sh"
    ).read_text(encoding="utf-8")
    assert (
        release_image_step["env"]["RELEASE_SHA"]
        == "${{ needs.publish.outputs.revision }}"
    )
    assert workflow["jobs"]["deploy-staging"]["permissions"]["packages"] == "read"
    assert workflow["jobs"]["deploy-staging"]["permissions"]["id-token"] == "write"
    assert workflow["jobs"]["deploy-production"]["permissions"]["packages"] == "read"
    assert workflow["jobs"]["deploy-production"]["permissions"]["id-token"] == "write"
    staging_condition = workflow["jobs"]["deploy-staging"]["if"]
    production_condition = workflow["jobs"]["deploy-production"]["if"]
    assert "github.event_name != 'pull_request'" in staging_condition
    assert "needs.release-verify.result == 'success'" in staging_condition
    assert "github.event_name == 'push'" in staging_condition
    assert "github.ref == 'refs/heads/main'" in staging_condition
    assert "github.event_name == 'workflow_dispatch'" in staging_condition
    assert "github.ref == 'refs/heads/main'" in staging_condition
    assert "inputs.target_environment == 'staging'" in staging_condition
    assert "inputs.deploy == true" in staging_condition
    assert "vars.STAGING_DEPLOY_ENABLED == 'true'" in staging_condition
    assert "always()" in production_condition
    assert "github.event_name == 'push'" in production_condition
    assert "github.event_name == 'workflow_dispatch'" not in production_condition
    assert "github.ref == 'refs/heads/main'" in production_condition
    assert "inputs.target_environment == 'production'" not in production_condition
    assert "inputs.deploy == true" not in production_condition
    assert "vars.PROD_DEPLOY_ENABLED == 'true'" in production_condition
    assert "needs.release-verify.result == 'success'" in production_condition
    assert "needs.deploy-staging.result == 'success'" in production_condition
    assert "needs.verify-staging-tls.result == 'success'" in production_condition
    assert "vars.STAGING_DEPLOY_ENABLED != 'true'" not in production_condition
    assert workflow["jobs"]["deploy-production"]["needs"] == [
        "release-verify",
        "deploy-staging",
        "verify-staging-tls",
    ]
    staging_tls = workflow["jobs"]["verify-staging-tls"]
    production_tls = workflow["jobs"]["verify-production-tls"]
    assert staging_tls["uses"] == "./.github/workflows/tls-scan.yml"
    assert staging_tls["needs"] == "deploy-staging"
    assert "always()" in staging_tls["if"]
    assert "needs.deploy-staging.result == 'success'" in staging_tls["if"]
    assert staging_tls["with"] == {
        "scan_scope": "staging",
        "staging_host": "${{ vars.STAGING_PUBLIC_HOST }}",
    }
    assert production_tls["uses"] == "./.github/workflows/tls-scan.yml"
    assert production_tls["needs"] == "deploy-production"
    assert "always()" in production_tls["if"]
    assert "needs.deploy-production.result == 'success'" in production_tls["if"]
    assert production_tls["with"] == {
        "scan_scope": "production",
        "production_host": "${{ vars.PROD_PUBLIC_HOST }}",
    }
    staging_deploy_env = workflow["jobs"]["deploy-staging"]["env"]
    production_deploy_env = workflow["jobs"]["deploy-production"]["env"]
    assert not any(name.startswith("PROD_") for name in staging_deploy_env)
    assert (
        staging_deploy_env["IMAGE_DIGEST"]
        == "${{ needs.release-verify.outputs.digest }}"
    )
    assert (
        staging_deploy_env["STAGING_MFA_KEK_ACTIVE_ID"]
        == "${{ vars.STAGING_MFA_KEK_ACTIVE_ID }}"
    )
    assert (
        staging_deploy_env["STAGING_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID"]
        == "${{ vars.STAGING_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID }}"
    )
    assert (
        staging_deploy_env["STAGING_PASSWORD_RESET_EMAIL_FROM"]
        == "${{ vars.STAGING_PASSWORD_RESET_EMAIL_FROM }}"
    )
    assert staging_deploy_env["STAGING_SMTP_HOST"] == "${{ vars.STAGING_SMTP_HOST }}"
    assert (
        production_deploy_env["IMAGE_DIGEST"]
        == "${{ needs.release-verify.outputs.digest }}"
    )
    assert (
        production_deploy_env["PROD_MFA_KEK_ACTIVE_ID"]
        == "${{ vars.PROD_MFA_KEK_ACTIVE_ID }}"
    )
    assert (
        workflow["jobs"]["deploy-production"]["env"]["PROD_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID"]
        == "${{ vars.PROD_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID }}"
    )
    assert (
        production_deploy_env["PROD_PASSWORD_RESET_EMAIL_FROM"]
        == "${{ vars.PROD_PASSWORD_RESET_EMAIL_FROM }}"
    )
    assert production_deploy_env["PROD_SMTP_HOST"] == "${{ vars.PROD_SMTP_HOST }}"
    for job_name, verify_step_name, required_names in (
        (
            "deploy-staging",
            "Verify staging deployment configuration",
            {
                "STAGING_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID",
                "STAGING_PASSWORD_RESET_EMAIL_FROM",
                "STAGING_SMTP_HOST",
            },
        ),
        (
            "deploy-production",
            "Verify production deployment configuration",
            {
                "PROD_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID",
                "PROD_PASSWORD_RESET_EMAIL_FROM",
                "PROD_SMTP_HOST",
            },
        ),
    ):
        verify_step = next(
            step
            for step in workflow["jobs"][job_name]["steps"]
            if step["name"] == verify_step_name
        )
        assert required_names <= set(_extract_bash_array(verify_step["run"], "required"))
    assert workflow["jobs"]["publish"]["needs"] == [
        "test",
        "workflow-security",
        "deployment-preflight",
        "resolve-source",
    ]
    assert (
        workflow["jobs"]["image-test"]["if"]
        == "github.event_name == 'pull_request' || github.event_name == 'schedule'"
    )
    assert "schedule" in workflow[True]
    assert "github.event_name == 'schedule'" not in workflow["jobs"]["publish"]["if"]
    assert all(
        "uses" in job or job["timeout-minutes"] > 0
        for job in workflow["jobs"].values()
    )
    assert "vars.PROD_DEPLOY_ENABLED == 'true'" in workflow_text
    assert "vars.STAGING_DEPLOY_ENABLED == 'true'" in workflow_text
    assert "workflow_dispatch" in workflow_text
    assert "target_environment" in workflow_text
    assert "run_dast" in workflow_text
    assert "deploy-staging" in workflow_text
    assert "deploy-production" in workflow_text
    assert "PROD_EC2_HOST" in workflow_text
    assert "PROD_EC2_SSH_PRIVATE_KEY_B64" in workflow_text
    assert "STAGING_EC2_HOST" in workflow_text
    assert "STAGING_EC2_SSH_PRIVATE_KEY_B64" in workflow_text
    assert workflow_text.count("ssh-keygen -y -P") == 2
    assert workflow_text.count("base64 --decode > ~/.ssh/deploy_key") == 2
    assert workflow_text.count("^[A-Za-z0-9+/]+={0,2}$") == 2
    assert "STAGING_EC2_SSH_PRIVATE_KEY:" not in workflow_text
    assert "PROD_EC2_SSH_PRIVATE_KEY:" not in workflow_text
    assert workflow_text.count("-i ~/.ssh/deploy_key") == 6
    assert workflow_text.count(
        "sha256sum ops/deploy/sitbank-container-deploy"
    ) == 2
    assert workflow_text.count("sha256sum compose.staging.yml") == 1
    assert workflow_text.count("sha256sum compose.prod.yml") == 1
    assert workflow_text.count(
        "sha256sum /usr/local/sbin/sitbank-container-deploy"
    ) == 2
    assert workflow_text.count("/opt/sitbank-staging/compose.yml") >= 2
    assert workflow_text.count("/opt/sitbank/compose.yml") >= 2
    assert "EC2 staging deployment wrapper is missing or stale" in workflow_text
    assert "EC2 production deployment wrapper is missing or stale" in workflow_text
    assert "EC2 staging compose file is missing or stale" in workflow_text
    assert "EC2 production compose file is missing or stale" in workflow_text
    for job_name, wrapper_step_name, upload_step_name in (
        (
            "deploy-staging",
            "Verify trusted staging deployment files",
            "Upload authenticated deployment inputs",
        ),
        (
            "deploy-production",
            "Verify trusted production deployment files",
            "Upload authenticated deployment inputs",
        ),
    ):
        step_names = [
            step["name"] for step in workflow["jobs"][job_name]["steps"]
        ]
        assert step_names.index(wrapper_step_name) < step_names.index(upload_step_name)
    assert "~/.ssh/id_ed25519" not in workflow_text
    assert "vars.EC2_" not in workflow_text
    assert "secrets.EC2_" not in workflow_text
    assert "provenance: mode=max" in workflow_text
    assert "sbom: true" in workflow_text
    assert "ignore-unfixed: false" in workflow_text
    assert "ignore-unfixed: true" in workflow_text
    assert workflow_text.count("Report all critical vulnerabilities") == 2
    assert workflow_text.count("Block unexpected critical vulnerabilities") == 2
    assert workflow_text.count('exit-code: "0"') == 2
    assert workflow_text.count('exit-code: "1"') == 4
    assert workflow_text.count("trivyignores: .trivyignore") == 2
    assert workflow_text.count("TRIVY_IGNOREFILE: /dev/null") == 4
    assert "pull: ${{ github.event_name == 'schedule' }}" in workflow_text
    assert "no-cache: ${{ github.event_name == 'schedule' }}" in workflow_text
    assert "cosign sign --yes" in workflow_text
    assert "cosign sign-blob --yes" in workflow_text
    assert workflow_text.count("Build and push the release candidate once") == 1
    assert ":latest" not in workflow_text
    assert "cosign verify-blob" in deploy_script
    assert "runtime-${RELEASE_SHA}.sigstore.json" in workflow_text
    assert "RUN_ZAP_DAST" in workflow_text
    assert "dependency-review-action@" in workflow_text
    assert "zizmorcore/zizmor-action@" in workflow_text
    assert "actionlint" in workflow_text
    assert "shellcheck" in workflow_text
    assert "ops/container/validate-compose.sh" in workflow_text
    assert "ops/container/dast-smoke.sh" in workflow_text
    assert "scan_repository_secrets.py" in workflow_text
    assert "scan_repository_secrets.py --history" in workflow_text
    assert "check_dependency_locks.py" in workflow_text
    assert "IMAGE_DIGEST" in workflow_text
    assert "StrictHostKeyChecking=no" not in workflow_text
    checkout_uses = [
        action for action in _workflow_uses(workflow_text)
        if action.startswith("actions/checkout@")
    ]
    setup_python_uses = [
        action for action in _workflow_uses(workflow_text)
        if action.startswith("actions/setup-python@")
    ]
    assert len(checkout_uses) == 10
    assert workflow_text.count("persist-credentials: false") == len(checkout_uses)
    _assert_pinned_actions(checkout_uses, context="actions/checkout")
    _assert_pinned_actions(
        setup_python_uses,
        context="actions/setup-python",
    )
    assert "sitbank:pr" in workflow_text
    assert "SITBANK_IMAGE" in workflow_text
    assert "source_ref" in workflow_text
    assert "source_sha" in workflow_text
    assert "VCS_REF=${{ needs.resolve-source.outputs.source_sha }}" in workflow_text
    assert "RELEASE_SHA: ${{ needs.publish.outputs.revision }}" in workflow_text
    assert workflow_text.count("ref: ${{ github.workflow_sha }}") == 4
    assert workflow_text.count(
        "ref: ${{ needs.resolve-source.outputs.source_sha }}"
    ) == 2
    assert "ref: ${{ needs.publish.outputs.revision }}" in workflow_text
    assert "candidate-source/ops/container/smoke-test.sh" in workflow_text
    assert "RELEASE_SHA: ${{ github.sha }}" not in workflow_text
    assert "SITBANK_SECRET_KEY" not in workflow_text
    assert "STAGING_SECRET_KEY" not in workflow_text
    assert "STAGING_DATABASE_URL" not in workflow_text
    assert "STAGING_MFA_KEK_KEYS_JSON" not in workflow_text
    assert "PROD_SECRET_KEY" not in workflow_text
    assert "PROD_ADMIN_SECRET_KEY" not in workflow_text
    assert "PROD_ADMIN_DATABASE_URL" not in workflow_text
    assert "PROD_ADMIN_REDIS_URL" not in workflow_text
    assert "PROD_DATABASE_URL" not in workflow_text
    assert "PROD_MFA_KEK_KEYS_JSON" not in workflow_text
    assert "STAGING_MFA_KEK_ACTIVE_ID" in workflow_text
    assert "PROD_MFA_KEK_ACTIVE_ID" in workflow_text
    assert "--environment-only" in workflow_text
    assert "--prefix STAGING" in workflow_text
    assert "--prefix PROD" in workflow_text
    assert "sitbank-container-deploy" in workflow_text
    assert "runtime-staging-${RELEASE_SHA}" in workflow_text
    assert "registry-staging-${RELEASE_SHA}.credentials" in workflow_text
    assert (
        "sitbank-container-deploy staging '${RELEASE_SHA}' '${IMAGE_DIGEST}'"
        in workflow_text
    )
    assert (
        "sitbank-container-deploy '${RELEASE_SHA}' '${IMAGE_DIGEST}'"
        in workflow_text
    )
    assert "sha256:[0-9a-f]{64}" in deploy_script
    assert "COSIGN_CERTIFICATE_IDENTITY" in deploy_script
    assert "COSIGN_CERTIFICATE_IDENTITY_REGEXP" not in deploy_script
    assert "--certificate-identity-regexp" not in deploy_script
    assert "ci-deploy.yml@refs/heads/main" in deploy_script
    assert "org.opencontainers.image.revision" in deploy_script
    assert "production-check" in deploy_script
    assert "db upgrade" in deploy_script
    assert "previous_image" in deploy_script
    assert "restore_runtime" in deploy_script
    assert "secrets/database_url" not in deploy_script
    assert "audit_log" in deploy_script
    assert "load_runtime_secrets" not in deploy_script
    assert "SITBANK_SECRET_KEY" not in deploy_script
    assert "SITBANK_SECRET_KEY" not in runtime_script
    assert "/etc/sitbank-staging/deploy.conf" in deploy_script
    assert "/opt/sitbank-staging/compose.yml" in deploy_script
    assert "/var/lib/sitbank-staging-container" in deploy_script
    assert "sitbank-staging-container.service" in deploy_script
    assert "sitbank-staging-postgres-data" in deploy_script
    assert "Staging secret must not reuse the production" in deploy_script
    assert "hostname != \"postgres\"" in deploy_script
    assert "hostname != \"redis\"" not in deploy_script
    assert "sitbank-container-runtime staging up" in Path(
        "ops/systemd/sitbank-staging-container.service"
    ).read_text(encoding="utf-8")
    assert "--project-name \"${COMPOSE_PROJECT}\"" in runtime_script
    assert "gpasswd --delete" in bootstrap
    assert "docker.sock" in bootstrap
    assert "grep -Eq ':(2375|2376)([[:space:]]|$)'" in bootstrap
    assert "grep -Eq ':(2375|2376)([[:space:]]|$)'" in deploy_script
    assert "COSIGN_SHA256" in bootstrap
    assert "COSIGN_CERTIFICATE_IDENTITY_REGEXP" not in bootstrap
    assert "ci-deploy.yml@refs/heads/main" in bootstrap
    assert "/opt/sitbank" in bootstrap
    assert "/etc/sitbank" in bootstrap
    assert "/var/lib/sitbank-container" in bootstrap
    assert "/opt/sitbank-staging" in bootstrap
    assert "/etc/sitbank-staging" in bootstrap
    assert "/var/lib/sitbank-staging-container" in bootstrap
    assert "sitbank-deploy" in bootstrap
    assert "sitbank-container.service" in bootstrap
    assert "sitbank-staging-container.service" in bootstrap
    assert "sitbank-security-alerts.service" in bootstrap
    assert "sitbank-security-alerts.timer" in bootstrap
    docs = _project_docs_text()
    assert "Manual pre-merge staging:" in docs
    assert "run trusted workflow from main" in docs
    assert "source_ref = candidate branch, tag, or SHA" in docs
    assert "resolve immutable source_sha" in docs
    assert "deploy staging using trusted main scripts" in docs
    assert "main push -> publish -> release-verify -> staging -> production" in docs
    assert "manual production dispatch -> publish -> release-verify -> production" not in docs
    assert "Production deployment is manual-only." not in docs
    assert "target_environment = production" not in docs
    assert "PROD_DEPLOY_ENABLED = true" in docs
    assert "Production never skips disabled, skipped, or failed staging." in docs
    assert "PROD_ADMIN_SESSION_HMAC_ACTIVE_KEY_ID" in docs
    assert "environment-specific settings, including SMTP sender/host values" in docs
    assert "Feature-branch workflow and deployment scripts" in docs
    assert "adopt-existing" in docs


def test_manual_bootstrap_workflow_uses_only_signed_trusted_main_sources():
    workflow_path = Path(".github/workflows/bootstrap-ec2.yml")
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)
    triggers = workflow[True]

    assert workflow["name"] == "Bootstrap EC2 from trusted main"
    assert set(triggers) == {"workflow_dispatch"}
    dispatch = triggers["workflow_dispatch"]
    target_input = dispatch["inputs"]["target_environment"]
    assert target_input["required"] is True
    assert target_input["type"] == "choice"
    assert target_input["options"] == ["staging", "production"]
    assert workflow["permissions"] == {}
    assert set(workflow["jobs"]) == {
        "validate-request",
        "bootstrap-staging",
        "bootstrap-production",
    }

    guard_step = workflow["jobs"]["validate-request"]["steps"][0]
    assert "refs/heads/main" in guard_step["run"]
    assert "GITHUB_WORKFLOW_SHA" in guard_step["run"]

    for target, prefix in (("staging", "STAGING"), ("production", "PROD")):
        job = workflow["jobs"][f"bootstrap-{target}"]
        assert job["if"] == f"inputs.target_environment == '{target}'"
        assert job["needs"] == "validate-request"
        assert job["environment"]["name"] == target
        assert job["permissions"] == {
            "contents": "read",
            "id-token": "write",
        }
        assert job["env"]["TARGET"] == target
        assert job["env"]["TRUSTED_SHA"] == "${{ github.workflow_sha }}"
        assert job["env"]["REMOTE_HOST"] == (
            f"${{{{ vars.{prefix}_EC2_HOST }}}}"
        )
        checkout = next(
            step
            for step in job["steps"]
            if step["name"] == "Check out trusted main workflow commit"
        )
        assert checkout["with"]["ref"] == "${{ github.workflow_sha }}"
        assert checkout["with"]["persist-credentials"] is False
        assert checkout["with"]["fetch-depth"] == 0
        step_text = "\n".join(
            str(step.get("run", "")) for step in job["steps"]
        )
        assert "git archive" in step_text
        assert "--add-virtual-file" in step_text
        assert "cosign sign-blob --yes" in step_text
        assert "StrictHostKeyChecking=yes" in step_text
        assert "StrictHostKeyChecking=no" not in step_text
        assert "incoming/" in step_text
        assert (
            "sudo -n /usr/local/sbin/sitbank-container-bootstrap "
            "'${TARGET}' '${TRUSTED_SHA}'"
        ) in step_text
        assert (
            "sudo -n -l /usr/local/sbin/sitbank-container-bootstrap"
            in step_text
        )
        assert "one-time administrator bootstrap from merged main" in step_text
        assert "sha256sum ops/deploy/sitbank-container-deploy" in step_text
        assert (
            "sha256sum /usr/local/sbin/sitbank-container-deploy"
            in step_text
        )

    assert "pull_request:" not in workflow_text
    assert "\npush:" not in workflow_text
    assert "\nschedule:" not in workflow_text
    assert "sitbank-container-deploy staging" not in workflow_text
    assert "IMAGE_DIGEST" not in workflow_text
    assert ":latest" not in workflow_text
    assert "STAGING_EC2_SSH_PRIVATE_KEY_B64" in workflow_text
    assert "PROD_EC2_SSH_PRIVATE_KEY_B64" in workflow_text
    assert "STAGING_EC2_KNOWN_HOSTS" in workflow_text
    assert "PROD_EC2_KNOWN_HOSTS" in workflow_text


def test_root_bootstrap_wrapper_authenticates_and_limits_privileged_updates():
    wrapper = Path("ops/deploy/sitbank-container-bootstrap").read_text(
        encoding="utf-8"
    )
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(
        encoding="utf-8"
    )
    sudoers = Path("ops/sudoers/sitbank-container-deploy").read_text(
        encoding="utf-8"
    )

    assert "TARGET TRUSTED_MAIN_SHA" in wrapper
    assert "bootstrap-ec2.yml@refs/heads/main" in wrapper
    assert "cosign verify-blob" in wrapper
    assert 'trusted_sha}" =~ ^[0-9a-f]{40}$' in wrapper
    assert ".sitbank-bootstrap-commit" in wrapper
    assert "token.actions.githubusercontent.com" in wrapper
    assert "Bootstrap input must be owned by" in wrapper
    assert "Unsafe bootstrap archive member" in wrapper
    assert "unsupported special file" in wrapper
    assert "/var/lock/sitbank-container-deploy.lock" in wrapper
    assert "/var/lock/sitbank-staging-container-deploy.lock" in wrapper
    assert "An application deployment is running" in wrapper
    assert "sitbank-container-deploy" in wrapper
    assert "sha256sum /usr/local/sbin/sitbank-container-deploy" in wrapper
    assert "sitbank-container-bootstrap" in bootstrap
    assert "/usr/local/sbin/sitbank-container-bootstrap" in bootstrap
    assert "OWNER/REPOSITORY [PUBLIC_HOST]" in bootstrap
    deployment_scripts = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "ops/deploy/bootstrap-container-ec2",
            "ops/deploy/sitbank-container-bootstrap",
            "ops/deploy/sitbank-container-deploy",
            "ops/deploy/sitbank-database-cutover",
        )
    )
    for forbidden in (
        "LEGACY_SERVICE",
        "LEGACY_APP_ROOT",
        "import_legacy_env.py",
        "legacy service",
        "former application",
    ):
        assert forbidden not in deployment_scripts
    assert sudoers.splitlines() == [
        (
            "sitbank-deploy ALL=(root) NOPASSWD: "
            "/usr/local/sbin/sitbank-container-deploy"
        ),
        (
            "sitbank-deploy ALL=(root) NOPASSWD: "
            "/usr/local/sbin/sitbank-container-bootstrap"
        ),
    ]
    assert "NOPASSWD: ALL" not in sudoers
    assert "/bin/bash" not in sudoers


def test_trivy_exception_is_narrow_documented_and_temporary():
    trivyignore = Path(".trivyignore").read_text(encoding="utf-8")
    docs = _project_docs_text()
    security = Path("SECURITY.md").read_text(encoding="utf-8")
    active_ignores = [
        line.strip()
        for line in trivyignore.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert active_ignores == ["CVE-2026-42496", "CVE-2026-8376"]
    for required in (
        "official python:3.12 slim-trixie / Debian Trixie",
        "does not install Perl directly",
        "Essential: yes",
        "must not be removed",
        "does not invoke Perl",
        "does not process attacker-controlled tar archives with Perl",
        "temporary",
        "review/remove-by date: 2026-06-26",
    ):
        assert required in trivyignore
    assert "CVE-2026-42496" in docs
    assert "CVE-2026-8376" in docs
    assert "2026-06-26" in docs
    assert "mixing Debian sid packages into Trixie is riskier" in docs
    assert "full Critical Trivy report with no ignore file" in docs
    assert "fixable High/Critical gate must continue to run without" in security


def test_dependabot_tracks_docker_base_images_without_automerge():
    dependabot = yaml.safe_load(Path(".github/dependabot.yml").read_text(encoding="utf-8"))
    docs = _project_docs_text()
    docker_updates = [
        update
        for update in dependabot["updates"]
        if update["package-ecosystem"] == "docker"
    ]

    assert len(docker_updates) == 1
    docker_update = docker_updates[0]
    assert docker_update["directory"] == "/"
    assert docker_update["schedule"]["interval"] == "weekly"
    assert docker_update["ignore"] == [
        {"dependency-name": "python", "versions": [">=3.13"]}
    ]
    assert "Dependabot updates are review-only" in docs
    assert "Base-image updates must not be auto-merged" in docs
    assert "container smoke test, Compose" in docs
    assert "Ordinary pull requests skip the full authenticated DAST crawl" in docs
    assert "scheduled scans" in docs
    assert "release verification retains that coverage" in docs


def test_codeowners_and_codeql_cover_security_sensitive_changes():
    codeowners = Path(".github/CODEOWNERS").read_text(encoding="utf-8")
    codeql = Path(".github/workflows/codeql.yml").read_text(encoding="utf-8")

    for protected_path in (
        "/.github/workflows/",
        "/Dockerfile",
        "/compose.prod.yml",
        "/compose.staging.yml",
        "/requirements.lock",
        "/requirements-dev.lock",
        "/ops/deploy/",
        "/ops/nginx/",
        "/ops/nginx-proxy-headers.conf",
        "/ops/security/",
    ):
        assert protected_path in codeowners
    codeql_uses = _workflow_uses(codeql)
    init_actions = [
        action for action in codeql_uses
        if action.startswith("github/codeql-action/init@")
    ]
    analyze_actions = [
        action for action in codeql_uses
        if action.startswith("github/codeql-action/analyze@")
    ]
    _assert_pinned_actions(init_actions, context="github/codeql-action/init")
    _assert_pinned_actions(analyze_actions, context="github/codeql-action/analyze")
    assert "languages: python" in codeql


def test_every_github_action_is_pinned_to_a_full_commit_sha():
    workflow_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path(".github/workflows").glob("*.yml")
    )
    uses = _workflow_uses(workflow_text)

    _assert_pinned_actions(uses, context="GitHub Actions workflow")
    assert "pull_request_target:" not in workflow_text


def test_live_tls_scan_workflow_collects_evidence_without_running_on_pull_requests():
    workflow_path = Path(".github/workflows/tls-scan.yml")
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)
    triggers = workflow[True]

    assert workflow["name"] == "Live TLS scan evidence"
    assert set(triggers) == {"workflow_call", "workflow_dispatch", "schedule"}
    assert "pull_request" not in workflow_text
    assert workflow["permissions"] == {}
    assert workflow["concurrency"] == {
        "group": "live-tls-scan",
        "cancel-in-progress": False,
    }

    inputs = triggers["workflow_dispatch"]["inputs"]
    assert inputs["scan_scope"]["options"] == ["all", "staging", "production"]
    assert inputs["staging_host"]["default"] == "staging-sitbank.duckdns.org"
    assert inputs["production_host"]["default"] == "sitbank.duckdns.org"
    assert inputs["admin_host"]["default"] == "admin-sitbank.duckdns.org"

    call_inputs = triggers["workflow_call"]["inputs"]
    assert call_inputs["scan_scope"] == {
        "description": "Set of deployed endpoints to scan: all, staging, or production.",
        "required": False,
        "default": "all",
        "type": "string",
    }
    assert call_inputs["staging_host"]["required"] is False
    assert call_inputs["production_host"]["required"] is False
    assert call_inputs["admin_host"]["required"] is False

    resolver = workflow["jobs"]["resolve-targets"]
    assert resolver["timeout-minutes"] == 5
    assert resolver["outputs"]["matrix"] == "${{ steps.select.outputs.matrix }}"
    select_step = resolver["steps"][0]
    assert select_step["env"]["SCAN_SCOPE"] == "${{ inputs.scan_scope || 'all' }}"
    assert "scan_scope must be all, staging, or production" in select_step["run"]
    assert "tls-scan-staging-sitbank" in select_step["run"]
    assert "tls-scan-prod-sitbank" in select_step["run"]
    assert "tls-scan-admin-sitbank" in select_step["run"]

    scan = workflow["jobs"]["scan"]
    assert scan["needs"] == "resolve-targets"
    assert scan["timeout-minutes"] == 35
    assert scan["strategy"]["fail-fast"] is False
    assert scan["strategy"]["max-parallel"] == 3
    assert scan["strategy"]["matrix"] == "${{ fromJSON(needs.resolve-targets.outputs.matrix) }}"
    assert "testssl.sh/archive/${commit}.tar.gz" in workflow_text
    assert 'readonly commit="d2d9d2a04120033a7d1e01e52d9b409168544cc6"' in workflow_text
    assert "d35d2454e2a86d1748381602fcc51783f79bf70263cd17f1b8030da49dfc0ef6" in workflow_text
    assert "sha256sum --check --strict" in workflow_text
    assert "--jsonfile" in workflow_text
    assert "--logfile" in workflow_text
    assert "--htmlfile" in workflow_text
    assert "GITHUB_STEP_SUMMARY" in workflow_text
    assert "TLS1_1" in workflow_text
    assert "cipherlist_(NULL|aNULL|EXPORT|LOW|OBSOLETED|3DES|RC4)" in workflow_text
    assert "cert_expirationStatus" in workflow_text
    assert "cert_trust" in workflow_text
    assert "cert_chain_of_trust" in workflow_text
    assert "index($severity) != null" in workflow_text
    assert '.[]\n              | select(type == "object")\n              | select(' in workflow_text
    assert "secrets." not in workflow_text

    uses = _workflow_uses(workflow_text)
    assert uses == [
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    ]
    _assert_pinned_actions(uses, context="Live TLS scan workflow")

    deployment_docs = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    operations_docs = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
    crypto_docs = Path("docs/security/cryptography-and-authentication.md").read_text(
        encoding="utf-8"
    )
    for docs in (deployment_docs, operations_docs, crypto_docs):
        assert "live tls scan evidence" in docs.lower()
        assert "staging-sitbank.duckdns.org" in docs
        assert "sitbank.duckdns.org" in docs
        assert "admin-sitbank.duckdns.org" in docs
        assert "SSL Labs" in docs
        assert re.search(r"HIGH,\s+CRITICAL,\s+or FATAL", docs)
    assert "testssl.sh --warnings batch --color 0" in deployment_docs
    assert "tls-scan-staging-sitbank" in deployment_docs
    assert "tls-scan-prod-sitbank" in deployment_docs
    assert "tls-scan-admin-sitbank" in deployment_docs


def test_only_sitbank_container_deployment_units_are_active():
    assert not Path("ops/deploy/bootstrap-ec2").exists()
    assert Path("ops/deploy/sitbank-container-bootstrap").exists()
    assert Path("ops/deploy/sitbank-container-deploy").exists()
    assert Path("ops/deploy/sitbank-container-runtime").exists()
    assert Path("ops/deploy/sitbank-database-cutover").exists()
    assert Path("ops/systemd/sitbank-container.service").exists()
    assert Path("ops/systemd/sitbank-staging-container.service").exists()
    assert Path("ops/systemd/sitbank-security-alerts.service").exists()
    assert Path("ops/systemd/sitbank-security-alerts.timer").exists()
    assert Path("ops/sudoers/sitbank-container-deploy").exists()


def test_linux_deployment_artifacts_are_forced_to_lf_and_reject_crlf():
    attributes = Path(".gitattributes").read_text(encoding="utf-8")
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(
        encoding="utf-8"
    )
    linux_files = (
        Path("Dockerfile"),
        Path("compose.prod.yml"),
        Path("compose.staging.yml"),
        Path("ops/deploy/bootstrap-container-ec2"),
        Path("ops/deploy/sitbank-container-bootstrap"),
        Path("ops/deploy/sitbank-container-deploy"),
        Path("ops/deploy/sitbank-container-runtime"),
        Path("ops/deploy/sitbank-database-cutover"),
        Path("ops/deploy/verify-certbot-host-state"),
        Path("ops/nginx-proxy-headers.conf"),
        Path("ops/nginx/sitbank-default.conf"),
        Path("ops/nginx/sitbank-production.conf"),
        Path("ops/nginx/sitbank-production-rate-limits.conf"),
        Path("ops/nginx/sitbank-staging.conf"),
        Path("ops/nginx/sitbank-staging-rate-limits.conf"),
        Path("ops/sudoers/sitbank-container-deploy"),
        Path("ops/systemd/sitbank-container.service"),
        Path("ops/systemd/sitbank-staging-container.service"),
        Path("ops/systemd/sitbank-security-alerts.service"),
        Path("ops/systemd/sitbank-security-alerts.timer"),
    )

    assert "*.sh text eol=lf" in attributes
    assert "*.yml text eol=lf" in attributes
    assert "*.conf text eol=lf" in attributes
    assert "*.service text eol=lf" in attributes
    assert "*.timer text eol=lf" in attributes
    assert "ops/deploy/bootstrap-container-ec2 text eol=lf" in attributes
    assert "ops/deploy/sitbank-container-bootstrap text eol=lf" in attributes
    assert "ops/deploy/verify-certbot-host-state text eol=lf" in attributes
    assert "ops/sudoers/* text eol=lf" in attributes
    for path in linux_files:
        assert b"\r\n" not in path.read_bytes(), f"{path} must use LF line endings"

    assert "Refusing to install CRLF-formatted Linux file" in bootstrap
    assert "grep -q $'\\r$'" in bootstrap


def test_certbot_host_state_verifier_enforces_host_managed_tls():
    verifier_path = Path("ops/deploy/verify-certbot-host-state")
    verifier = verifier_path.read_text(encoding="utf-8")
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(
        encoding="utf-8"
    )
    production_nginx = Path("ops/nginx/sitbank-production.conf").read_text(
        encoding="utf-8"
    )
    staging_nginx = Path("ops/nginx/sitbank-staging.conf").read_text(
        encoding="utf-8"
    )

    assert verifier_path.exists()
    assert verifier.startswith("#!/usr/bin/env bash\n")
    assert 'LETSENCRYPT_ROOT="/etc/letsencrypt"' in verifier
    assert 'PRODUCTION_PUBLIC_HOST="sitbank.duckdns.org"' in verifier
    assert 'PRODUCTION_ADMIN_PUBLIC_HOST="admin-sitbank.duckdns.org"' in verifier
    assert 'STAGING_PUBLIC_HOST="staging-sitbank.duckdns.org"' in verifier
    assert 'readlink -f -- "${key_path}"' in verifier
    assert "stat -c '%U'" in verifier
    assert "stat -c '%G'" in verifier
    assert "stat -c '%a'" in verifier
    assert "world-readable or world-writable" in verifier
    assert "group-writable or world-writable" in verifier
    assert "mode_value & 0007" in verifier
    assert "mode_value & 0022" in verifier
    assert "certbot.timer" in verifier
    assert "systemctl is-enabled --quiet certbot.timer" in verifier
    assert "systemctl is-active --quiet certbot.timer" in verifier
    assert "certbot renew --dry-run" in verifier
    assert "chmod " not in verifier
    assert "chown " not in verifier
    assert "cat \"${key_path}\"" not in verifier

    expected_key_paths = {
        "/etc/letsencrypt/live/sitbank.duckdns.org/privkey.pem",
        "/etc/letsencrypt/live/admin-sitbank.duckdns.org/privkey.pem",
        "/etc/letsencrypt/live/staging-sitbank.duckdns.org/privkey.pem",
    }
    configured_key_paths = set(
        re.findall(
            r"^\s*ssl_certificate_key\s+([^;]+);$",
            "\n".join([production_nginx, staging_nginx]),
            flags=re.MULTILINE,
        )
    )
    assert configured_key_paths == expected_key_paths
    assert all(path.startswith("/etc/letsencrypt/live/") for path in configured_key_paths)
    assert all("/opt/sitbank" not in path for path in configured_key_paths)

    assert '"${repo_root}/ops/deploy/verify-certbot-host-state"' in bootstrap
    assert "/usr/local/sbin/verify-certbot-host-state" in bootstrap
    assert "/usr/local/sbin/verify-certbot-host-state production" in bootstrap
    assert "/usr/local/sbin/verify-certbot-host-state staging" in bootstrap
    assert "Missing required production TLS file" in bootstrap
    assert "Missing required staging TLS file" in bootstrap


def test_repository_keeps_acme_state_and_tls_private_keys_out_of_git():
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    tracked_paths = [
        Path(item.decode("utf-8")) for item in result.stdout.split(b"\0") if item
    ]
    forbidden_directories = (
        Path(".well-known") / "acme-challenge",
        Path("letsencrypt") / "accounts",
        Path("letsencrypt") / "archive",
        Path("letsencrypt") / "live",
    )
    private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"

    assert all(path.name != "privkey.pem" for path in tracked_paths)
    for directory in forbidden_directories:
        assert not any(path.is_relative_to(directory) for path in tracked_paths)
    for path in tracked_paths:
        if not path.is_file():
            continue
        try:
            contents = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        assert private_key_marker not in contents, path


def test_security_alert_scheduler_units_are_committed_and_safe():
    service_path = Path("ops/systemd/sitbank-security-alerts.service")
    timer_path = Path("ops/systemd/sitbank-security-alerts.timer")
    service = service_path.read_text(encoding="utf-8")
    timer = timer_path.read_text(encoding="utf-8")
    runtime = Path("ops/deploy/sitbank-container-runtime").read_text(encoding="utf-8")
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(encoding="utf-8")
    docs = _project_docs_text()
    exec_start = next(
        line for line in service.splitlines() if line.startswith("ExecStart=")
    )

    assert "Description=SITBank security alert check" in service
    assert "ConditionPathExists=/var/lib/sitbank-container/current" in service
    assert "ExecStart=/usr/local/sbin/sitbank-container-runtime check-security-alerts" in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    assert "ReadWritePaths=/run/docker.sock" in service
    assert "OnActiveSec=5min" in timer
    assert "OnUnitActiveSec=5min" in timer
    assert "Unit=sitbank-security-alerts.service" in timer
    for forbidden in (
        "webhook",
        "password",
        "token",
        "api_key",
        "apikey",
        "secret",
        "https://",
    ):
        assert forbidden not in exec_start.casefold()

    assert "check-security-alerts)" in runtime
    assert "exec -T app python -m flask --app wsgi:app check-security-alerts" in runtime
    assert "ops/systemd/${alert_systemd_service}" in bootstrap
    assert "ops/systemd/${alert_systemd_timer}" in bootstrap
    assert "systemctl enable --now \"${alert_systemd_timer}\"" in bootstrap
    for required in (
        "sudo systemctl daemon-reload",
        "sudo systemctl enable --now sitbank-security-alerts.timer",
        "sudo systemctl status sitbank-security-alerts.timer",
        "journalctl -u sitbank-security-alerts.service",
        "every 5 minutes",
        "production bootstrap",
    ):
        assert required in docs


def test_nginx_default_server_is_shared_for_same_host_production_and_staging():
    default_nginx = Path("ops/nginx/sitbank-default.conf").read_text(encoding="utf-8")
    production_nginx = Path("ops/nginx/sitbank-production.conf").read_text(encoding="utf-8")
    staging_nginx = Path("ops/nginx/sitbank-staging.conf").read_text(encoding="utf-8")
    combined = "\n".join([default_nginx, production_nginx, staging_nginx])

    assert combined.count("listen 80 default_server;") == 1
    assert combined.count("listen [::]:80 default_server;") == 1
    assert combined.count("listen 443 ssl http2 default_server;") == 1
    assert combined.count("listen [::]:443 ssl http2 default_server;") == 1
    assert "listen 80 default_server;" not in production_nginx
    assert "listen 80 default_server;" not in staging_nginx
    assert "server_name sitbank.duckdns.org;" in combined
    assert "server_name admin-sitbank.duckdns.org;" in combined
    assert "server_name staging-sitbank.duckdns.org;" in combined


def test_nginx_tls_policy_pins_strong_suites_curves_and_session_hardening():
    tls_policy_path = Path("ops/nginx/sitbank-tls-policy.conf")
    tls_policy = tls_policy_path.read_text(encoding="utf-8")
    production_nginx = Path("ops/nginx/sitbank-production.conf").read_text(
        encoding="utf-8"
    )
    staging_nginx = Path("ops/nginx/sitbank-staging.conf").read_text(encoding="utf-8")
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(encoding="utf-8")

    assert tls_policy_path.exists()
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in tls_policy
    assert "ssl_ecdh_curve X25519:prime256v1:secp384r1;" in tls_policy
    assert "ssl_prefer_server_ciphers off;" in tls_policy
    assert "ssl_session_tickets off;" in tls_policy

    tls12_match = re.search(r"ssl_ciphers '([^']+)';", tls_policy)
    assert tls12_match
    assert tls12_match.group(1).split(":") == [
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ]
    for weak_cipher_family in (
        "RC4",
        "3DES",
        "DES",
        "CBC",
        "MD5",
        "aNULL",
        "eNULL",
        "EXPORT",
        "TLS_RSA_",
    ):
        assert weak_cipher_family not in tls12_match.group(1)
    assert not re.search(r"(?:^|:)DHE-", tls12_match.group(1))

    tls13_match = re.search(r"ssl_conf_command Ciphersuites ([^;]+);", tls_policy)
    assert tls13_match
    assert tls13_match.group(1).split(":") == [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ]

    policy_include = "include /etc/nginx/snippets/sitbank-tls-policy.conf;"
    for nginx, server_name, session_cache in (
        (production_nginx, "sitbank.duckdns.org", "shared:sitbank_prod_ssl:10m"),
        (
            production_nginx,
            "admin-sitbank.duckdns.org",
            "shared:sitbank_prod_admin_ssl:10m",
        ),
        (staging_nginx, "staging-sitbank.duckdns.org", "shared:sitbank_staging_ssl:10m"),
    ):
        https_server = _nginx_https_server_prelocation(nginx, server_name=server_name)
        assert policy_include in https_server
        assert session_cache in https_server
        assert "ssl_session_timeout 1d;" in https_server

    assert 'TLS_POLICY_FILE="/etc/nginx/snippets/sitbank-tls-policy.conf"' in bootstrap
    assert '"${repo_root}/ops/nginx/sitbank-tls-policy.conf"' in bootstrap
    assert '"${TLS_POLICY_FILE}"' in bootstrap
    assert '"shared Nginx TLS policy"' in bootstrap
    assert '"nginx-sitbank-tls-policy"' in bootstrap
    assert bootstrap.count("    install_tls_policy\n") == 2
    tls_policy_install = bootstrap.index("install_tls_policy", bootstrap.index("if [[ \"${target}\" == \"production\" ]]"))
    assert tls_policy_install < bootstrap.index("nginx -t", tls_policy_install)


def test_staging_nginx_enforces_https_auth_health_and_rate_limits():
    default_nginx = Path("ops/nginx/sitbank-default.conf").read_text(encoding="utf-8")
    nginx = Path("ops/nginx/sitbank-staging.conf").read_text(encoding="utf-8")
    rate_limits = Path("ops/nginx/sitbank-staging-rate-limits.conf").read_text(
        encoding="utf-8"
    )
    staging_compose = yaml.safe_load(Path("compose.staging.yml").read_text(encoding="utf-8"))
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(
        encoding="utf-8"
    )
    staging_http_nginx = _nginx_http_server_block(
        nginx,
        "staging-sitbank.duckdns.org",
    )

    assert Path("ops/nginx/sitbank-default.conf").exists()
    assert Path("ops/nginx/sitbank-staging-rate-limits.conf").exists()
    assert "listen 80 default_server;" in default_nginx
    assert "listen [::]:80 default_server;" in default_nginx
    assert "listen 443 ssl http2 default_server;" in default_nginx
    assert "listen [::]:443 ssl http2 default_server;" in default_nginx
    assert "server_name _;" in default_nginx
    assert "ssl_reject_handshake on;" in default_nginx
    assert "return 444;" in default_nginx
    assert "listen 80;" in nginx
    assert "listen 80 default_server;" not in nginx
    assert "listen 443 ssl http2 default_server;" not in nginx
    assert "server_name _;" not in nginx
    assert "listen 443 ssl http2;" in nginx
    assert "server_name staging-sitbank.duckdns.org;" in nginx
    assert "ssl_certificate /etc/letsencrypt/live/staging-sitbank.duckdns.org/fullchain.pem;" in nginx
    assert "ssl_certificate_key /etc/letsencrypt/live/staging-sitbank.duckdns.org/privkey.pem;" in nginx
    assert "ssl_client_certificate /etc/nginx/cloudflare-authenticated-origin-pull-ca.pem;" in nginx
    assert "ssl_verify_client optional;" in nginx
    _assert_nginx_owns_duplicate_edge_security_headers(
        nginx,
        hsts_add_header='add_header Strict-Transport-Security "max-age=300" always;',
    )
    assert "preload" not in nginx
    assert 'auth_basic "SITBank staging";' in nginx
    assert "auth_basic_user_file /etc/nginx/.htpasswd-sitbank-staging;" in nginx
    staging_https_prelocation = _nginx_https_server_prelocation(
        nginx,
        server_name="staging-sitbank.duckdns.org",
    )
    assert 'auth_basic "SITBank staging";' not in staging_https_prelocation
    assert "auth_basic_user_file /etc/nginx/.htpasswd-sitbank-staging;" not in staging_https_prelocation
    assert not Path("ops/nginx/.htpasswd-sitbank-staging").exists()
    assert not re.search(
        r"^\S+:\$(?:apr1|2[aby]|5|6)\$",
        nginx,
        flags=re.MULTILINE,
    )

    acme_bodies = _nginx_location_bodies(nginx, "^~ /.well-known/acme-challenge/")
    assert len(acme_bodies) == 2
    for acme_body in acme_bodies:
        assert "auth_basic off;" in acme_body
        assert "root /var/www/certbot;" in acme_body
        assert "limit_req" not in acme_body

    staging_http_root_bodies = _nginx_location_bodies(staging_http_nginx, "/")
    assert len(staging_http_root_bodies) == 1
    assert "return 403;" in staging_http_root_bodies[0]
    assert "return 301" not in staging_http_root_bodies[0]

    health_bodies = _nginx_location_bodies(nginx, "= /health/ready")
    assert len(health_bodies) == 1
    health_body = health_bodies[0]
    assert "auth_basic off;" in health_body
    assert "allow 127.0.0.1;" in health_body
    assert "allow ::1;" in health_body
    assert "deny all;" in health_body
    assert "proxy_pass http://127.0.0.1:5001;" in health_body
    assert "limit_req" not in health_body

    health_live_bodies = _nginx_location_bodies(nginx, "= /health/live")
    assert len(health_live_bodies) == 1
    assert "$ssl_client_verify != SUCCESS" in health_live_bodies[0]
    assert "return 403;" in health_live_bodies[0]
    assert 'auth_basic "SITBank staging";' in health_live_bodies[0]
    assert "auth_basic_user_file /etc/nginx/.htpasswd-sitbank-staging;" in health_live_bodies[0]
    assert health_live_bodies[0].index("$ssl_client_verify != SUCCESS") < health_live_bodies[0].index(
        'auth_basic "SITBank staging";'
    )
    assert "limit_req zone=sitbank_staging_app" in health_live_bodies[0]
    assert "proxy_pass http://127.0.0.1:5001;" in health_live_bodies[0]

    proxy_targets = set(re.findall(r"proxy_pass\s+([^;]+);", nginx))
    assert proxy_targets == {"http://127.0.0.1:5001"}
    assert "127.0.0.1:5000" not in nginx
    assert "server_name sitbank.duckdns.org;" not in nginx
    assert staging_compose["services"]["app"]["ports"] == ["127.0.0.1:5001:5000"]
    assert staging_compose["services"]["admin"]["ports"] == ["127.0.0.1:5003:5000"]
    assert "127.0.0.1:5002:5000" not in staging_compose["services"]["admin"]["ports"]
    assert "ports" not in staging_compose["services"]["postgres"]
    assert "redis" not in staging_compose["services"]

    assert "limit_req_zone $binary_remote_addr zone=sitbank_staging_login:10m rate=5r/m;" in rate_limits
    assert "limit_req_zone $binary_remote_addr zone=sitbank_staging_app:10m rate=10r/s;" in rate_limits
    assert "limit_req_status 429;" in nginx
    assert "limit_req_log_level warn;" in nginx
    assert "limit_req_status" not in rate_limits
    assert "limit_req_log_level" not in rate_limits
    for selector in ("= /login", "= /register", "= /mfa/verify", "^~ /auth/"):
        bodies = _nginx_location_bodies(nginx, selector)
        assert len(bodies) == 1
        assert "$ssl_client_verify != SUCCESS" in bodies[0]
        assert "return 403;" in bodies[0]
        assert 'auth_basic "SITBank staging";' in bodies[0]
        assert "auth_basic_user_file /etc/nginx/.htpasswd-sitbank-staging;" in bodies[0]
        assert bodies[0].index("$ssl_client_verify != SUCCESS") < bodies[0].index(
            'auth_basic "SITBank staging";'
        )
        assert "limit_req zone=sitbank_staging_login" in bodies[0]
    assert any(
        "$ssl_client_verify != SUCCESS" in body
        and "return 403;" in body
        and 'auth_basic "SITBank staging";' in body
        and body.index("$ssl_client_verify != SUCCESS") < body.index(
            'auth_basic "SITBank staging";'
        )
        and "limit_req zone=sitbank_staging_app" in body
        for body in _nginx_location_bodies(nginx, "/")
    )

    assert "Conflicting Nginx staging site is already enabled" in bootstrap
    assert "Disable the duplicate staging server block" in bootstrap
    assert 'public_host_regex="${public_host//./\\\\.}"' in bootstrap
    assert "grep -RlE \\" in bootstrap
    assert (
        '"^[[:space:]]*server_name[[:space:]].*(^|[[:space:]])'
        '${public_host_regex}([[:space:];]|$)" \\'
    ) in bootstrap
    assert "Missing required staging Basic Auth file" in bootstrap
    assert "STAGING_CLOUDFLARE_ORIGIN_PULL_CA_FILE=\"/etc/nginx/cloudflare-authenticated-origin-pull-ca.pem\"" in bootstrap
    assert "Missing required Cloudflare Authenticated Origin Pull CA file" in bootstrap
    assert "Install the Cloudflare origin-pull CA certificate before rerunning staging bootstrap." in bootstrap
    assert "Missing required staging TLS file" in bootstrap
    assert "apache2-utils" in bootstrap
    assert "certbot" in bootstrap
    assert "STAGING_RATE_LIMITS_FILE=\"/etc/nginx/conf.d/sitbank-staging-rate-limits.conf\"" in bootstrap
    assert "EDGE_DEFAULTS_FILE=\"/etc/nginx/conf.d/sitbank-default.conf\"" in bootstrap
    assert "ops/nginx/sitbank-default.conf" in bootstrap
    assert "ops/nginx/sitbank-staging-rate-limits.conf" in bootstrap
    assert "sitbank-staging-rate-limits.$(date -u +%Y%m%dT%H%M%SZ).conf" in bootstrap
    assert '"nginx-sitbank-default"' in bootstrap
    assert '${backup_prefix}.$(date -u +%Y%m%dT%H%M%SZ).conf' in bootstrap
    assert "nginx-sitbank-staging.$(date -u +%Y%m%dT%H%M%SZ).conf" in bootstrap
    assert "&& ! cmp -s \\" in bootstrap
    assert '"${repo_root}/ops/nginx/sitbank-staging.conf" \\' in bootstrap
    assert "refresh_enabled_sibling_site" in bootstrap
    assert "&& -e /etc/nginx/sites-enabled/sitbank" in bootstrap
    assert '"${staging_site}"; then' in bootstrap
    assert "if [[ ! -e /etc/nginx/sites-available/sitbank-staging" not in bootstrap
    staging_site_install = bootstrap.index('"${repo_root}/ops/nginx/sitbank-staging.conf"')
    assert staging_site_install < bootstrap.index("nginx -t", staging_site_install)
    assert bootstrap.index("nginx -t", staging_site_install) < bootstrap.index(
        "systemctl reload nginx",
        staging_site_install,
    )
    assert "docker compose up" not in bootstrap
    assert "docker pull" not in bootstrap
    assert "SITBANK_IMAGE" not in bootstrap


def test_production_nginx_edge_config_enforces_network_boundary_and_limits():
    default_nginx = Path("ops/nginx/sitbank-default.conf").read_text(encoding="utf-8")
    nginx = Path("ops/nginx/sitbank-production.conf").read_text(encoding="utf-8")
    rate_limits = Path("ops/nginx/sitbank-production-rate-limits.conf").read_text(
        encoding="utf-8"
    )
    proxy_headers = Path("ops/nginx-proxy-headers.conf").read_text(encoding="utf-8")
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(
        encoding="utf-8"
    )
    deploy_script = Path("ops/deploy/sitbank-container-deploy").read_text(encoding="utf-8")
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    production_compose = yaml.safe_load(Path("compose.prod.yml").read_text(encoding="utf-8"))
    app = production_compose["services"]["app"]
    admin = production_compose["services"]["admin"]
    customer_nginx = _nginx_server_block(nginx, "sitbank.duckdns.org")
    admin_nginx = _nginx_server_block(nginx, "admin-sitbank.duckdns.org")
    admin_http_nginx = _nginx_http_server_block(nginx, "admin-sitbank.duckdns.org")

    assert Path("ops/nginx/sitbank-default.conf").exists()
    assert Path("ops/nginx/sitbank-production.conf").exists()
    assert not Path("ops/nginx/admin-verification.html").exists()
    assert Path("ops/nginx/sitbank-production-rate-limits.conf").exists()
    assert "listen 80 default_server;" in default_nginx
    assert "listen [::]:80 default_server;" in default_nginx
    assert "listen 443 ssl http2 default_server;" in default_nginx
    assert "listen [::]:443 ssl http2 default_server;" in default_nginx
    assert "server_name _;" in default_nginx
    assert "ssl_reject_handshake on;" in default_nginx
    assert "return 444;" in default_nginx
    assert "listen 80;" in nginx
    assert "return 301 https://sitbank.duckdns.org$request_uri;" in nginx
    assert "return 301 https://admin-sitbank.duckdns.org$request_uri;" not in nginx
    assert "listen 80 default_server;" not in nginx
    assert "listen 443 ssl http2 default_server;" not in nginx
    assert "server_name _;" not in nginx
    assert "listen 443 ssl http2;" in nginx
    assert "server_name sitbank.duckdns.org;" in nginx
    assert "server_name admin-sitbank.duckdns.org;" in nginx
    assert "ssl_certificate /etc/letsencrypt/live/sitbank.duckdns.org/fullchain.pem;" in nginx
    assert "ssl_certificate_key /etc/letsencrypt/live/sitbank.duckdns.org/privkey.pem;" in nginx
    assert "ssl_certificate /etc/letsencrypt/live/admin-sitbank.duckdns.org/fullchain.pem;" in nginx
    assert "ssl_certificate_key /etc/letsencrypt/live/admin-sitbank.duckdns.org/privkey.pem;" in nginx
    _assert_nginx_owns_duplicate_edge_security_headers(
        nginx,
        hsts_add_header=(
            'add_header Strict-Transport-Security "max-age=31536000; '
            'includeSubDomains" always;'
        ),
        server_name="sitbank.duckdns.org",
    )
    assert "client_max_body_size 4m;" in nginx
    for timeout in (
        "client_body_timeout 15s;",
        "client_header_timeout 15s;",
        "keepalive_timeout 30s;",
        "send_timeout 30s;",
        "proxy_connect_timeout 5s;",
        "proxy_send_timeout 30s;",
        "proxy_read_timeout 30s;",
    ):
        assert timeout in nginx
    assert "if ($request_method = TRACE)" in nginx
    assert "return 405;" in nginx

    health_ready_bodies = _nginx_location_bodies(customer_nginx, "= /health/ready")
    assert len(health_ready_bodies) == 1
    health_ready = health_ready_bodies[0]
    assert "allow 127.0.0.1;" in health_ready
    assert "allow ::1;" in health_ready
    assert "deny all;" in health_ready
    assert "proxy_pass http://127.0.0.1:5000;" in health_ready
    assert "limit_req" not in health_ready

    health_live_bodies = _nginx_location_bodies(customer_nginx, "= /health/live")
    assert len(health_live_bodies) == 1
    assert "limit_req zone=sitbank_prod_app" in health_live_bodies[0]
    assert "proxy_pass http://127.0.0.1:5000;" in health_live_bodies[0]

    customer_admin_bodies = _nginx_location_bodies(customer_nginx, "^~ /admin")
    assert len(customer_admin_bodies) == 1
    assert "return 404;" in customer_admin_bodies[0]

    admin_http_root_bodies = _nginx_location_bodies(admin_http_nginx, "/")
    assert len(admin_http_root_bodies) == 1
    assert "return 403;" in admin_http_root_bodies[0]
    assert "return 301" not in admin_http_root_bodies[0]

    admin_http_acme_bodies = _nginx_location_bodies(
        admin_http_nginx,
        "^~ /.well-known/acme-challenge/",
    )
    assert len(admin_http_acme_bodies) == 1
    assert "root /var/www/certbot;" in admin_http_acme_bodies[0]
    assert "try_files $uri =404;" in admin_http_acme_bodies[0]

    admin_health_ready_bodies = _nginx_location_bodies(admin_nginx, "= /health/ready")
    assert len(admin_health_ready_bodies) == 1
    assert "deny all;" in admin_health_ready_bodies[0]
    assert "return 403;" in admin_health_ready_bodies[0]
    assert "proxy_pass" not in admin_health_ready_bodies[0]

    admin_health_live_bodies = _nginx_location_bodies(admin_nginx, "= /health/live")
    assert len(admin_health_live_bodies) == 1
    assert "allow 127.0.0.1;" in admin_health_live_bodies[0]
    assert "allow ::1;" in admin_health_live_bodies[0]
    assert "deny all;" in admin_health_live_bodies[0]
    assert "proxy_pass http://127.0.0.1:5002;" in admin_health_live_bodies[0]

    admin_login_bodies = _nginx_location_bodies(admin_nginx, "= /login")
    assert len(admin_login_bodies) == 1
    assert "deny all;" in admin_login_bodies[0]
    assert "limit_req zone=sitbank_prod_admin_auth" in admin_login_bodies[0]
    assert "proxy_pass http://127.0.0.1:5002;" in admin_login_bodies[0]

    admin_exact_root_bodies = _nginx_location_bodies(admin_nginx, "= /")
    assert len(admin_exact_root_bodies) == 1
    admin_exact_root = admin_exact_root_bodies[0]
    assert "return 403;" in admin_exact_root
    assert "root /var/www/sitbank-admin-verification;" not in admin_exact_root
    assert "try_files /index.html =404;" not in admin_exact_root
    assert "default_type text/html;" not in admin_exact_root
    assert "limit_req zone=sitbank_prod_admin" not in admin_exact_root
    assert "proxy_pass" not in admin_exact_root

    admin_root_bodies = _nginx_location_bodies(admin_nginx, "/")
    assert any("deny all;" in body and "limit_req zone=sitbank_prod_admin" in body for body in admin_root_bodies)

    customer_proxy_targets = set(re.findall(r"proxy_pass\s+([^;]+);", customer_nginx))
    admin_proxy_targets = set(re.findall(r"proxy_pass\s+([^;]+);", admin_nginx))
    assert customer_proxy_targets == {"http://127.0.0.1:5000"}
    assert admin_proxy_targets == {"http://127.0.0.1:5002"}
    assert "0.0.0.0:5000" not in nginx
    assert "0.0.0.0:5002" not in nginx
    assert "--bind\", \"127.0.0.1:5000" in dockerfile
    assert app["network_mode"] == "host"
    assert "ports" not in app
    assert admin["network_mode"] == "host"
    assert "ports" not in admin
    assert admin["command"][admin["command"].index("--bind") + 1] == "127.0.0.1:5002"
    assert admin["command"][-1] == "admin_wsgi:app"

    for zone in (
        "limit_req_zone $binary_remote_addr zone=sitbank_prod_app:10m rate=20r/s;",
        "limit_req_zone $binary_remote_addr zone=sitbank_prod_auth:10m rate=5r/m;",
        "limit_req_zone $binary_remote_addr zone=sitbank_prod_register:10m rate=2r/m;",
        "limit_req_zone $binary_remote_addr zone=sitbank_prod_challenge:10m rate=3r/m;",
        "limit_req_zone $binary_remote_addr zone=sitbank_prod_security:10m rate=10r/m;",
        "limit_req_zone $binary_remote_addr zone=sitbank_prod_admin:10m rate=2r/s;",
        "limit_req_zone $binary_remote_addr zone=sitbank_prod_admin_auth:10m rate=3r/m;",
    ):
        assert zone in rate_limits
    assert "limit_req_status 429;" in nginx
    assert "limit_req_log_level warn;" in nginx
    assert "limit_req_status" not in rate_limits
    assert "limit_req_log_level" not in rate_limits

    expected_location_limits = {
        "= /login": "sitbank_prod_auth",
        "= /auth/login": "sitbank_prod_auth",
        "= /mfa/verify": "sitbank_prod_auth",
        "= /auth/mfa/verify": "sitbank_prod_auth",
        "= /register": "sitbank_prod_register",
        "= /auth/register": "sitbank_prod_register",
        "~ ^/auth/webauthn/(?:register|authenticate|step-up)/(?:options|verify)$": "sitbank_prod_challenge",
        "~ ^/(?:account|password|profile|security-keys|sessions)(?:/|$)": "sitbank_prod_security",
        "~ ^/auth/(?:account|mfa|password|sessions|webauthn/credentials)(?:/|$)": "sitbank_prod_security",
        "/auth/": "sitbank_prod_auth",
    }
    for selector, zone in expected_location_limits.items():
        bodies = _nginx_location_bodies(customer_nginx, selector)
        assert len(bodies) == 1
        assert f"limit_req zone={zone}" in bodies[0]
        assert "include /etc/nginx/snippets/sitbank-proxy-headers.conf;" in bodies[0]
    assert any(
        "limit_req zone=sitbank_prod_app" in body
        for body in _nginx_location_bodies(customer_nginx, "/")
    )

    assert "proxy_set_header X-Forwarded-For $remote_addr;" in proxy_headers
    assert "$proxy_add_x_forwarded_for" not in proxy_headers

    assert 'PRODUCTION_PUBLIC_HOST="sitbank.duckdns.org"' in bootstrap
    assert 'PRODUCTION_ADMIN_PUBLIC_HOST="admin-sitbank.duckdns.org"' in bootstrap
    assert "Production PUBLIC_HOST must be ${PRODUCTION_PUBLIC_HOST}" in bootstrap
    assert "Missing required production TLS file" in bootstrap
    assert "/etc/letsencrypt/live/${PRODUCTION_ADMIN_PUBLIC_HOST}" in bootstrap
    assert "Issue the production Certbot certificate before rerunning bootstrap." in bootstrap
    assert "PRODUCTION_RATE_LIMITS_FILE=\"/etc/nginx/conf.d/sitbank-production-rate-limits.conf\"" in bootstrap
    assert "EDGE_DEFAULTS_FILE=\"/etc/nginx/conf.d/sitbank-default.conf\"" in bootstrap
    assert "ops/nginx/sitbank-default.conf" in bootstrap
    assert "ops/nginx/sitbank-production-rate-limits.conf" in bootstrap
    assert "ops/nginx/sitbank-production.conf" in bootstrap
    assert "ops/nginx/admin-verification.html" not in bootstrap
    assert "/var/www/sitbank-admin-verification/index.html" not in bootstrap
    assert "install -d -o \"${CONTAINER_ACCOUNT}\" -g \"${CONTAINER_GID}\" -m 0750" in bootstrap
    assert "/var/lib/sitbank" in bootstrap
    assert "install -d -o sitbank-container -g 10001 -m 0750 /var/lib/sitbank" in deploy_script
    assert "Refusing to replace unsafe production Nginx rate-limit file" in bootstrap
    assert "Refusing to replace unsafe production Nginx config" in bootstrap
    assert "Conflicting Nginx production site is already enabled" in bootstrap
    assert "Disable the duplicate production server block" in bootstrap
    assert "nginx-sitbank-production-rate-limits.$(date -u +%Y%m%dT%H%M%SZ).conf" in bootstrap
    assert '"nginx-sitbank-default"' in bootstrap
    assert '${backup_prefix}.$(date -u +%Y%m%dT%H%M%SZ).conf' in bootstrap
    assert "nginx-sitbank-production.$(date -u +%Y%m%dT%H%M%SZ).conf" in bootstrap
    assert "/etc/nginx/sites-enabled/sitbank" in bootstrap
    assert "&& -e /etc/nginx/sites-enabled/sitbank-staging" in bootstrap

    production_rate_install = bootstrap.index(
        '"${repo_root}/ops/nginx/sitbank-production-rate-limits.conf"'
    )
    production_site_install = bootstrap.index(
        '"${repo_root}/ops/nginx/sitbank-production.conf"'
    )
    production_nginx_test = bootstrap.index("nginx -t", production_site_install)
    production_reload = bootstrap.index("systemctl reload nginx", production_nginx_test)
    assert production_rate_install < production_nginx_test
    assert production_site_install < production_nginx_test < production_reload


def test_production_edge_runbook_documents_network_waf_and_verification_steps():
    docs = _project_docs_text()
    security = Path("SECURITY.md").read_text(encoding="utf-8")

    for required in (
        "Production Edge and Network Hardening",
        "ops/nginx/sitbank-production.conf",
        "ops/nginx/sitbank-production-rate-limits.conf",
        "Public ingress is TCP `80` and `443` only.",
        "SSH is restricted to an administrator IP allowlist",
        "Nginx terminates TLS, redirects production customer HTTP to HTTPS",
        "Gunicorn binds only to `127.0.0.1:5000`",
        "Admin Gunicorn binds only to `127.0.0.1:5002`",
        "Flask admin auth is implemented only for root-admin-controlled invite",
        "compose.prod.yml` publishes no",
        "`/health/ready` is for local deployment and load-balancer checks",
        "Cloudflare or AWS WAF should sit in front of Nginx",
        "The reviewed production bootstrap installs and enables the production edge",
        "requires a production bootstrap after merge",
        "sudo test -r /etc/letsencrypt/live/sitbank.duckdns.org/fullchain.pem",
        "Cloudflare or AWS WAF rules and security-group allowlists are still",
        "sudo nginx -t",
        "sudo ss -ltnp | grep -E ':(80|443|5000|5002)([[:space:]]|$)'",
        "sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-app",
        "sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-admin",
        "curl --fail https://sitbank.duckdns.org/health/live",
        "curl -I https://sitbank.duckdns.org/health/ready",
        "curl -I https://admin-sitbank.duckdns.org/",
        "curl -I https://admin-sitbank.duckdns.org/login",
        "Admin `/`, `/health/ready`, `/login`, and all other admin routes remain",
        "old public admin verification",
        "external `/health/ready` returns `403`",
        "admin `/` returns `403`",
    ):
        assert required in docs

    for required in (
        "Production Edge and WAF Checklist",
        "Run production bootstrap from reviewed `main`",
        "`nginx -t` succeeds",
        "Issue production Certbot files under",
        "Allow public inbound TCP `80` and `443` only.",
        "never allow TCP `22` from `0.0.0.0/0` or `::/0`",
        "Do not expose Gunicorn or PostgreSQL directly to the internet.",
        "admin Gunicorn bound to",
        "`127.0.0.1:5002`",
        "Restrict `/health/ready` to loopback",
        "Keep public admin `/` and app routes denied by default",
        "Tailscale/private operator access only",
        "Do not enable Tailscale Funnel",
        "Require Cloudflare Access and Cloudflare Authenticated Origin Pulls",
        "Enable WAF managed common, SQL injection, XSS, bot, and protocol anomaly",
        "rules.",
        "Add WAF rate-based rules for `/login`, `/register`, `/mfa/verify`,",
        "Block TRACE at the edge",
        "Host`, `X-Real-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto`",
        "sudo nginx -t",
        "external readiness is denied",
    ):
        assert required in security


def test_staging_edge_runbook_documents_operator_verification_steps():
    docs = _project_docs_text()

    for required in (
        "Staging uses Cloudflare Access as the identity-aware boundary",
        "Cloudflare Authenticated Origin Pulls",
        "The production customer hostname remains public.",
        "sudo htpasswd -c /etc/nginx/.htpasswd-sitbank-staging",
        "sudo chown root:www-data /etc/nginx/.htpasswd-sitbank-staging",
        "sudo chmod 0640 /etc/nginx/.htpasswd-sitbank-staging",
        "Do not store the Basic Auth password or generated htpasswd hash in the repo.",
        "sudo install -o root -g root -m 0644",
        "/etc/nginx/cloudflare-authenticated-origin-pull-ca.pem",
        "Do not store Cloudflare API tokens, tunnel credentials, Access IdP secrets, or",
        "Cloudflare-managed zone/hostname or Cloudflare Tunnel",
        "sudo certbot --nginx -d staging-sitbank.duckdns.org",
        "sudo certbot certonly --webroot",
        "sudo certbot renew --dry-run",
        "ops/deploy/bootstrap-container-ec2",
        "staging-sitbank.duckdns.org",
        "Nginx proxy header snippet",
        "Cloudflare origin-pull CA file",
        "rate-limit include",
        "sudo nginx -t",
        "sudo systemctl reload nginx",
        "curl -I https://staging-sitbank.duckdns.org/",
        'curl -I -u "$STAGING_BASIC_AUTH_USER:$STAGING_BASIC_AUTH_PASSWORD"',
        "curl -I https://staging-sitbank.duckdns.org/health/ready",
        "curl -fsS http://127.0.0.1:5001/health/ready",
        "curl --fail --resolve staging-sitbank.duckdns.org:443:127.0.0.1",
        "curl -I --resolve staging-sitbank.duckdns.org:443:<EC2_PUBLIC_IP>",
        "unauthenticated browser traffic receives the Cloudflare Access",
        "direct EC2-origin access to",
        "returns `403` without Cloudflare's origin-pull client certificate",
        "external `/health/ready` returns `403`",
        "local app readiness",
        "separate from application deployment",
        "docs/security/admin-and-staging-zero-trust-access.md",
    ):
        assert required in docs


def test_dependency_manifests_have_one_hashed_lockfile_source_of_truth():
    assert Path("requirements.in").exists()
    assert Path("requirements-dev.in").exists()
    assert Path("requirements.lock").exists()
    assert Path("requirements-dev.lock").exists()
    assert not Path("requirements.txt").exists()
    assert not Path("requirements-dev.txt").exists()
    assert "-r requirements.in" in Path("requirements-dev.in").read_text(
        encoding="utf-8"
    )

    result = subprocess.run(
        [sys.executable, "ops/security/check_dependency_locks.py"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_removed_legacy_crypto_interfaces_stay_absent():
    runtime_files = [
        Path(".github/workflows/ci-deploy.yml"),
        Path("app/auth/services.py"),
        Path("app/ops/commands.py"),
        Path("app/security/crypto.py"),
        Path("compose.prod.yml"),
        Path("compose.staging.yml"),
        Path("config.py"),
        Path("ops/container/dast-smoke.sh"),
        Path("ops/container/smoke-test.sh"),
        Path("ops/deploy/render_container_bundle.py"),
        Path("ops/deploy/sitbank-container-deploy"),
        Path("ops/production-env.required"),
        Path("ops/runtime_contract.py"),
        Path("requirements.in"),
        Path("requirements.lock"),
        Path("requirements-dev.lock"),
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in runtime_files)

    assert "MFA_AES256_GCM_KEY_B64" not in combined
    assert "mfa_aes256_gcm_key_b64" not in combined
    assert "rotate-mfa-encryption" not in combined
    assert "bcrypt==" not in combined


def test_tracked_files_do_not_contain_the_retired_project_name():
    forbidden = ("scam" + "centre").casefold()
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    paths = [
        Path(item.decode("utf-8"))
        for item in result.stdout.split(b"\0")
        if item
    ]

    for path in paths:
        if not path.is_file():
            continue
        assert forbidden not in path.as_posix().casefold()
        try:
            contents = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        assert forbidden not in contents.casefold(), path


def test_migration_baseline_and_existing_database_runbook_are_present():
    migration = Path(
        "migrations/versions/20260610_0001_baseline.py"
    ).read_text(encoding="utf-8")
    audit_hash_migration = Path(
        "migrations/versions/20260618_0002_audit_hash_chain.py"
    ).read_text(encoding="utf-8")
    audit_append_only_migration = Path(
        "migrations/versions/20260618_0003_audit_append_only_triggers.py"
    ).read_text(encoding="utf-8")
    audit_truncate_migration = Path(
        "migrations/versions/20260618_0004_audit_truncate_trigger.py"
    ).read_text(encoding="utf-8")
    audit_hmac_default_migration = Path(
        "migrations/versions/20260620_0006_audit_hmac_default.py"
    ).read_text(encoding="utf-8")
    docs = _project_docs_text()

    assert 'revision = "20260610_0001"' in migration
    assert '"users"' in migration
    assert '"webauthn_credentials"' in migration
    assert '"security_audit_events"' in migration
    assert 'revision = "20260618_0002"' in audit_hash_migration
    assert 'down_revision = "20260610_0001"' in audit_hash_migration
    assert "previous_event_hash" in audit_hash_migration
    assert "event_hash" in audit_hash_migration
    assert "hash_algorithm" in audit_hash_migration
    assert 'revision = "20260618_0003"' in audit_append_only_migration
    assert 'down_revision = "20260618_0002"' in audit_append_only_migration
    assert "security_audit_events_reject_mutation" in audit_append_only_migration
    assert "BEFORE UPDATE ON security_audit_events" in audit_append_only_migration
    assert "BEFORE DELETE ON security_audit_events" in audit_append_only_migration
    assert "ERRCODE = '42501'" in audit_append_only_migration
    assert 'revision = "20260618_0004"' in audit_truncate_migration
    assert 'down_revision = "20260618_0003"' in audit_truncate_migration
    assert "security_audit_events_reject_mutation" in audit_truncate_migration
    assert "security_audit_events_reject_truncate" in audit_truncate_migration
    assert "BEFORE TRUNCATE ON security_audit_events" in audit_truncate_migration
    assert "FOR EACH STATEMENT" in audit_truncate_migration
    assert 'revision = "20260620_0006"' in audit_hmac_default_migration
    assert 'down_revision = "20260619_0005"' in audit_hmac_default_migration
    assert "hmac-sha256-v1" in audit_hmac_default_migration
    assert "verify-migration-baseline" in docs
    assert "db stamp 20260610_0001" in docs
    assert "Do not run `db.create_all()`" in docs
    assert "hetp88/SITBank" in docs
    assert "ghcr.io/hetp88/sitbank@sha256:<digest>" in docs
    assert "sitbank_db" in docs
    assert "sitbank_owner" in docs
    assert "sitbank_app" in docs
    assert "sitbank-database-cutover prepare" in docs


def test_audit_operations_runbook_and_append_only_privileges_are_present():
    docs = _project_docs_text()
    commands = Path("app/ops/commands.py").read_text(encoding="utf-8")
    production_guard = Path("app/security/production_guard.py").read_text(encoding="utf-8")
    audit_source = Path("app/security/audit.py").read_text(encoding="utf-8")
    privileges = Path("app/ops/db_privileges.py").read_text(encoding="utf-8")
    append_only_migration = Path(
        "migrations/versions/20260618_0003_audit_append_only_triggers.py"
    ).read_text(encoding="utf-8")
    truncate_migration = Path(
        "migrations/versions/20260618_0004_audit_truncate_trigger.py"
    ).read_text(encoding="utf-8")
    deploy_script = Path("ops/deploy/sitbank-container-deploy").read_text(encoding="utf-8")
    smoke_test = Path("ops/container/smoke-test.sh").read_text(encoding="utf-8")
    staging_compose = Path("compose.staging.yml").read_text(encoding="utf-8")
    prod_compose = Path("compose.prod.yml").read_text(encoding="utf-8")

    for required in (
        "Retain security audit records for 7 years",
        "Do not silently auto-delete audit",
        "apply-runtime-db-privileges",
        "verify-runtime-db-privileges",
        "security_audit_events",
        "cannot update, delete, or truncate",
        "security_audit_write_failed",
        "hash chain",
        "verify-audit-log-chain",
        "export-audit-log-anchor",
        "check-security-alerts",
        "verify-audit-log-chain --anchor",
        "SECURITY_ALERT_WEBHOOK_URL_FILE",
        "SECURITY_ALERT_DEDUPE_TTL_SECONDS",
        "SECURITY_ALERT_STATE_PATH",
        "SECURITY_AUDIT_ANCHOR_PATH",
        "`SECURITY_AUDIT_HMAC_KEY` is mandatory",
        "`SECURITY_AUDIT_HMAC_KEY` and `SECURITY_AUDIT_ANCHOR_PATH` are mandatory",
        "/var/lib/sitbank/security-audit.anchor",
        "outside the application and",
        "systemd timer",
        "database table regression",
        "immutable storage",
        "10 or more `login` failures",
        "`auth_backoff`",
        "3 or more transaction failures",
        "There is no final ledger",
        "Docker `local` log rotation",
    ):
        assert required in docs

    assert "apply-runtime-db-privileges" in commands
    assert "apply_runtime_audit_table_privileges" in commands
    assert "verify-audit-log-chain" in commands
    assert "--anchor" in commands
    assert "--alert-on-failure" in commands
    assert "export-audit-log-anchor" in commands
    assert "check-security-alerts" in commands
    assert "build_security_alert_report" in commands
    assert "validate_security_alert_config" in production_guard
    assert "pg_advisory_xact_lock" in audit_source
    assert "AUDIT_CHAIN_ADVISORY_LOCK_ID" in audit_source
    assert ".with_for_update(" not in audit_source
    assert "security_audit_events_reject_mutation" in append_only_migration
    assert "security_audit_events_reject_update" in append_only_migration
    assert "security_audit_events_reject_delete" in append_only_migration
    assert "security_audit_events_reject_truncate" in truncate_migration
    assert "BEFORE TRUNCATE ON security_audit_events" in truncate_migration
    assert "REVOKE UPDATE, DELETE, TRUNCATE ON TABLE" in privileges
    assert "TRUNCATE security_audit_events" in privileges
    assert "GRANT SELECT, INSERT ON TABLE" in privileges
    assert "_assert_audit_append_only_triggers_installed" in privileges
    assert "pg_advisory_xact_lock" in privileges
    assert "previous_event_hash" in privileges
    assert "event_hash" in privileges
    assert "hash_algorithm" in privileges
    assert "audit_update_delete_truncate=revoked" in commands
    assert deploy_script.index("db upgrade") < deploy_script.index("apply-runtime-db-privileges")
    assert deploy_script.index("apply-runtime-db-privileges") < deploy_script.index("verify-runtime-db-privileges")
    assert smoke_test.index("db upgrade") < smoke_test.index("apply-runtime-db-privileges")
    assert smoke_test.index("apply-runtime-db-privileges") < smoke_test.index("verify-runtime-db-privileges")
    assert "driver: local" in staging_compose
    assert "driver: local" in prod_compose
    assert "max-size: 10m" in staging_compose
    assert "max-size: 10m" in prod_compose


def test_migration_baseline_renders_offline_sql(app):
    result = app.test_cli_runner().invoke(args=["db", "upgrade", "--sql"])

    assert result.exit_code == 0, result.output
    assert "CREATE TABLE users" in result.output
    assert "CREATE TABLE webauthn_credentials" in result.output
    assert "CREATE TABLE registration_invites" in result.output
    assert "DROP TABLE registration_invites" in result.output
    assert "CREATE TABLE security_audit_events" in result.output
    assert "previous_event_hash" in result.output
    assert "event_hash" in result.output
    assert "hash_algorithm" in result.output


def test_existing_schema_matches_migration_baseline(app):
    result = app.test_cli_runner().invoke(args=["verify-migration-baseline"])

    assert result.exit_code == 0, result.output
    assert "matches migration baseline 20260610_0001" in result.output


def test_proxyfix_trusts_exactly_the_configured_nginx_hop(app):
    from app import create_app

    proxy_config = type(
        "ProxyConfig",
        (),
        {
            **{key: value for key, value in app.config.items() if key.isupper()},
            "TRUSTED_PROXY_COUNT": 1,
        },
    )
    proxy_app = create_app(proxy_config)

    @proxy_app.get("/_proxy-ip-test")
    def proxy_ip_test():
        return {"remote_addr": request.remote_addr}

    response = proxy_app.test_client().get(
        "/_proxy-ip-test",
        headers={"X-Forwarded-For": "203.0.113.25"},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    assert response.get_json() == {"remote_addr": "203.0.113.25"}
