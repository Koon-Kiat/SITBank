from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from flask import request

from ops.deploy.render_runtime_env import render_runtime_environment


RUNTIME_VALUES = {
    "COMMON_PASSWORDS_PATH": "/etc/scamcentre/common-passwords.txt",
    "DATABASE_URL": "postgresql+psycopg2://bank:secret@db.internal/bank",
    "MFA_AES256_GCM_KEY_B64": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
    "MFA_ISSUER_NAME": "O$P$ Bank",
    "PASSWORD_PBKDF2_ITERATIONS": "600000",
    "PASSWORD_PEPPER_B64": "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=",
    "PROD_PUBLIC_HOST": "sitbank.duckdns.org",
    "REDIS_URL": "redis://:secret@redis.internal:6379/0",
    "SECRET_KEY": "secret-key-with-$-and-enough-length-for-production",
    "SESSION_HMAC_ACTIVE_KEY_B64": "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI=",
    "SESSION_HMAC_ACTIVE_KEY_ID": "2026-06",
    "WEBAUTHN_APPROVED_AAGUIDS_PATH": "/etc/scamcentre/fido-approved-aaguids.json",
    "WEBAUTHN_MDS_CACHE_PATH": "/etc/scamcentre/fido-mds-cache.json",
    "WTF_CSRF_SECRET_KEY": "csrf-secret-with-enough-length-for-production",
}


def test_runtime_environment_renderer_is_complete_and_shell_inert(monkeypatch):
    for name, value in RUNTIME_VALUES.items():
        monkeypatch.setenv(name, value)

    rendered = render_runtime_environment()

    assert 'APP_ENV="production"' in rendered
    assert 'WEBAUTHN_RP_ID="sitbank.duckdns.org"' in rendered
    assert 'WEBAUTHN_RP_ORIGIN="https://sitbank.duckdns.org"' in rendered
    assert 'SECRET_KEY="secret-key-with-$-and-enough-length-for-production"' in rendered
    assert 'SESSION_HMAC_KEYS_JSON="{\\"2026-06\\":' in rendered
    assert "PROD_PUBLIC_HOST" not in rendered
    assert "\r" not in rendered


def test_runtime_environment_renderer_rejects_missing_or_multiline_values(monkeypatch):
    for name, value in RUNTIME_VALUES.items():
        monkeypatch.setenv(name, value)

    monkeypatch.delenv("DATABASE_URL")
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        render_runtime_environment()

    monkeypatch.setenv("DATABASE_URL", "postgresql://bank:secret@db/bank")
    monkeypatch.setenv("SECRET_KEY", "line-one\nline-two")
    with pytest.raises(RuntimeError, match="control characters"):
        render_runtime_environment()

    monkeypatch.setenv("SECRET_KEY", RUNTIME_VALUES["SECRET_KEY"])
    monkeypatch.setenv("PROD_PUBLIC_HOST", "sitbank.duckdns.org'; touch /tmp/bad")
    with pytest.raises(RuntimeError, match="bare hostname"):
        render_runtime_environment()


def test_runtime_environment_renderer_builds_two_key_rotation_ring(monkeypatch):
    for name, value in RUNTIME_VALUES.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SESSION_HMAC_PREVIOUS_KEY_ID", "2026-03")
    monkeypatch.setenv(
        "SESSION_HMAC_PREVIOUS_KEY_B64",
        "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=",
    )

    rendered = render_runtime_environment()

    assert '\\"2026-03\\":\\"MzMz' in rendered
    assert '\\"2026-06\\":\\"MjIy' in rendered


def test_runtime_environment_renderer_rejects_partial_rotation_pair(monkeypatch):
    for name, value in RUNTIME_VALUES.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SESSION_HMAC_PREVIOUS_KEY_ID", "2026-03")
    monkeypatch.delenv("SESSION_HMAC_PREVIOUS_KEY_B64", raising=False)

    with pytest.raises(RuntimeError, match="must be configured together"):
        render_runtime_environment()


def test_deployment_workflow_uses_protected_main_release_and_verified_ssh():
    workflow = Path(".github/workflows/ci-deploy.yml").read_text(encoding="utf-8")
    workflow_data = yaml.safe_load(workflow)
    deploy_script = Path("ops/deploy/scamcentre-deploy").read_text(encoding="utf-8")
    bootstrap_script = Path("ops/deploy/bootstrap-ec2").read_text(encoding="utf-8")
    service = Path("ops/systemd/scamcentre.service").read_text(encoding="utf-8")
    check_service = Path(
        "ops/systemd/scamcentre-check@.service"
    ).read_text(encoding="utf-8")

    assert "environment:\n      name: production" in workflow
    assert set(workflow_data["jobs"]) == {"test", "package", "deploy"}
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "vars.PROD_DEPLOY_ENABLED == 'true'" in workflow
    assert "EC2_KNOWN_HOSTS" in workflow
    assert "PROD_SESSION_HMAC_KEYS_JSON" not in workflow
    assert '\"${EC2_DEPLOY_USER}@${EC2_HOST}:incoming/\"' in workflow
    assert "Remove deployment credentials" in workflow
    assert "StrictHostKeyChecking=no" not in workflow
    assert "sha256sum" in workflow
    assert "requirements-dev.lock" in workflow
    assert "/etc/scamcentre/runtime.env" in deploy_script
    assert "scamcentre-migrate@" in deploy_script
    assert "/health/ready" in deploy_script
    assert "flock -n" in deploy_script
    assert "runtime_backup" in deploy_script
    assert 'readonly INCOMING_DIR="/home/${DEPLOY_USER}/incoming"' in deploy_script
    assert 'archive_path="${INCOMING_DIR}/scamcentre-${release_sha}.tar.gz"' in deploy_script
    assert 'stat -c \'%U\'' in deploy_script
    assert 'runuser -u "${SERVICE_USER}" -- python3.12 -m venv "${release_dir}/.venv"' in deploy_script
    assert '"${staging_dir}/.venv"' not in deploy_script
    assert "legacy-${timestamp}" in bootstrap_script
    assert "/home/scamcentre-deploy/incoming" in bootstrap_script
    assert "scamcentre.service.pre-actions-" in bootstrap_script
    assert "EnvironmentFile=/etc/scamcentre/runtime.env" in service
    assert "User=scamcentre" in service
    assert ".venv/bin/python -m gunicorn" in service
    assert ".venv/bin/python -m flask" in check_service


def test_migration_baseline_and_existing_database_runbook_are_present():
    migration = Path(
        "migrations/versions/20260610_0001_baseline.py"
    ).read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")

    assert 'revision = "20260610_0001"' in migration
    assert '"users"' in migration
    assert '"webauthn_credentials"' in migration
    assert '"security_audit_events"' in migration
    assert "db stamp 20260610_0001" in readme
    assert "git archive --format=tar.gz" in readme
    assert "python -m dotenv run -- python -m flask" in readme
    assert "Do not use" in readme and "db.create_all()" in readme


def test_migration_baseline_renders_offline_sql(app):
    result = app.test_cli_runner().invoke(args=["db", "upgrade", "--sql"])

    assert result.exit_code == 0, result.output
    assert "CREATE TABLE users" in result.output
    assert "CREATE TABLE webauthn_credentials" in result.output
    assert "CREATE TABLE security_audit_events" in result.output


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
