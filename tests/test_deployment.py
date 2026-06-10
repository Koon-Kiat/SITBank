from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from flask import request

from ops.deploy.import_legacy_env import import_legacy_environment
from ops.deploy.render_container_bundle import (
    build_container_bundle,
    write_container_bundle,
)


DEPLOYMENT_VALUES = {
    "PROD_DATABASE_URL": "postgresql+psycopg2://bank:secret@127.0.0.1/bank",
    "PROD_MFA_AES256_GCM_KEY_B64": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
    "PROD_PASSWORD_PEPPER_B64": "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=",
    "PROD_PUBLIC_HOST": "sitbank.duckdns.org",
    "PROD_REDIS_URL": "redis://:secret@127.0.0.1:6379/0",
    "PROD_SECRET_KEY": "secret-key-with-$-and-enough-length-for-production",
    "PROD_SESSION_HMAC_ACTIVE_KEY_B64": "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI=",
    "PROD_SESSION_HMAC_ACTIVE_KEY_ID": "2026-06",
    "PROD_WTF_CSRF_SECRET_KEY": "csrf-secret-with-enough-length-for-production",
}


def _set_deployment_values(monkeypatch):
    for name, value in DEPLOYMENT_VALUES.items():
        monkeypatch.setenv(name, value)


def test_container_bundle_separates_secrets_from_non_secret_environment(monkeypatch):
    _set_deployment_values(monkeypatch)

    environment, secrets = build_container_bundle()

    assert environment["APP_ENV"] == "production"
    assert environment["WEBAUTHN_RP_ID"] == "sitbank.duckdns.org"
    assert environment["WEBAUTHN_RP_ORIGIN"] == "https://sitbank.duckdns.org"
    assert environment["SESSION_HMAC_ACTIVE_KEY_ID"] == "2026-06"
    assert environment["COMMON_PASSWORDS_PATH"] == "/run/config/common-passwords.txt"
    assert "SECRET_KEY" not in environment
    assert secrets["secret_key"] == DEPLOYMENT_VALUES["PROD_SECRET_KEY"]
    assert secrets["database_url"] == DEPLOYMENT_VALUES["PROD_DATABASE_URL"]
    assert '"2026-06":"MjIy' in secrets["session_hmac_keys_json"]


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


def test_legacy_environment_import_seeds_root_runtime_without_printing_values(
    tmp_path,
):
    source = tmp_path / "legacy.env"
    source.write_text(
        "\n".join(
            [
                f"SECRET_KEY={DEPLOYMENT_VALUES['PROD_SECRET_KEY']}",
                f"WTF_CSRF_SECRET_KEY={DEPLOYMENT_VALUES['PROD_WTF_CSRF_SECRET_KEY']}",
                "SESSION_HMAC_ACTIVE_KEY_ID=2026-06",
                'SESSION_HMAC_KEYS_JSON={"2026-06":"MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI="}',
                f"DATABASE_URL={DEPLOYMENT_VALUES['PROD_DATABASE_URL']}",
                f"REDIS_URL={DEPLOYMENT_VALUES['PROD_REDIS_URL']}",
                f"MFA_AES256_GCM_KEY_B64={DEPLOYMENT_VALUES['PROD_MFA_AES256_GCM_KEY_B64']}",
                f"PASSWORD_PEPPER_B64={DEPLOYMENT_VALUES['PROD_PASSWORD_PEPPER_B64']}",
                "MFA_ISSUER_NAME=SITBank",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    destination = tmp_path / "runtime"

    import_legacy_environment(
        source.resolve(),
        destination,
        "sitbank.duckdns.org",
    )

    environment = (destination / "container.env").read_text(encoding="utf-8")
    assert "MFA_ISSUER_NAME='SITBank'" in environment
    assert "DATABASE_URL" not in environment
    assert (destination / "secrets" / "database_url").read_text(
        encoding="utf-8"
    ) == DEPLOYMENT_VALUES["PROD_DATABASE_URL"]


def test_dockerfile_and_compose_enforce_hardened_runtime():
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    compose_text = Path("compose.prod.yml").read_text(encoding="utf-8")
    smoke_test = Path("ops/container/smoke-test.sh").read_text(encoding="utf-8")
    compose = yaml.safe_load(compose_text)
    app = compose["services"]["app"]

    assert compose["name"] == "sitbank"
    assert "python:3.12.11-slim-bookworm@sha256:" in dockerfile
    assert 'org.opencontainers.image.title="SITBank banking application"' in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "/health/ready" in dockerfile
    assert "apt-get upgrade" not in dockerfile
    assert app["network_mode"] == "host"
    assert app["read_only"] is True
    assert app["user"] == "10001:10001"
    assert app["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in app["security_opt"]
    assert "ports" not in app
    assert app["pids_limit"] == 256
    assert app["mem_limit"] == "768m"
    assert app["restart"] == "unless-stopped"
    assert all(volume["read_only"] for volume in app["volumes"])
    assert all(secret["mode"] == 0o400 for secret in app["secrets"])
    assert all(
        value.startswith("/run/secrets/")
        for name, value in app["environment"].items()
        if name.endswith("_FILE")
    )
    assert (
        "/app/redis_compatibility_check.py:ro"
        in smoke_test
    )
    assert "python /app/redis_compatibility_check.py" in smoke_test
    assert "/redis-check.py" not in smoke_test


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

    assert set(workflow["jobs"]) == {"test", "image-test", "publish", "deploy"}
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["publish"]["permissions"]["packages"] == "write"
    assert workflow["jobs"]["publish"]["permissions"]["id-token"] == "write"
    assert "attestations" not in workflow["jobs"]["publish"]["permissions"]
    assert workflow["jobs"]["deploy"]["permissions"]["packages"] == "read"
    assert all(
        job["timeout-minutes"] > 0
        for job in workflow["jobs"].values()
    )
    assert "vars.PROD_DEPLOY_ENABLED == 'true'" in workflow_text
    assert "provenance: mode=max" in workflow_text
    assert "sbom: true" in workflow_text
    assert "ignore-unfixed: true" in workflow_text
    assert "cosign sign --yes" in workflow_text
    assert "shellcheck" in workflow_text
    assert "scan_repository_secrets.py" in workflow_text
    assert "check_dependency_locks.py" in workflow_text
    assert "IMAGE_DIGEST" in workflow_text
    assert "StrictHostKeyChecking=no" not in workflow_text
    assert workflow_text.count("persist-credentials: false") == 4
    assert (
        workflow_text.count(
            "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10"
        )
        == 4
    )
    assert (
        "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405"
        in workflow_text
    )
    assert "sitbank:smoke" in workflow_text
    assert "SITBANK_IMAGE" in workflow_text
    assert "SITBANK_SECRET_KEY" not in workflow_text
    assert "sitbank-container-deploy" in workflow_text
    assert "sha256:[0-9a-f]{64}" in deploy_script
    assert "COSIGN_CERTIFICATE_IDENTITY" in deploy_script
    assert "org.opencontainers.image.revision" in deploy_script
    assert "production-check" in deploy_script
    assert "db upgrade" in deploy_script
    assert "previous_image" in deploy_script
    assert "restore_runtime" in deploy_script
    assert "load_runtime_secrets" not in deploy_script
    assert "SITBANK_SECRET_KEY" not in deploy_script
    assert "SITBANK_SECRET_KEY" not in runtime_script
    assert "gpasswd --delete" in bootstrap
    assert "docker.sock" in bootstrap
    assert "COSIGN_SHA256" in bootstrap
    assert "/opt/sitbank" in bootstrap
    assert "/etc/sitbank" in bootstrap
    assert "/var/lib/sitbank-container" in bootstrap
    assert "sitbank-deploy" in bootstrap
    assert "sitbank-container.service" in bootstrap


def test_only_sitbank_container_deployment_units_are_active():
    assert not Path("ops/deploy/bootstrap-ec2").exists()
    assert Path("ops/deploy/sitbank-container-deploy").exists()
    assert Path("ops/deploy/sitbank-container-runtime").exists()
    assert Path("ops/deploy/sitbank-database-cutover").exists()
    assert Path("ops/systemd/sitbank-container.service").exists()
    assert Path("ops/sudoers/sitbank-container-deploy").exists()


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
    readme = Path("README.md").read_text(encoding="utf-8")

    assert 'revision = "20260610_0001"' in migration
    assert '"users"' in migration
    assert '"webauthn_credentials"' in migration
    assert '"security_audit_events"' in migration
    assert "verify-migration-baseline" in readme
    assert "db stamp 20260610_0001" in readme
    assert "Do not run `db.create_all()`" in readme
    assert "WenJiangggg/SITBank" in readme
    assert "ghcr.io/wenjiangggg/sitbank@sha256:<digest>" in readme
    assert "sitbank_db" in readme
    assert "sitbank_user" in readme
    assert "sitbank-database-cutover prepare" in readme


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
