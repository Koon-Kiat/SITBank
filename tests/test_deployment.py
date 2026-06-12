from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from flask import request

from ops.deploy.import_legacy_env import import_legacy_environment
from ops.deploy.render_container_bundle import (
    build_container_bundle,
    build_container_environment,
    build_deployment_environment,
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


def _set_prefixed_deployment_values(monkeypatch, prefix: str, public_host: str):
    for name, value in DEPLOYMENT_VALUES.items():
        target_name = name.replace("PROD_", f"{prefix}_", 1)
        if name == "PROD_PUBLIC_HOST":
            value = public_host
        monkeypatch.setenv(target_name, value)


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


def test_container_bundle_accepts_staging_prefix(monkeypatch):
    _set_prefixed_deployment_values(
        monkeypatch,
        "STAGING",
        "staging.sitbank.example",
    )

    environment, secrets = build_container_bundle("STAGING")

    assert environment["APP_ENV"] == "production"
    assert environment["WEBAUTHN_RP_ID"] == "staging.sitbank.example"
    assert environment["WEBAUTHN_RP_ORIGIN"] == "https://staging.sitbank.example"
    assert environment["SESSION_HMAC_ACTIVE_KEY_ID"] == "2026-06"
    assert secrets["secret_key"] == DEPLOYMENT_VALUES["PROD_SECRET_KEY"]
    assert secrets["database_url"] == DEPLOYMENT_VALUES["PROD_DATABASE_URL"]


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
    assert production["POSTGRES_VOLUME_NAME"] == "none"
    assert production["REDIS_VOLUME_NAME"] == "none"

    assert staging["DEPLOYMENT_TARGET"] == "staging"
    assert staging["CONFIG_ROOT"] == "/etc/sitbank-staging"
    assert staging["SECRET_ROOT"] == "/etc/sitbank-staging/secrets"
    assert staging["COMPOSE_DIR"] == "/opt/sitbank-staging"
    assert staging["SYSTEMD_SERVICE"] == "sitbank-staging-container.service"
    assert staging["COMPOSE_PROJECT_NAME"] == "sitbank-staging"
    assert staging["APP_CONTAINER_NAME"] == "sitbank-staging-app"
    assert staging["APP_BIND_PORT"] == "5001"
    assert staging["POSTGRES_CONTAINER_NAME"] == "sitbank-staging-postgres"
    assert staging["REDIS_CONTAINER_NAME"] == "sitbank-staging-redis"
    assert staging["POSTGRES_VOLUME_NAME"] == "sitbank-staging-postgres-data"
    assert staging["REDIS_VOLUME_NAME"] == "sitbank-staging-redis-data"
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


def test_environment_only_bundle_does_not_export_long_lived_secrets(
    monkeypatch,
    tmp_path,
):
    _set_deployment_values(monkeypatch)
    for name in (
        "PROD_DATABASE_URL",
        "PROD_MFA_AES256_GCM_KEY_B64",
        "PROD_PASSWORD_PEPPER_B64",
        "PROD_REDIS_URL",
        "PROD_SECRET_KEY",
        "PROD_SESSION_HMAC_ACTIVE_KEY_B64",
        "PROD_WTF_CSRF_SECRET_KEY",
    ):
        monkeypatch.delenv(name)

    environment = build_container_environment()
    output = tmp_path / "runtime"
    write_container_bundle(output, include_secrets=False)

    assert environment["SESSION_HMAC_ACTIVE_KEY_ID"] == "2026-06"
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
        "STAGING_DATABASE_URL",
        "STAGING_MFA_AES256_GCM_KEY_B64",
        "STAGING_PASSWORD_PEPPER_B64",
        "STAGING_REDIS_URL",
        "STAGING_SECRET_KEY",
        "STAGING_SESSION_HMAC_ACTIVE_KEY_B64",
        "STAGING_WTF_CSRF_SECRET_KEY",
    ):
        monkeypatch.delenv(name)

    output = tmp_path / "runtime"
    write_container_bundle(output, "STAGING", include_secrets=False)

    environment = (output / "container.env").read_text(encoding="utf-8")
    deployment = (output / "deployment.env").read_text(encoding="utf-8")
    assert "WEBAUTHN_RP_ID='staging.sitbank.example'" in environment
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
    compose = yaml.safe_load(compose_text)
    app = compose["services"]["app"]
    staging_compose = yaml.safe_load(staging_compose_text)
    staging_services = staging_compose["services"]
    staging_app = staging_services["app"]

    assert compose["name"] == "sitbank"
    assert (
        "python:3.12.13-slim-trixie@"
        "sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203"
        in dockerfile
    )
    assert dockerfile.count("python:3.12.13-slim-trixie@sha256:") == 2
    assert 'org.opencontainers.image.title="SITBank banking application"' in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "/health/ready" in dockerfile
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
    assert all(volume["read_only"] for volume in app["volumes"])
    assert all(secret["mode"] == 0o400 for secret in app["secrets"])
    assert all(
        value.startswith("/run/secrets/")
        for name, value in app["environment"].items()
        if name.endswith("_FILE")
    )
    assert "/app/redis_compatibility_check.py:ro" in smoke_test
    assert "python /app/redis_compatibility_check.py" in smoke_test
    assert "/redis-check.py" not in smoke_test
    assert "--publish 127.0.0.1::5432" in smoke_test
    assert "--publish 127.0.0.1::6379" in smoke_test
    assert "wait_for_healthy smoke-postgres" in smoke_test
    assert "wait_for_healthy smoke-redis" in smoke_test
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
    assert set(staging_services) == {"app", "postgres", "redis"}
    assert staging_app["container_name"] == "sitbank-staging-app"
    assert staging_app["ports"] == ["127.0.0.1:5001:5000"]
    assert "network_mode" not in staging_app
    assert staging_app["read_only"] is True
    assert staging_app["user"] == "10001:10001"
    assert staging_app["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in staging_app["security_opt"]
    assert staging_app["env_file"] == ["/etc/sitbank-staging/container.env"]
    assert all(
        volume["source"].startswith("/etc/sitbank-staging/")
        for volume in staging_app["volumes"]
    )
    assert all(
        secret["file"].startswith("/etc/sitbank-staging/secrets/")
        for secret in staging_compose["secrets"].values()
    )
    assert staging_services["postgres"]["container_name"] == (
        "sitbank-staging-postgres"
    )
    assert staging_services["redis"]["container_name"] == "sitbank-staging-redis"
    assert "ports" not in staging_services["postgres"]
    assert "ports" not in staging_services["redis"]
    assert staging_compose["volumes"]["sitbank-staging-postgres-data"]["name"] == (
        "sitbank-staging-postgres-data"
    )
    assert staging_compose["volumes"]["sitbank-staging-redis-data"]["name"] == (
        "sitbank-staging-redis-data"
    )
    assert "/etc/sitbank-staging" not in compose_text
    assert "/etc/sitbank/" not in staging_compose_text
    assert "sitbank-staging-postgres-data" not in compose_text
    assert "sitbank-staging-redis-data" not in compose_text

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
        "deploy-production",
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
    trusted_jobs = ("release-verify", "deploy-staging", "deploy-production")
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
    assert "vars.PROD_DEPLOY_ENABLED == 'true'" in production_condition
    assert "needs.release-verify.result == 'success'" in production_condition
    assert "needs.deploy-staging.result == 'success'" in production_condition
    assert "vars.STAGING_DEPLOY_ENABLED != 'true'" not in production_condition
    assert "inputs.deploy == true" not in production_condition
    assert (
        workflow["jobs"]["deploy-staging"]["env"]["IMAGE_DIGEST"]
        == "${{ needs.release-verify.outputs.digest }}"
    )
    assert (
        workflow["jobs"]["deploy-production"]["env"]["IMAGE_DIGEST"]
        == "${{ needs.release-verify.outputs.digest }}"
    )
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
    assert all(job["timeout-minutes"] > 0 for job in workflow["jobs"].values())
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
    assert workflow_text.count(
        "sha256sum /usr/local/sbin/sitbank-container-deploy"
    ) == 2
    assert "EC2 staging deployment wrapper is missing or stale" in workflow_text
    assert "EC2 production deployment wrapper is missing or stale" in workflow_text
    for job_name, wrapper_step_name, upload_step_name in (
        (
            "deploy-staging",
            "Verify trusted staging deployment wrapper",
            "Upload authenticated deployment inputs",
        ),
        (
            "deploy-production",
            "Verify trusted production deployment wrapper",
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
    assert workflow_text.count("persist-credentials: false") == 9
    assert (
        workflow_text.count(
            "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10"
        )
        == 9
    )
    assert (
        "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405"
        in workflow_text
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
    assert "RELEASE_SHA: ${{ github.sha }}" not in workflow_text
    assert "SITBANK_SECRET_KEY" not in workflow_text
    assert "STAGING_SECRET_KEY" not in workflow_text
    assert "STAGING_DATABASE_URL" not in workflow_text
    assert "PROD_SECRET_KEY" not in workflow_text
    assert "PROD_DATABASE_URL" not in workflow_text
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
    assert "sitbank-staging-redis-data" in deploy_script
    assert "Staging secret must not reuse the production" in deploy_script
    assert "hostname != \"postgres\"" in deploy_script
    assert "hostname != \"redis\"" in deploy_script
    assert "sitbank-container-runtime staging up" in Path(
        "ops/systemd/sitbank-staging-container.service"
    ).read_text(encoding="utf-8")
    assert "--project-name \"${COMPOSE_PROJECT}\"" in runtime_script
    assert "gpasswd --delete" in bootstrap
    assert "docker.sock" in bootstrap
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

    readme = Path("README.md").read_text(encoding="utf-8")
    assert "Manual pre-merge staging:" in readme
    assert "run trusted workflow from main" in readme
    assert "source_ref = candidate branch, tag, or SHA" in readme
    assert "resolve immutable source_sha" in readme
    assert "deploy staging using trusted main scripts" in readme
    assert "main push -> publish -> release-verify -> staging -> production" in readme
    assert "Manual production deployment is disabled." in readme
    assert "Production never skips disabled, skipped, or failed staging." in readme
    assert "Feature-branch workflow and deployment scripts" in readme


def test_trivy_exception_is_narrow_documented_and_temporary():
    trivyignore = Path(".trivyignore").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")
    security = Path("SECURITY.md").read_text(encoding="utf-8")
    active_ignores = [
        line.strip()
        for line in trivyignore.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert active_ignores == ["CVE-2026-42496", "CVE-2026-8376"]
    for required in (
        "official python:3.12.13-slim-trixie / Debian Trixie",
        "does not install Perl directly",
        "Essential: yes",
        "must not be removed",
        "does not invoke Perl",
        "does not process attacker-controlled tar archives with Perl",
        "temporary",
        "review/remove-by date: 2026-06-26",
    ):
        assert required in trivyignore
    assert "CVE-2026-42496" in readme
    assert "CVE-2026-8376" in readme
    assert "2026-06-26" in readme
    assert "mixing Debian sid packages into Trixie is riskier" in readme
    assert "full Critical Trivy report with no ignore file" in readme
    assert "fixable High/Critical gate must continue to run without" in security


def test_dependabot_tracks_docker_base_images_without_automerge():
    dependabot = yaml.safe_load(Path(".github/dependabot.yml").read_text(encoding="utf-8"))
    readme = Path("README.md").read_text(encoding="utf-8")
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
    assert "Dependabot updates are review-only" in readme
    assert "Base-image updates must not be auto-merged" in readme
    assert "container smoke test, Compose" in readme
    assert "Ordinary pull requests skip the full authenticated DAST crawl" in readme
    assert "scheduled scans" in readme
    assert "release verification retain that coverage" in readme


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
    assert "github/codeql-action/init@411bbbe57033eedfc1a82d68c01345aa96c737d7" in codeql
    assert "github/codeql-action/analyze@411bbbe57033eedfc1a82d68c01345aa96c737d7" in codeql
    assert "languages: python" in codeql


def test_every_github_action_is_pinned_to_a_full_commit_sha():
    workflow_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path(".github/workflows").glob("*.yml")
    )
    uses = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow_text, flags=re.MULTILINE)

    assert uses
    for action in uses:
        assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), action
    assert "pull_request_target:" not in workflow_text


def test_only_sitbank_container_deployment_units_are_active():
    assert not Path("ops/deploy/bootstrap-ec2").exists()
    assert Path("ops/deploy/sitbank-container-deploy").exists()
    assert Path("ops/deploy/sitbank-container-runtime").exists()
    assert Path("ops/deploy/sitbank-database-cutover").exists()
    assert Path("ops/systemd/sitbank-container.service").exists()
    assert Path("ops/systemd/sitbank-staging-container.service").exists()
    assert Path("ops/sudoers/sitbank-container-deploy").exists()


def test_staging_nginx_routes_only_to_the_staging_loopback_port():
    nginx = Path("ops/nginx/sitbank-staging.conf").read_text(encoding="utf-8")

    assert "server_name staging-sitbank.duckdns.org;" in nginx
    assert "proxy_pass http://127.0.0.1:5001;" in nginx
    assert "127.0.0.1:5000" not in nginx
    assert "server_name sitbank.duckdns.org;" not in nginx


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
