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

from ops.deploy.import_legacy_env import import_legacy_environment
from ops.deploy.render_container_bundle import (
    NON_SECRET_DEFAULTS,
    SECRET_INPUTS,
    build_container_bundle,
    build_container_environment,
    build_deployment_environment,
    write_container_bundle,
)
from ops.runtime_contract import (
    APP_SECRET_FILE_ENVIRONMENT,
    APP_SECRET_FILES,
    CONFIG_SECRET_INPUTS,
    DEPLOYMENT_SECRET_INPUTS,
    DEPLOYMENT_SECRET_FILES,
    NON_SECRET_DEFAULTS as CONTRACT_NON_SECRET_DEFAULTS,
    NON_SECRET_RUNTIME_ENVIRONMENT,
    STAGING_DATA_SERVICE_SECRETS,
)


ACTION_USES_PIN_RE = re.compile(r"[^@]+@[0-9a-f]{40}")
PYTHON_SLIM_TRIXIE_DIGEST_RE = re.compile(
    r"python:3\.12(?:\.\d+)?-slim-trixie@sha256:[0-9a-f]{64}"
)

DEPLOYMENT_VALUES = {
    "PROD_DATABASE_MIGRATION_URL": "postgresql+psycopg2://bank_owner:secret@127.0.0.1/bank",
    "PROD_DATABASE_URL": "postgresql+psycopg2://bank:secret@127.0.0.1/bank",
    "PROD_MFA_KEK_ACTIVE_ID": "2026-06-mfa",
    "PROD_MFA_KEK_KEYS_JSON": '{"2026-06-mfa":"NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ="}',
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


def _nginx_location_bodies(config: str, selector: str) -> list[str]:
    return re.findall(
        rf"location\s+{re.escape(selector)}\s*\{{(.*?)\n\s*\}}",
        config,
        flags=re.DOTALL,
    )


def _config_secret_inputs() -> set[str]:
    tree = ast.parse(Path("config.py").read_text(encoding="utf-8"))
    secret_readers = {
        "_optional_url",
        "_required_b64_32_bytes",
        "_required_keyring",
        "_required_secret",
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
    ):
        assert privilege_probe in source


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


def test_container_bundle_separates_secrets_from_non_secret_environment(monkeypatch):
    _set_deployment_values(monkeypatch)

    environment, secrets = build_container_bundle()

    assert set(environment) == set(NON_SECRET_RUNTIME_ENVIRONMENT)
    assert environment["APP_ENV"] == "production"
    assert environment["WEBAUTHN_RP_ID"] == "sitbank.duckdns.org"
    assert environment["WEBAUTHN_RP_ORIGIN"] == "https://sitbank.duckdns.org"
    assert environment["SESSION_HMAC_ACTIVE_KEY_ID"] == "2026-06"
    assert environment["MFA_KEK_ACTIVE_ID"] == "2026-06-mfa"
    assert environment["COMMON_PASSWORDS_PATH"] == "/run/config/common-passwords.txt"
    assert "SECRET_KEY" not in environment
    assert "DATABASE_MIGRATION_URL" not in environment
    assert "DATABASE_MIGRATION_URL_FILE" not in environment
    assert secrets["secret_key"] == DEPLOYMENT_VALUES["PROD_SECRET_KEY"]
    assert secrets["database_url"] == DEPLOYMENT_VALUES["PROD_DATABASE_URL"]
    assert secrets["database_migration_url"] == DEPLOYMENT_VALUES["PROD_DATABASE_MIGRATION_URL"]
    assert secrets["mfa_kek_keys_json"] == DEPLOYMENT_VALUES["PROD_MFA_KEK_KEYS_JSON"]
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
    assert environment["MFA_KEK_ACTIVE_ID"] == "2026-06-mfa"
    assert secrets["secret_key"] == DEPLOYMENT_VALUES["PROD_SECRET_KEY"]
    assert secrets["database_url"] == DEPLOYMENT_VALUES["PROD_DATABASE_URL"]
    assert secrets["database_migration_url"] == DEPLOYMENT_VALUES["PROD_DATABASE_MIGRATION_URL"]


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
    assert SECRET_INPUTS == DEPLOYMENT_SECRET_INPUTS
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
    for path, secret_root, extra_secrets in (
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

        expected_top_level = set(DEPLOYMENT_SECRET_FILES) | set(extra_secrets)
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
    assert ':/run/secrets/database_migration_url:ro' not in smoke_test
    assert '"${secrets_mount_source}:/run/secrets:ro"' in smoke_test

    _assert_sets_equal(
        set(_extract_bash_array(deploy_script, "allowed_environment")),
        set(NON_SECRET_RUNTIME_ENVIRONMENT),
        context="sitbank-container-deploy allowed_environment vs runtime contract",
    )
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
    assert 'logs --no-color --tail 120 postgres redis' in deploy_script
    assert "dependencies_prepared=1" in deploy_script


def test_local_ci_command_documents_required_local_checks():
    ci_local = Path("scripts/ci-local").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")

    for expected in (
        "tests/test_deployment.py",
        "tests/test_redis_session_integrity.py",
        '"pytest"',
        '"compileall"',
        '"pip", "check"',
        '"bandit"',
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
    assert "MFA_KEK_ACTIVE_ID='2026-06-mfa'" in environment
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
                "MFA_KEK_ACTIVE_ID=2026-06-mfa",
                f"MFA_KEK_KEYS_JSON={DEPLOYMENT_VALUES['PROD_MFA_KEK_KEYS_JSON']}",
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
    assert "MFA_KEK_ACTIVE_ID='2026-06-mfa'" in environment
    assert "DATABASE_URL" not in environment
    assert (destination / "secrets" / "database_url").read_text(
        encoding="utf-8"
    ) == DEPLOYMENT_VALUES["PROD_DATABASE_URL"]
    assert (destination / "secrets" / "mfa_kek_keys_json").read_text(
        encoding="utf-8"
    ) == DEPLOYMENT_VALUES["PROD_MFA_KEK_KEYS_JSON"]


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
    staging_compose = yaml.safe_load(staging_compose_text)
    staging_services = staging_compose["services"]
    staging_app = staging_services["app"]

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
    assert all(set(secret) == {"source", "target"} for secret in app["secrets"])
    assert all(
        value.startswith("/run/secrets/")
        for name, value in app["environment"].items()
        if name.endswith("_FILE")
    )
    assert "DATABASE_MIGRATION_URL_FILE" not in app["environment"]
    assert "/app/redis_compatibility_check.py:ro" in smoke_test
    assert "python /app/redis_compatibility_check.py" in smoke_test
    assert "ci_owner" in smoke_test
    assert "ci_app" in smoke_test
    assert "CREATE ROLE ci_owner" in smoke_test
    assert "CREATE ROLE ci_app" in smoke_test
    assert "Owner role exists: yes" in smoke_test
    assert "Runtime role exists: yes" in smoke_test
    assert "Owner connection test: passed" in smoke_test
    assert "Runtime connection test: passed" in smoke_test
    assert "DATABASE_MIGRATION_URL_FILE" in smoke_test
    assert "docker_bind_source" in smoke_test
    assert "docker network create" in smoke_test
    assert '--network "${network_name}"' in smoke_test
    assert "host.docker.internal" not in smoke_test
    assert "postgresql+psycopg2://ci_app:ci-app-password@%s:5432/ci" in smoke_test
    assert "postgresql+psycopg2://ci_owner:ci-owner-password@%s:5432/ci" in smoke_test
    assert "redis://:ci-password@%s:6379/15" in smoke_test
    assert '"${postgres_container}"' in smoke_test
    assert '"${redis_container}"' in smoke_test
    assert '"${secrets_mount_source}:/run/secrets:ro"' in smoke_test
    assert '"${config_mount_source}:/run/config:ro"' in smoke_test
    assert '"${work_dir}/secrets:/run/secrets:ro"' not in smoke_test
    assert '"${work_dir}/secrets/database_migration_url"' in smoke_test
    assert ':/run/secrets/database_migration_url:ro' not in smoke_test
    assert "verify-runtime-db-privileges" in smoke_test
    assert "/redis-check.py" not in smoke_test
    assert "--publish 127.0.0.1::5432" not in smoke_test
    assert "--publish 127.0.0.1::6379" not in smoke_test
    assert 'wait_for_healthy "${postgres_container}"' in smoke_test
    assert 'wait_for_healthy "${redis_container}"' in smoke_test
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
    assert set(staging_services) == {"app", "postgres", "redis"}
    assert staging_app["container_name"] == "sitbank-staging-app"
    assert staging_app["ports"] == ["127.0.0.1:5001:5000"]
    assert "network_mode" not in staging_app
    assert staging_app["read_only"] is True
    assert staging_app["user"] == "10001:10001"
    assert staging_app["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in staging_app["security_opt"]
    assert staging_app["env_file"] == ["/etc/sitbank-staging/container.env"]
    assert "DATABASE_MIGRATION_URL_FILE" not in staging_app["environment"]
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
    assert staging_services["redis"]["container_name"] == "sitbank-staging-redis"
    assert "ports" not in staging_services["postgres"]
    assert "ports" not in staging_services["redis"]
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
    assert staging_compose["volumes"]["sitbank-staging-redis-data"]["name"] == (
        "sitbank-staging-redis-data"
    )
    assert "/etc/sitbank-staging" not in compose_text
    assert "/etc/sitbank/" not in staging_compose_text
    assert "sitbank-staging-postgres-data" not in compose_text
    assert "sitbank-staging-redis-data" not in compose_text
    assert "--wait --wait-timeout 120" in deploy_script
    assert deploy_script.count("--retry-all-errors") == 2
    assert "show_app_diagnostics" in deploy_script
    assert "DATABASE_MIGRATION_URL_FILE=/run/secrets/database_migration_url" in deploy_script
    assert "Staging runtime database URL must use only the staging app role" in deploy_script
    assert "Staging migration database URL must use only the staging owner role" in deploy_script
    assert "Staging runtime and migration database URLs must be different" in deploy_script
    assert "Staging database URL must target only the staging PostgreSQL service" not in deploy_script
    assert 'unquote(database.username or "") != "sitbank_app"' in deploy_script
    assert 'unquote(migration.username or "") != "sitbank_owner"' in deploy_script
    assert "postgres_app_password" in deploy_script
    assert "postgres_owner_password" in deploy_script
    assert "verify-runtime-db-privileges" in deploy_script
    assert "staging_migration_run" not in deploy_script
    assert deploy_script.count("migration_run \\") == 2
    assert (
        "Complete the production database role split and install the "
        "owner-role migration URL before retrying deployment."
        in deploy_script
    )
    assert "DATABASE_MIGRATION_URL must not be configured for the runtime app" in Path(
        "app/ops/commands.py"
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
    assert "logs --no-color --tail 80 app" in deploy_script
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
        workflow["jobs"]["deploy-staging"]["env"]["STAGING_MFA_KEK_ACTIVE_ID"]
        == "${{ vars.STAGING_MFA_KEK_ACTIVE_ID }}"
    )
    assert (
        workflow["jobs"]["deploy-production"]["env"]["IMAGE_DIGEST"]
        == "${{ needs.release-verify.outputs.digest }}"
    )
    assert (
        workflow["jobs"]["deploy-production"]["env"]["PROD_MFA_KEK_ACTIVE_ID"]
        == "${{ vars.PROD_MFA_KEK_ACTIVE_ID }}"
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
    docs = _project_docs_text()
    assert "Manual pre-merge staging:" in docs
    assert "run trusted workflow from main" in docs
    assert "source_ref = candidate branch, tag, or SHA" in docs
    assert "resolve immutable source_sha" in docs
    assert "deploy staging using trusted main scripts" in docs
    assert "main push -> publish -> release-verify -> staging -> production" in docs
    assert "Manual production deployment is disabled." in docs
    assert "Production never skips disabled, skipped, or failed staging." in docs
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


def test_only_sitbank_container_deployment_units_are_active():
    assert not Path("ops/deploy/bootstrap-ec2").exists()
    assert Path("ops/deploy/sitbank-container-bootstrap").exists()
    assert Path("ops/deploy/sitbank-container-deploy").exists()
    assert Path("ops/deploy/sitbank-container-runtime").exists()
    assert Path("ops/deploy/sitbank-database-cutover").exists()
    assert Path("ops/systemd/sitbank-container.service").exists()
    assert Path("ops/systemd/sitbank-staging-container.service").exists()
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
        Path("ops/nginx-proxy-headers.conf"),
        Path("ops/nginx/sitbank-production.conf"),
        Path("ops/nginx/sitbank-production-rate-limits.conf"),
        Path("ops/nginx/sitbank-staging.conf"),
        Path("ops/nginx/sitbank-staging-rate-limits.conf"),
        Path("ops/sudoers/sitbank-container-deploy"),
        Path("ops/systemd/sitbank-container.service"),
        Path("ops/systemd/sitbank-staging-container.service"),
    )

    assert "*.sh text eol=lf" in attributes
    assert "*.yml text eol=lf" in attributes
    assert "*.conf text eol=lf" in attributes
    assert "*.service text eol=lf" in attributes
    assert "ops/deploy/bootstrap-container-ec2 text eol=lf" in attributes
    assert "ops/deploy/sitbank-container-bootstrap text eol=lf" in attributes
    assert "ops/sudoers/* text eol=lf" in attributes
    for path in linux_files:
        assert b"\r\n" not in path.read_bytes(), f"{path} must use LF line endings"

    assert "Refusing to install CRLF-formatted Linux file" in bootstrap
    assert "grep -q $'\\r$'" in bootstrap


def test_staging_nginx_enforces_https_auth_health_and_rate_limits():
    nginx = Path("ops/nginx/sitbank-staging.conf").read_text(encoding="utf-8")
    rate_limits = Path("ops/nginx/sitbank-staging-rate-limits.conf").read_text(
        encoding="utf-8"
    )
    staging_compose = yaml.safe_load(Path("compose.staging.yml").read_text(encoding="utf-8"))
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(
        encoding="utf-8"
    )

    assert Path("ops/nginx/sitbank-staging-rate-limits.conf").exists()
    assert "listen 80;" in nginx
    assert "return 301 https://$host$request_uri;" in nginx
    assert "listen 443 ssl http2;" in nginx
    assert "server_name staging-sitbank.duckdns.org;" in nginx
    assert "ssl_certificate /etc/letsencrypt/live/staging-sitbank.duckdns.org/fullchain.pem;" in nginx
    assert "ssl_certificate_key /etc/letsencrypt/live/staging-sitbank.duckdns.org/privkey.pem;" in nginx
    assert 'add_header X-Content-Type-Options "nosniff" always;' in nginx
    assert 'add_header X-Frame-Options "DENY" always;' in nginx
    assert 'add_header Referrer-Policy "no-referrer" always;' in nginx
    assert "Permissions-Policy" in nginx
    assert "preload" not in nginx
    assert 'auth_basic "SITBank staging";' in nginx
    assert "auth_basic_user_file /etc/nginx/.htpasswd-sitbank-staging;" in nginx
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

    health_bodies = _nginx_location_bodies(nginx, "= /health/ready")
    assert len(health_bodies) == 1
    health_body = health_bodies[0]
    assert "auth_basic off;" in health_body
    assert "allow 127.0.0.1;" in health_body
    assert "allow ::1;" in health_body
    assert "deny all;" in health_body
    assert "proxy_pass http://127.0.0.1:5001;" in health_body
    assert "limit_req" not in health_body

    proxy_targets = set(re.findall(r"proxy_pass\s+([^;]+);", nginx))
    assert proxy_targets == {"http://127.0.0.1:5001"}
    assert "127.0.0.1:5000" not in nginx
    assert "server_name sitbank.duckdns.org;" not in nginx
    assert staging_compose["services"]["app"]["ports"] == ["127.0.0.1:5001:5000"]
    assert "ports" not in staging_compose["services"]["postgres"]
    assert "ports" not in staging_compose["services"]["redis"]

    assert "limit_req_zone $binary_remote_addr zone=sitbank_staging_login:10m rate=5r/m;" in rate_limits
    assert "limit_req_zone $binary_remote_addr zone=sitbank_staging_app:10m rate=10r/s;" in rate_limits
    assert "limit_req_status 429;" in nginx
    assert "limit_req_log_level warn;" in nginx
    assert "limit_req_status" not in rate_limits
    assert "limit_req_log_level" not in rate_limits
    for selector in ("= /login", "= /register", "= /mfa/verify", "^~ /auth/"):
        bodies = _nginx_location_bodies(nginx, selector)
        assert len(bodies) == 1
        assert "limit_req zone=sitbank_staging_login" in bodies[0]
    assert any(
        "limit_req zone=sitbank_staging_app" in body
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
    assert "Missing required staging TLS file" in bootstrap
    assert "apache2-utils" in bootstrap
    assert "certbot" in bootstrap
    assert "STAGING_RATE_LIMITS_FILE=\"/etc/nginx/conf.d/sitbank-staging-rate-limits.conf\"" in bootstrap
    assert "ops/nginx/sitbank-staging-rate-limits.conf" in bootstrap
    assert "sitbank-staging-rate-limits.$(date -u +%Y%m%dT%H%M%SZ).conf" in bootstrap
    assert "nginx-sitbank-staging.$(date -u +%Y%m%dT%H%M%SZ).conf" in bootstrap
    assert "&& ! cmp -s \\" in bootstrap
    assert '"${repo_root}/ops/nginx/sitbank-staging.conf" \\' in bootstrap
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
    nginx = Path("ops/nginx/sitbank-production.conf").read_text(encoding="utf-8")
    rate_limits = Path("ops/nginx/sitbank-production-rate-limits.conf").read_text(
        encoding="utf-8"
    )
    proxy_headers = Path("ops/nginx-proxy-headers.conf").read_text(encoding="utf-8")
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(
        encoding="utf-8"
    )
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    production_compose = yaml.safe_load(Path("compose.prod.yml").read_text(encoding="utf-8"))
    app = production_compose["services"]["app"]

    assert Path("ops/nginx/sitbank-production.conf").exists()
    assert Path("ops/nginx/sitbank-production-rate-limits.conf").exists()
    assert "listen 80;" in nginx
    assert "return 301 https://sitbank.duckdns.org$request_uri;" in nginx
    assert "listen 443 ssl http2;" in nginx
    assert "server_name sitbank.duckdns.org;" in nginx
    assert "ssl_certificate /etc/letsencrypt/live/sitbank.duckdns.org/fullchain.pem;" in nginx
    assert "ssl_certificate_key /etc/letsencrypt/live/sitbank.duckdns.org/privkey.pem;" in nginx
    assert 'add_header X-Content-Type-Options "nosniff" always;' in nginx
    assert 'add_header X-Frame-Options "DENY" always;' in nginx
    assert 'add_header Referrer-Policy "no-referrer" always;' in nginx
    assert "Permissions-Policy" in nginx
    assert 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' in nginx
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

    health_ready_bodies = _nginx_location_bodies(nginx, "= /health/ready")
    assert len(health_ready_bodies) == 1
    health_ready = health_ready_bodies[0]
    assert "allow 127.0.0.1;" in health_ready
    assert "allow ::1;" in health_ready
    assert "deny all;" in health_ready
    assert "proxy_pass http://127.0.0.1:5000;" in health_ready
    assert "limit_req" not in health_ready

    health_live_bodies = _nginx_location_bodies(nginx, "= /health/live")
    assert len(health_live_bodies) == 1
    assert "proxy_pass http://127.0.0.1:5000;" in health_live_bodies[0]

    proxy_targets = set(re.findall(r"proxy_pass\s+([^;]+);", nginx))
    assert proxy_targets == {"http://127.0.0.1:5000"}
    assert "0.0.0.0:5000" not in nginx
    assert "--bind\", \"127.0.0.1:5000" in dockerfile
    assert app["network_mode"] == "host"
    assert "ports" not in app

    for zone in (
        "limit_req_zone $binary_remote_addr zone=sitbank_prod_app:10m rate=20r/s;",
        "limit_req_zone $binary_remote_addr zone=sitbank_prod_auth:10m rate=5r/m;",
        "limit_req_zone $binary_remote_addr zone=sitbank_prod_register:10m rate=2r/m;",
        "limit_req_zone $binary_remote_addr zone=sitbank_prod_challenge:10m rate=3r/m;",
        "limit_req_zone $binary_remote_addr zone=sitbank_prod_security:10m rate=10r/m;",
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
        bodies = _nginx_location_bodies(nginx, selector)
        assert len(bodies) == 1
        assert f"limit_req zone={zone}" in bodies[0]
        assert "include /etc/nginx/snippets/sitbank-proxy-headers.conf;" in bodies[0]
    assert any(
        "limit_req zone=sitbank_prod_app" in body
        for body in _nginx_location_bodies(nginx, "/")
    )

    assert "proxy_set_header X-Forwarded-For $remote_addr;" in proxy_headers
    assert "$proxy_add_x_forwarded_for" not in proxy_headers

    assert 'PRODUCTION_PUBLIC_HOST="sitbank.duckdns.org"' in bootstrap
    assert "Production PUBLIC_HOST must be ${PRODUCTION_PUBLIC_HOST}" in bootstrap
    assert "Missing required production TLS file" in bootstrap
    assert "Issue the production Certbot certificate before rerunning bootstrap." in bootstrap
    assert "PRODUCTION_RATE_LIMITS_FILE=\"/etc/nginx/conf.d/sitbank-production-rate-limits.conf\"" in bootstrap
    assert "ops/nginx/sitbank-production-rate-limits.conf" in bootstrap
    assert "ops/nginx/sitbank-production.conf" in bootstrap
    assert "Refusing to replace unsafe production Nginx rate-limit file" in bootstrap
    assert "Refusing to replace unsafe production Nginx config" in bootstrap
    assert "Conflicting Nginx production site is already enabled" in bootstrap
    assert "Disable the duplicate production server block" in bootstrap
    assert "nginx-sitbank-production-rate-limits.$(date -u +%Y%m%dT%H%M%SZ).conf" in bootstrap
    assert "nginx-sitbank-production.$(date -u +%Y%m%dT%H%M%SZ).conf" in bootstrap
    assert "/etc/nginx/sites-enabled/sitbank" in bootstrap

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
        "Nginx terminates TLS, redirects HTTP to HTTPS",
        "Gunicorn binds only to `127.0.0.1:5000`",
        "compose.prod.yml` publishes no",
        "`/health/ready` is for local deployment and load-balancer checks",
        "Cloudflare or AWS WAF should sit in front of Nginx",
        "The reviewed production bootstrap installs and enables the production edge",
        "requires a production bootstrap after merge",
        "sudo test -r /etc/letsencrypt/live/sitbank.duckdns.org/fullchain.pem",
        "Cloudflare or AWS WAF rules and security-group allowlists are still",
        "sudo nginx -t",
        "sudo ss -ltnp | grep -E ':(80|443|5000)([[:space:]]|$)'",
        "sudo docker inspect --format '{{json .NetworkSettings.Ports}}' sitbank-app",
        "curl --fail https://sitbank.duckdns.org/health/live",
        "curl -I https://sitbank.duckdns.org/health/ready",
        "external `/health/ready` returns `403`",
    ):
        assert required in docs

    for required in (
        "Production Edge and WAF Checklist",
        "Run production bootstrap from reviewed `main`",
        "`nginx -t` succeeds",
        "Issue production Certbot files under",
        "Allow public inbound TCP `80` and `443` only.",
        "never allow TCP `22` from `0.0.0.0/0` or `::/0`",
        "Do not expose Gunicorn, PostgreSQL, or Redis directly to the internet.",
        "Keep Gunicorn bound to `127.0.0.1:5000`",
        "Restrict `/health/ready` to loopback",
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
        "sudo htpasswd -c /etc/nginx/.htpasswd-sitbank-staging",
        "sudo chown root:www-data /etc/nginx/.htpasswd-sitbank-staging",
        "sudo chmod 0640 /etc/nginx/.htpasswd-sitbank-staging",
        "Do not store the Basic Auth password or generated htpasswd hash in the repo.",
        "sudo certbot --nginx -d staging-sitbank.duckdns.org",
        "sudo certbot certonly --webroot",
        "sudo certbot renew --dry-run",
        "ops/deploy/bootstrap-container-ec2",
        "staging-sitbank.duckdns.org",
        "Nginx proxy header snippet",
        "rate-limit include",
        "sudo nginx -t",
        "sudo systemctl reload nginx",
        "curl -k -I https://staging-sitbank.duckdns.org/",
        'curl -k -I -u "$STAGING_BASIC_AUTH_USER:$STAGING_BASIC_AUTH_PASSWORD"',
        "curl -k -I https://staging-sitbank.duckdns.org/health/ready",
        "curl -fsS http://127.0.0.1:5001/health/ready",
        "unauthenticated `/` returns `401`",
        "external `/health/ready` returns `403`",
        "local app readiness",
        "separate from application deployment",
    ):
        assert required in docs
    assert re.search(r"authenticated `/` returns\s+`200`", docs)


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
    docs = _project_docs_text()

    assert 'revision = "20260610_0001"' in migration
    assert '"users"' in migration
    assert '"webauthn_credentials"' in migration
    assert '"security_audit_events"' in migration
    assert "verify-migration-baseline" in docs
    assert "db stamp 20260610_0001" in docs
    assert "Do not run `db.create_all()`" in docs
    assert "WenJiangggg/SITBank" in docs
    assert "ghcr.io/wenjiangggg/sitbank@sha256:<digest>" in docs
    assert "sitbank_db" in docs
    assert "sitbank_owner" in docs
    assert "sitbank_app" in docs
    assert "sitbank-database-cutover prepare" in docs


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
