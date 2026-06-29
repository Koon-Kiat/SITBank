from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture()
def ci_local_module():
    module_name = "sitbank_ci_local_test"
    loader = importlib.machinery.SourceFileLoader(module_name, "scripts/ci-local")
    spec = importlib.util.spec_from_loader(module_name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    loader.exec_module(module)
    try:
        yield module
    finally:
        sys.modules.pop(module_name, None)


def test_default_mode_reports_docker_checks_skipped_when_docker_is_unavailable(
    ci_local_module, monkeypatch, capsys
):
    monkeypatch.setattr(ci_local_module.shutil, "which", lambda _name: None)
    results = []

    succeeded = ci_local_module.run_docker_checks(
        require_docker=False,
        bash="bash",
        results=results,
    )
    ci_local_module.print_summary(results)

    output = capsys.readouterr().out
    assert succeeded is True
    assert [result.status for result in results] == ["SKIPPED"]
    assert "SKIPPED: Docker/Compose checks" in output
    assert "Local validation is partial" in output
    assert "OVERALL: PASS (PARTIAL" in output


def test_strict_mode_fails_when_docker_is_unavailable(
    ci_local_module, monkeypatch, capsys
):
    monkeypatch.setattr(ci_local_module.shutil, "which", lambda _name: None)
    results = []

    succeeded = ci_local_module.run_docker_checks(
        require_docker=True,
        bash="bash",
        results=results,
    )
    ci_local_module.print_summary(results)

    output = capsys.readouterr()
    assert succeeded is False
    assert [result.status for result in results] == ["FAIL"]
    assert "Docker is required by --require-docker" in output.err
    assert "OVERALL: FAIL" in output.out


def test_cli_and_environment_can_enable_strict_docker_mode(
    ci_local_module, monkeypatch
):
    assert ci_local_module.parse_args(["--require-docker"]).require_docker is True

    monkeypatch.setattr(ci_local_module, "PYTHON_CHECKS", ())
    monkeypatch.setattr(ci_local_module, "discover_lint_targets", lambda _kind: [])
    monkeypatch.setattr(
        ci_local_module,
        "run_optional_static_analysis",
        lambda _results: True,
    )
    monkeypatch.setattr(ci_local_module, "find_git_bash", lambda: "bash")
    monkeypatch.setenv("CI_LOCAL_REQUIRE_DOCKER", "1")
    observed = {}

    def fake_docker_checks(*, require_docker, bash, results):
        observed["require_docker"] = require_docker
        observed["bash"] = bash
        ci_local_module.record_result(
            results,
            "Docker CLI availability",
            "FAIL",
        )
        return False

    monkeypatch.setattr(ci_local_module, "run_docker_checks", fake_docker_checks)

    assert ci_local_module.main([]) == 1
    assert observed == {"require_docker": True, "bash": "bash"}


def test_strict_mode_fails_when_docker_compose_is_unavailable(
    ci_local_module, monkeypatch
):
    monkeypatch.setattr(ci_local_module.shutil, "which", lambda _name: "docker")

    def fake_run(command, **_kwargs):
        returncode = 1 if command == ["docker", "compose", "version"] else 0
        return subprocess.CompletedProcess(command, returncode)

    monkeypatch.setattr(ci_local_module.subprocess, "run", fake_run)
    results = []

    succeeded = ci_local_module.run_docker_checks(
        require_docker=True,
        bash="bash",
        results=results,
    )

    assert succeeded is False
    assert [(result.name, result.status) for result in results] == [
        ("Docker CLI availability", "PASS"),
        ("Docker daemon reachability", "PASS"),
        ("Docker Compose availability", "FAIL"),
    ]


def test_strict_mode_fails_when_docker_daemon_is_unreachable(
    ci_local_module, monkeypatch
):
    monkeypatch.setattr(ci_local_module.shutil, "which", lambda _name: "docker")

    def fake_run(command, **_kwargs):
        returncode = 1 if command == ["docker", "version"] else 0
        return subprocess.CompletedProcess(command, returncode)

    monkeypatch.setattr(ci_local_module.subprocess, "run", fake_run)
    results = []

    succeeded = ci_local_module.run_docker_checks(
        require_docker=True,
        bash="bash",
        results=results,
    )

    assert succeeded is False
    assert [(result.name, result.status) for result in results] == [
        ("Docker CLI availability", "PASS"),
        ("Docker daemon reachability", "FAIL"),
    ]


def test_strict_mode_attempts_production_and_staging_compose_validation(
    ci_local_module, monkeypatch
):
    monkeypatch.setattr(ci_local_module.shutil, "which", lambda _name: "docker")
    commands = []

    def fake_run(command, **_kwargs):
        commands.append(list(command))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(ci_local_module.subprocess, "run", fake_run)
    results = []

    succeeded = ci_local_module.run_docker_checks(
        require_docker=True,
        bash="bash",
        results=results,
    )

    assert succeeded is True
    assert ["docker", "version"] in commands
    assert ["docker", "compose", "version"] in commands
    assert [
        "bash",
        "ops/container/validate-compose.sh",
        "sitbank:local-ci",
    ] in commands

    validator = Path("ops/container/validate-compose.sh").read_text(encoding="utf-8")
    assert "docker compose" in validator
    assert "compose.prod.yml" in validator
    assert "compose.staging.yml" in validator


def test_final_summary_distinguishes_pass_fail_and_skipped(
    ci_local_module, capsys
):
    results = [
        ci_local_module.CheckResult("Python checks", "PASS"),
        ci_local_module.CheckResult("Docker/Compose checks", "SKIPPED"),
        ci_local_module.CheckResult("Example failed check", "FAIL"),
    ]

    ci_local_module.print_summary(results)

    output = capsys.readouterr().out
    assert "PASS: Python checks" in output
    assert "SKIPPED: Docker/Compose checks" in output
    assert "FAIL: Example failed check" in output
    assert "OVERALL: FAIL" in output


def test_optional_static_analysis_reports_missing_tools_and_required_workflows(
    ci_local_module, monkeypatch
):
    monkeypatch.setattr(
        ci_local_module,
        "discover_lint_targets",
        lambda kind: ["script.sh"] if kind == "shell" else ["Dockerfile"],
    )
    monkeypatch.setattr(ci_local_module.shutil, "which", lambda _tool: None)
    results = []

    assert ci_local_module.run_optional_static_analysis(results) is True
    assert [(result.name, result.status) for result in results] == [
        ("ShellCheck repository shell scripts", "SKIPPED"),
        ("Hadolint repository Dockerfiles", "SKIPPED"),
        ("Semgrep high-severity SAST", "SKIPPED"),
    ]
    assert ".github/workflows/shellcheck.yml" in results[0].detail
    assert ".github/workflows/hadolint.yml" in results[1].detail
    assert ".github/workflows/semgrep.yml" in results[2].detail


def test_optional_static_analysis_uses_discovered_targets_and_shared_policy(
    ci_local_module, monkeypatch
):
    monkeypatch.setattr(
        ci_local_module,
        "discover_lint_targets",
        lambda kind: (
            ["scripts/ci-local", "ops/backups/sitbank-backup-encrypted"]
            if kind == "shell"
            else ["Dockerfile", "ops/container/Dockerfile.scan"]
        ),
    )
    monkeypatch.setattr(
        ci_local_module.shutil,
        "which",
        lambda tool: f"/tools/{tool}",
    )
    commands = []

    def fake_run(name, command, results):
        commands.append((name, command))
        ci_local_module.record_result(results, name, "PASS")

    monkeypatch.setattr(ci_local_module, "run", fake_run)
    results = []

    assert ci_local_module.run_optional_static_analysis(results) is True
    shellcheck = commands[0][1]
    hadolint = commands[1][1]
    semgrep = commands[2][1]
    assert shellcheck == [
        "/tools/shellcheck",
        "--severity=style",
        "scripts/ci-local",
        "ops/backups/sitbank-backup-encrypted",
    ]
    assert hadolint == [
        "/tools/hadolint",
        "--failure-threshold",
        "style",
        "Dockerfile",
        "ops/container/Dockerfile.scan",
    ]
    for config in ci_local_module.SEMGREP_CONFIGS:
        config_index = semgrep.index(config)
        assert semgrep[config_index - 1] == "--config"
    assert "--severity" in semgrep
    assert "ERROR" in semgrep
    assert "--error" in semgrep
    assert semgrep[-1] == "."


def test_ci_local_docs_explain_partial_and_strict_docker_validation():
    contributing = Path("docs/CONTRIBUTING.md").read_text(encoding="utf-8")
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")

    for text in (contributing, deployment):
        normalized = " ".join(text.split())
        assert "scripts/ci-local --require-docker" in normalized
        assert "CI_LOCAL_REQUIRE_DOCKER=1" in normalized
        assert "partial" in normalized.lower()
        assert "CI/CD remains the source of truth" in normalized
