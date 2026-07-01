from __future__ import annotations

import re
from pathlib import Path

import yaml


WORKFLOW_DIR = Path(".github/workflows")
DISCOVERY_HELPER = Path("ops/security/discover_lint_targets.py")


def _load(name: str) -> tuple[str, dict]:
    path = WORKFLOW_DIR / name
    text = path.read_text(encoding="utf-8")
    return text, yaml.load(text, Loader=yaml.BaseLoader)


def _assert_standard_triggers_permissions_and_checkout(workflow: dict) -> None:
    triggers = workflow["on"]
    assert triggers["pull_request"]["branches"] == ["main"]
    assert triggers["push"]["branches"] == ["main"]
    assert triggers["workflow_dispatch"] == ""
    assert "pull_request_target" not in triggers
    assert workflow["permissions"] == {"contents": "read"}

    checkout = workflow["jobs"]["scan"]["steps"][0]
    assert re.fullmatch(r"actions/checkout@[0-9a-f]{40}", checkout["uses"])
    assert checkout["with"]["persist-credentials"] == "false"


def _assert_no_secret_or_mutating_boundary(text: str) -> None:
    lowered = text.casefold()
    for forbidden in (
        "${{ secrets.",
        "printenv",
        "env |",
        "set -x",
        "pull_request_target",
        "docker push",
        "tailscale up",
        "tailscale serve",
        "cloudflare",
        "database-cutover",
        "bootstrap-container",
        "security-events: write",
        "upload-artifact",
        "|| true",
    ):
        assert forbidden not in lowered


def test_shellcheck_workflow_discovers_and_scans_all_tracked_shell_scripts():
    text, workflow = _load("shellcheck.yml")

    assert workflow["name"] == "ShellCheck"
    _assert_standard_triggers_permissions_and_checkout(workflow)
    _assert_no_secret_or_mutating_boundary(text)
    steps = workflow["jobs"]["scan"]["steps"]
    discovery = steps[1]["run"]
    install = steps[2]["run"]
    scan = steps[3]["run"]

    assert "discover_lint_targets.py shell --format nul" in discovery
    assert 'test -s "${RUNNER_TEMP}/shellcheck-targets"' in discovery
    assert 'readonly version="0.11.0"' in install
    assert re.search(r'readonly expected_sha256="[0-9a-f]{64}"', install)
    assert "sha256sum --check --status" in install
    assert "shellcheck-v${version}.linux.x86_64.tar.xz" in install
    assert "xargs --null --no-run-if-empty" in scan
    assert "--severity=style" in scan
    assert "ops/deploy/" not in scan
    assert "scripts/ci-local" not in scan


def test_hadolint_workflow_discovers_and_scans_all_tracked_dockerfiles():
    text, workflow = _load("hadolint.yml")

    assert workflow["name"] == "Hadolint"
    _assert_standard_triggers_permissions_and_checkout(workflow)
    _assert_no_secret_or_mutating_boundary(text)
    steps = workflow["jobs"]["scan"]["steps"]
    discovery = steps[1]["run"]
    install = steps[2]["run"]
    scan = steps[3]["run"]

    assert "discover_lint_targets.py dockerfile --format nul" in discovery
    assert 'test -s "${RUNNER_TEMP}/hadolint-targets"' in discovery
    assert 'readonly version="2.14.0"' in install
    assert re.search(r'readonly expected_sha256="[0-9a-f]{64}"', install)
    assert "sha256sum --check --status" in install
    assert "hadolint-linux-x86_64" in install
    assert "xargs --null --no-run-if-empty" in scan
    assert "--failure-threshold style" in scan
    assert "Dockerfile" not in scan


def test_semgrep_workflow_is_automatic_scheduled_local_oss_and_blocking():
    text, workflow = _load("semgrep.yml")

    assert workflow["name"] == "Semgrep"
    _assert_standard_triggers_permissions_and_checkout(workflow)
    _assert_no_secret_or_mutating_boundary(text)
    assert workflow["on"]["schedule"] == [{"cron": "43 3 * * 1"}]
    scan_job = workflow["jobs"]["scan"]
    assert re.fullmatch(
        r"semgrep/semgrep:1\.168\.0@sha256:[0-9a-f]{64}",
        scan_job["env"]["SEMGREP_IMAGE"],
    )

    command = scan_job["steps"][1]["run"]
    assert "semgrep/semgrep-action" not in text
    assert "semgrep scan" in command
    assert "--metrics=off" in command
    for config in (
        "p/python",
        "p/flask",
        "p/security-audit",
        "p/owasp-top-ten",
        "p/github-actions",
    ):
        assert f"--config {config}" in command
    assert "--severity ERROR" in command
    assert "--error" in command
    assert "${GITHUB_WORKSPACE}:/src:ro" in command
    for excluded in (
        ".venv",
        "venv",
        ".pytest_cache",
        ".pytest-tmp",
        "coverage",
        "htmlcov",
        "node_modules",
        "dist",
        "build",
    ):
        assert f"--exclude {excluded}" in command
    for required_scope in ("app", "ops", "scripts", "tests", ".github"):
        assert f"--exclude {required_scope}" not in command
    assert "SEMGREP_APP_TOKEN" not in text
    assert "SEMGREP_APP_TOKEN" not in scan_job.get("env", {})
    assert "sarif" not in text.casefold()

    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "SECURITY.md",
            "docs/GITHUB_ACTIONS.md",
            "docs/CONTRIBUTING.md",
            "docs/security/assurance/test-automation-and-dependencies.md",
        )
    )
    assert docs.count("--metrics=off") >= 4
    assert "local/OSS" in docs
    assert "uploads no source or SARIF" in docs


def test_discovery_helper_is_shared_by_ci_and_local_validation():
    helper = DISCOVERY_HELPER.read_text(encoding="utf-8")
    local_ci = Path("scripts/ci-local").read_text(encoding="utf-8")

    assert "git\", \"ls-files\", \"-z" in helper
    assert "relative.suffix.casefold() == \".sh\"" in helper
    assert "SHELL_SHEBANG" in helper
    assert 'relative.name == "Dockerfile"' in helper
    assert 'relative.name.startswith("Dockerfile.")' in helper
    assert "refusing a silent pass" in helper
    assert "ops/security/discover_lint_targets.py" in local_ci
    for tool, workflow in (
        ("shellcheck", ".github/workflows/shellcheck.yml"),
        ("hadolint", ".github/workflows/hadolint.yml"),
        ("semgrep", ".github/workflows/semgrep.yml"),
    ):
        assert f'"{tool}"' in local_ci
        assert workflow in local_ci


def test_static_analysis_controls_are_documented_as_implemented():
    docs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            Path("docs/CONTRIBUTING.md"),
            Path("docs/GITHUB_ACTIONS.md"),
            Path("docs/OPERATIONS.md"),
            Path("docs/security/assurance/secure-coding.md"),
            Path("docs/security/assurance/test-automation-and-dependencies.md"),
            Path("docs/security/governance/framework-control-matrix.md"),
            Path("docs/security/governance/security-gap-register.md"),
            Path("docs/security/architecture/threat-model.md"),
        )
    )

    for required in (
        ".github/workflows/shellcheck.yml",
        ".github/workflows/hadolint.yml",
        ".github/workflows/semgrep.yml",
        "ShellCheck 0.11.0",
        "Hadolint 2.14.0",
        "Semgrep 1.168.0",
        "tracked-file discovery",
        "Bash syntax",
        "local/OSS",
        "ERROR severity",
        "no production secrets",
        "branch protection",
    ):
        assert required in docs
    for stale in (
        "ShellCheck is missing",
        "Hadolint is missing",
        "Semgrep is missing",
        "Semgrep is manual-only",
    ):
        assert stale not in docs
