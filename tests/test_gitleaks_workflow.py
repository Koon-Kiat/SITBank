from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml


WORKFLOW_PATH = Path(".github/workflows/gitleaks.yml")
CONFIG_PATH = Path(".gitleaks.toml")
CI_WORKFLOW_PATH = Path(".github/workflows/ci-deploy.yml")
CUSTOM_SCANNER_PATH = Path("ops/security/scan_repository_secrets.py")
LOCAL_CI_PATH = Path("scripts/ci-local")


def _load_workflow() -> tuple[str, dict]:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    return text, yaml.load(text, Loader=yaml.BaseLoader)


def test_gitleaks_workflow_has_protected_branch_manual_and_scheduled_triggers():
    _, workflow = _load_workflow()
    triggers = workflow["on"]

    assert workflow["name"] == "Gitleaks"
    assert triggers["pull_request"]["branches"] == ["main"]
    assert triggers["push"]["branches"] == ["main"]
    assert triggers["workflow_dispatch"] == ""
    assert triggers["schedule"] == [{"cron": "37 2 * * 1"}]
    assert "pull_request_target" not in triggers
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["scan"]["runs-on"] == "ubuntu-24.04"
    assert workflow["jobs"]["scan"]["timeout-minutes"] == "15"


def test_gitleaks_uses_safe_full_history_checkout_and_verified_pinned_cli():
    text, workflow = _load_workflow()
    steps = workflow["jobs"]["scan"]["steps"]
    checkout = steps[0]
    install = steps[1]["run"]

    assert re.fullmatch(r"actions/checkout@[0-9a-f]{40}", checkout["uses"])
    assert checkout["with"] == {
        "fetch-depth": "0",
        "persist-credentials": "false",
    }
    assert 'readonly version="8.30.1"' in install
    assert re.search(r'readonly expected_sha256="[0-9a-f]{64}"', install)
    assert "releases/download/v${version}" in install
    assert "sha256sum --check --status" in install
    assert "curl --fail --location --silent --show-error" in install
    assert "gitleaks/gitleaks-action" not in text


def test_gitleaks_scans_all_history_with_redaction_and_no_unsafe_report():
    text, workflow = _load_workflow()
    scan = workflow["jobs"]["scan"]["steps"][2]["run"]
    lowered = text.casefold()

    for required in (
        "gitleaks-bin/gitleaks",
        "git",
        "--config .gitleaks.toml",
        "--log-opts=--all",
        "--redact",
        "--no-banner",
        "--no-color",
    ):
        assert required in scan
    for forbidden in (
        "upload-artifact",
        "security-events: write",
        "printenv",
        "env |",
        "set -x",
        "pull_request_target",
        "tailscale",
        "cloudflare",
        "docker compose",
        "bootstrap",
        "deploy",
        "sarif",
    ):
        assert forbidden not in lowered
    assert "${{ secrets." not in text


def test_gitleaks_configuration_keeps_defaults_and_has_no_broad_allowlist():
    text = CONFIG_PATH.read_text(encoding="utf-8")
    config = tomllib.loads(text)
    lowered = text.casefold()

    assert config["title"] == "SITBank Gitleaks configuration"
    assert config["extend"] == {"useDefault": True}
    allowlists = config["allowlists"]
    assert len(allowlists) == 6
    assert {entry["description"] for entry in allowlists} == {
        "Public SHA-256 checksum pinned by the Tailscale installer",
        "Public SonarQube Cloud project key metadata",
        "Historical public SonarQube Cloud project key metadata",
        "Historical synthetic accepted-password test fixture",
        "Historical mappings from secret environment names to config field names",
        "Historical shell cases that reject private-key PEM headers",
    }
    for entry in allowlists:
        assert entry["condition"] == "AND"
        assert entry["targetRules"] in (["generic-api-key"], ["private-key"])
        assert entry["regexTarget"] in {"line", "match"}
        assert entry["paths"]
        assert entry["regexes"]
        assert all(path.startswith("^") and path.endswith("$") for path in entry["paths"])
    historical = [entry for entry in allowlists if entry["description"].startswith("Historical")]
    assert historical
    assert all(entry["commits"] for entry in historical)
    assert "baseline" in lowered
    assert "disabledRules" not in config["extend"]
    paths = [path for entry in allowlists for path in entry["paths"]]
    assert not set(paths) & {
        ".*",
        r"^ops/.*$",
        r"^scripts/.*$",
        r"^\.github/workflows/.*$",
        r"^config\.py$",
    }
    assert all(not path.endswith("/.*") for path in paths)
    sonar_project_key = next(
        entry
        for entry in allowlists
        if entry["description"] == "Public SonarQube Cloud project key metadata"
    )
    assert sonar_project_key == {
        "description": "Public SonarQube Cloud project key metadata",
        "condition": "AND",
        "targetRules": ["generic-api-key"],
        "regexTarget": "line",
        "paths": [r"^sonar-project\.properties$"],
        "regexes": [r"^sonar\.projectKey=WenJiangg_SITBank$"],
    }
    historical_sonar_project_key = next(
        entry
        for entry in allowlists
        if entry["description"]
        == "Historical public SonarQube Cloud project key metadata"
    )
    assert historical_sonar_project_key == {
        "description": "Historical public SonarQube Cloud project key metadata",
        "condition": "AND",
        "targetRules": ["generic-api-key"],
        "regexTarget": "line",
        "commits": ["f29d15f476d975d4b8e3c9e1b529a855a12776db"],
        "paths": [r"^sonar-project\.properties$"],
        "regexes": [r"^sonar\.projectKey=TL0024_SITBank$"],
    }


def test_custom_repository_scanner_remains_in_ci_and_local_ci():
    assert CUSTOM_SCANNER_PATH.is_file()
    assert Path("tests/test_secret_scanner.py").is_file()
    ci = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
    local_ci = LOCAL_CI_PATH.read_text(encoding="utf-8")

    assert "python ops/security/scan_repository_secrets.py --history" in ci
    assert '"ops/security/scan_repository_secrets.py"' in local_ci
    assert '"--history"' in local_ci


def test_gitleaks_triage_and_control_boundaries_are_documented():
    docs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            Path("SECURITY.md"),
            Path("docs/CONTRIBUTING.md"),
            Path("docs/GITHUB_ACTIONS.md"),
            Path("docs/security/assurance/secure-coding.md"),
            Path("docs/security/assurance/test-automation-and-dependencies.md"),
            Path("docs/security/assurance/sonarqube.md"),
            Path("docs/security/governance/framework-control-matrix.md"),
            Path("docs/security/governance/security-gap-register.md"),
            Path("docs/security/architecture/threat-model.md"),
        )
    )

    for required in (
        ".github/workflows/gitleaks.yml",
        ".gitleaks.toml",
        "Gitleaks 8.30.1",
        "custom repository secret scanner",
        "full Git history",
        "narrow allowlist",
        "rotate",
        "revoke",
        "false positive",
        "redacted",
        "no SARIF",
        "production secrets",
    ):
        assert required in docs
    assert "Gitleaks is missing" not in docs
