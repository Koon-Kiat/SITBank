from __future__ import annotations

import re
from pathlib import Path

import yaml


WORKFLOW_PATH = Path(".github/workflows/sonarqube.yml")
PROPERTIES_PATH = Path("sonar-project.properties")
SONAR_DOC_PATH = Path("docs/security/sonarqube.md")


def _workflow() -> tuple[str, dict]:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    data = yaml.load(text, Loader=yaml.BaseLoader)
    return text, data


def _properties() -> dict[str, str]:
    result = {}
    for line in PROPERTIES_PATH.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result[key] = value
    return result


def test_sonarqube_workflow_has_required_triggers_and_least_privilege():
    text, workflow = _workflow()

    assert set(workflow["on"]) == {"pull_request", "push", "workflow_dispatch"}
    assert workflow["on"]["pull_request"]["branches"] == ["main"]
    assert workflow["on"]["pull_request"]["types"] == [
        "opened",
        "synchronize",
        "reopened",
    ]
    assert workflow["on"]["push"]["branches"] == ["main"]
    assert workflow["permissions"] == {"contents": "read"}
    assert "environment:" not in text


def test_sonarqube_workflow_is_pinned_and_generates_full_suite_coverage():
    text, workflow = _workflow()
    steps = workflow["jobs"]["analyze"]["steps"]
    uses = [step["uses"] for step in steps if "uses" in step]

    assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action) for action in uses)
    assert any(
        action.startswith("SonarSource/sonarqube-scan-action@") for action in uses
    )
    checkout = next(step for step in steps if step.get("name") == "Check out repository")
    assert checkout["with"]["fetch-depth"] == "0"
    assert checkout["with"]["persist-credentials"] == "false"

    coverage = next(
        step for step in steps if step.get("name") == "Run full tests with coverage"
    )["run"]
    assert "python -m pytest -q -n auto" in coverage
    assert "--cov=app" in coverage
    assert "--cov-report=xml:coverage.xml" in coverage
    assert "tests/" not in coverage
    assert "continue-on-error" not in text


def test_sonarqube_workflow_handles_token_without_deployment_secrets():
    text, workflow = _workflow()
    lowered = text.lower()
    credential_step = next(
        step
        for step in workflow["jobs"]["analyze"]["steps"]
        if step.get("name") == "Check SonarQube Cloud credentials"
    )

    assert "SONAR_TOKEN" in credential_step["env"]
    assert "is not configured" in credential_step["run"]
    assert "untrusted fork or Dependabot pull request" in credential_step["run"]
    assert "dependabot[bot]" in text
    assert "echo \"${SONAR_TOKEN}\"" not in text
    assert "printenv" not in lowered
    assert "env |" not in lowered
    for forbidden in (
        "ec2_host",
        "ssh_private",
        "aws_access",
        "bootstrap-container-ec2",
        "sitbank-container-deploy",
        "docker compose",
        "production-check",
    ):
        assert forbidden not in lowered


def test_sonarqube_properties_define_scope_coverage_and_reporting_policy():
    properties = _properties()
    gitignore = Path(".gitignore").read_text(encoding="utf-8").splitlines()

    assert properties["sonar.projectKey"] == "WenJiangg_SITBank"
    assert properties["sonar.organization"] == "wenjiangg"
    assert properties["sonar.sources"].split(",") == [
        "app",
        "ops",
        "config.py",
        "wsgi.py",
        "admin_wsgi.py",
    ]
    assert properties["sonar.tests"] == "tests"
    assert properties["sonar.python.coverage.reportPaths"] == "coverage.xml"
    assert properties["sonar.qualitygate.wait"] == "false"
    assert "**/.env" in properties["sonar.exclusions"]
    assert "**/*.dump" in properties["sonar.exclusions"]
    assert properties["sonar.test.exclusions"] == "tests/fixtures/**"
    assert ".coverage" in gitignore
    assert "coverage.xml" in gitignore


def test_sonarqube_docs_record_cloud_private_repo_and_nonblocking_policy():
    text = SONAR_DOC_PATH.read_text(encoding="utf-8")
    normalized = " ".join(text.split())

    for required in (
        "SonarQube Cloud",
        "50,000",
        "private",
        "SONAR_TOKEN",
        "source code is sent",
        "reporting-only",
        "does not replace",
        "CodeQL",
        "Semgrep",
        "false positive",
        "coverage.xml",
        "WenJiangg_SITBank",
        "wenjiangg",
    ):
        assert required in normalized
    assert "SONAR_HOST_URL" in normalized
    assert "sonar.qualitygate.wait=false" in normalized


def test_active_docs_do_not_claim_sonarqube_is_missing():
    active_docs = [Path("README.md"), Path("SECURITY.md")] + list(
        Path("docs").rglob("*.md")
    )
    combined = " ".join(
        " ".join(path.read_text(encoding="utf-8").lower().split())
        for path in active_docs
    )
    stale_phrases = (
        "sonarqube is not active",
        "sonarqube is missing",
        "no sonarqube",
        "maintainability dashboard is missing",
        "code-quality dashboard is missing",
    )

    for phrase in stale_phrases:
        assert phrase not in combined


def test_code_quality_label_is_managed_by_all_labelers():
    labeler = yaml.safe_load(Path(".github/labeler.yml").read_text(encoding="utf-8"))
    workflows = [
        Path(path).read_text(encoding="utf-8")
        for path in (
            ".github/workflows/issue-labeler.yml",
            ".github/workflows/pr-labeler.yml",
            ".github/workflows/retag-labels.yml",
        )
    ]

    assert "code-quality" in labeler
    labeler_text = str(labeler["code-quality"])
    assert ".github/workflows/sonarqube.yml" in labeler_text
    assert "sonar-project.properties" in labeler_text
    for workflow in workflows:
        assert (
            'create_label code-quality "Static analysis, maintainability, coverage, '
            'or quality-gate work"'
        ) in workflow
        for term in (
            "sonarqube",
            "quality gate",
            "code quality",
            "maintainability",
            "coverage",
            "duplication",
            "technical debt",
        ):
            assert term in workflow
