from __future__ import annotations

import re
from pathlib import Path

import yaml


WORKFLOW_PATH = Path(".github/workflows/sonarqube.yml")
CI_WORKFLOW_PATH = Path(".github/workflows/ci-deploy.yml")
PROPERTIES_PATH = Path("sonar-project.properties")
SONAR_DOC_PATH = Path("docs/security/sonarqube.md")


def _workflow() -> tuple[str, dict]:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    data = yaml.load(text, Loader=yaml.BaseLoader)
    return text, data


def _ci_workflow() -> tuple[str, dict]:
    text = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
    data = yaml.load(text, Loader=yaml.BaseLoader)
    return text, data


def _properties() -> dict[str, str]:
    result = {}
    for line in PROPERTIES_PATH.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result[key] = value
    return result


def test_sonarqube_workflow_is_reusable_and_has_least_privilege():
    text, workflow = _workflow()
    ci_text, ci = _ci_workflow()

    assert set(workflow["on"]) == {"workflow_call"}
    workflow_call = workflow["on"]["workflow_call"]
    assert set(workflow_call["inputs"]) == {"coverage_artifact", "source_sha"}
    assert all(
        config["required"] == "true"
        for config in workflow_call["inputs"].values()
    )
    assert workflow_call["secrets"]["SONAR_TOKEN"]["required"] == "false"
    assert "pull_request" in ci["on"]
    assert "pull_request_target" not in ci["on"]
    assert "pull_request_target" not in ci_text
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["analyze"]["permissions"] == {"contents": "read"}
    assert ci["jobs"]["sonarqube"]["permissions"] == {"contents": "read"}
    assert ci["jobs"]["sonarqube-comment"]["permissions"] == {
        "contents": "read",
        "pull-requests": "write",
    }
    assert "actions/github-script@" not in text
    assert (
        "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3"
        in ci_text
    )
    assert "60a0d83039c74a4aee543508d2ffcb1c3799cdea" not in ci_text
    assert "environment:" not in text


def test_ci_runs_pytest_once_and_hands_coverage_to_sonarqube():
    ci_text, ci = _ci_workflow()
    text, workflow = _workflow()
    test_steps = ci["jobs"]["test"]["steps"]
    steps = workflow["jobs"]["analyze"]["steps"]
    uses = [step["uses"] for step in steps if "uses" in step]

    assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action) for action in uses)
    assert any(
        action.startswith("SonarSource/sonarqube-scan-action@") for action in uses
    )
    checkout = next(
        step for step in steps if step.get("name") == "Check out analyzed source"
    )
    assert checkout["with"]["fetch-depth"] == "0"
    assert checkout["with"]["persist-credentials"] == "false"
    assert checkout["with"]["ref"] == "${{ inputs.source_sha }}"

    test_command = next(
        step for step in test_steps if step.get("name") == "Run tests and security checks"
    )["run"]
    assert ci_text.count("python -m pytest") == 1
    assert "python -m pytest -q -n auto" in test_command
    assert "--cov-report=xml:coverage.xml" in test_command
    assert "--cov=." in test_command
    assert "--cov-config=.coveragerc" in test_command
    assert "node tests/js/collect-browser-coverage.mjs" in test_command

    upload = next(
        step
        for step in test_steps
        if step.get("name") == "Upload SonarQube coverage report"
    )
    assert (
        upload["uses"]
        == "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f"
    )
    assert upload["with"] == {
        "name": "sonarqube-coverage-${{ github.run_id }}",
        "path": "coverage.xml\ncoverage/lcov.info\n",
        "if-no-files-found": "error",
        "retention-days": "1",
    }

    sonar_call = ci["jobs"]["sonarqube"]
    assert "test" in sonar_call["needs"]
    assert sonar_call["uses"] == "./.github/workflows/sonarqube.yml"
    assert sonar_call["with"] == {
        "coverage_artifact": "sonarqube-coverage-${{ github.run_id }}",
        "source_sha": "${{ needs.resolve-source.outputs.source_sha }}",
    }

    download = next(
        step
        for step in steps
        if step.get("name") == "Download SonarQube coverage report"
    )
    assert (
        download["uses"]
        == "actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53"
    )
    assert download["with"] == {
        "name": "${{ inputs.coverage_artifact }}",
        "path": ".",
    }
    assert "python -m pytest" not in text
    assert "actions/setup-python@" not in text
    assert "pip install" not in text
    assert "continue-on-error" not in ci_text


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
    assert "fork or Dependabot PRs" in credential_step["run"]
    assert "PR comment are skipped" in credential_step["run"]
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
    assert properties["sonar.javascript.lcov.reportPaths"] == "coverage/lcov.info"
    assert properties["sonar.qualitygate.wait"] == "false"
    assert "**/.env" in properties["sonar.exclusions"]
    assert "**/*.dump" in properties["sonar.exclusions"]
    assert properties["sonar.test.exclusions"] == "tests/fixtures/**"
    assert ".coverage" in gitignore
    assert "coverage.xml" in gitignore
    assert "coverage/" in gitignore
    coverage_config = Path(".coveragerc").read_text(encoding="utf-8")
    assert "source = ." in coverage_config
    assert "tests/*" in coverage_config


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
    assert "specific version tag" in normalized
    assert "immutable digest" in normalized
    assert "visible to Dependabot" in normalized


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
