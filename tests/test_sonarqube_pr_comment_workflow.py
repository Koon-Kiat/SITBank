from __future__ import annotations

import re
from pathlib import Path

import yaml


WORKFLOW_PATH = Path(".github/workflows/sonarqube.yml")
CI_WORKFLOW_PATH = Path(".github/workflows/ci-deploy.yml")


def _workflow() -> tuple[str, dict]:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    return text, yaml.load(text, Loader=yaml.BaseLoader)


def _ci_workflow() -> tuple[str, dict]:
    text = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
    return text, yaml.load(text, Loader=yaml.BaseLoader)


def _comment_step(ci: dict) -> dict:
    return next(
        step
        for step in ci["jobs"]["sonarqube-comment"]["steps"]
        if step.get("name") == "Comment SonarQube summary on PR"
    )


def test_sonarqube_workflow_uses_safe_pr_trigger_and_least_privilege():
    text, workflow = _workflow()
    ci_text, ci = _ci_workflow()

    assert WORKFLOW_PATH.is_file()
    assert set(workflow["on"]) == {"workflow_call"}
    assert "pull_request" in ci["on"]
    assert "pull_request_target" not in ci["on"]
    assert "pull_request_target" not in workflow["on"]
    assert "pull_request_target" not in text
    assert "pull_request_target" not in ci_text
    assert "permissions: write-all" not in text
    assert "permissions: write-all" not in ci_text
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["analyze"]["permissions"] == {"contents": "read"}
    assert ci["jobs"]["sonarqube"]["permissions"] == {"contents": "read"}
    assert ci["jobs"]["sonarqube-comment"]["permissions"] == {
        "contents": "read",
        "pull-requests": "write",
    }
    assert {
        permission
        for permission, level in ci["jobs"]["sonarqube-comment"]["permissions"].items()
        if level == "write"
    } == {"pull-requests"}
    assert "issues: write" not in ci_text
    assert "issues: write" not in text


def test_pr_comment_step_is_pinned_sticky_and_updates_in_place():
    _, ci = _ci_workflow()
    step = _comment_step(ci)
    script = step["with"]["script"]

    assert (
        step["uses"]
        == "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3"
    )
    assert re.fullmatch(r"actions/github-script@[0-9a-f]{40}", step["uses"])
    assert "<!-- sitbank-sonarqube-summary -->" in script
    assert "github.paginate(github.rest.issues.listComments" in script
    assert "github-actions[bot]" in script
    assert "github.rest.issues.updateComment" in script
    assert "github.rest.issues.createComment" in script
    assert script.index("updateComment") < script.index("createComment")


def test_pr_comment_is_limited_to_trusted_internal_non_dependabot_prs():
    _, ci = _ci_workflow()
    condition = ci["jobs"]["sonarqube-comment"]["if"]

    assert "needs.sonarqube.result == 'success'" in condition
    assert "github.event_name == 'pull_request'" in condition
    assert (
        "github.event.pull_request.head.repo.full_name == github.repository"
        in condition
    )
    assert "github.actor != 'dependabot[bot]'" in condition


def test_untrusted_prs_skip_cloud_scan_and_comment_with_notice():
    _, workflow = _workflow()
    credential_step = next(
        step
        for step in workflow["jobs"]["analyze"]["steps"]
        if step.get("name") == "Check SonarQube Cloud credentials"
    )
    script = credential_step["run"]

    assert "should_scan=false" in script
    assert "SonarQube Cloud skipped" in script
    assert "Cloud scan and PR comment are skipped" in script
    assert "fork or Dependabot PRs" in script
    assert "repository secrets/write permissions are not available" in script


def test_comment_body_describes_blocking_gate_and_constructs_safe_links():
    _, ci = _ci_workflow()
    script = _comment_step(ci)["with"]["script"]
    normalized = " ".join(script.split())

    for required in (
        "## SonarQube Cloud Analysis",
        "Workflow run",
        "Quality gate: enforced",
        "must pass for trusted pull requests and release-producing runs",
        "blocking quality gate for trusted runs",
        "does not replace pytest",
        "CodeQL",
        "Semgrep",
        "Bandit",
        "dependency auditing",
        "production guard tests",
    ):
        assert required in normalized

    assert "sonar.organization" in script
    assert "sonar.projectKey" in script
    assert "try {" in script
    assert "} catch {" in script
    assert "project properties could not be read" in script
    assert "https://sonarcloud.io/project/overview" in script
    assert "dashboardUrl.searchParams.set('id', projectKey)" in script
    assert "Full findings: check the SonarQube Cloud dashboard" in script
    assert "reporting-only" not in normalized
    assert "not currently blocking" not in normalized


def test_comment_does_not_expose_secrets_or_add_inline_review_comments():
    text, workflow = _workflow()
    ci_text, ci = _ci_workflow()
    script = _comment_step(ci)["with"]["script"]
    lowered_script = script.lower()
    lowered_workflows = f"{text}\n{ci_text}".lower()

    assert "SONAR_TOKEN" not in script
    assert "secrets." not in lowered_script
    assert "printenv" not in lowered_script
    assert "process.env" not in lowered_script
    assert "pulls.createreviewcomment" not in lowered_workflows
    assert "createReviewComment" not in f"{text}\n{ci_text}"
