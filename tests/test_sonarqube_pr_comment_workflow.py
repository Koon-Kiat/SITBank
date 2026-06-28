from __future__ import annotations

import re
from pathlib import Path

import yaml


WORKFLOW_PATH = Path(".github/workflows/sonarqube.yml")


def _workflow() -> tuple[str, dict]:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    return text, yaml.load(text, Loader=yaml.BaseLoader)


def _comment_step(workflow: dict) -> dict:
    return next(
        step
        for step in workflow["jobs"]["analyze"]["steps"]
        if step.get("name") == "Comment SonarQube summary on PR"
    )


def test_sonarqube_workflow_uses_safe_pr_trigger_and_least_privilege():
    text, workflow = _workflow()

    assert WORKFLOW_PATH.is_file()
    assert "pull_request" in workflow["on"]
    assert "pull_request_target" not in workflow["on"]
    assert "pull_request_target" not in text
    assert "permissions: write-all" not in text
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["analyze"]["permissions"] == {
        "contents": "read",
        "issues": "write",
        "pull-requests": "read",
    }
    assert {
        permission
        for permission, level in workflow["jobs"]["analyze"]["permissions"].items()
        if level == "write"
    } == {"issues"}


def test_pr_comment_step_is_pinned_sticky_and_updates_in_place():
    _, workflow = _workflow()
    step = _comment_step(workflow)
    script = step["with"]["script"]

    assert re.fullmatch(r"actions/github-script@[0-9a-f]{40}", step["uses"])
    assert "<!-- sitbank-sonarqube-summary -->" in script
    assert "github.paginate(github.rest.issues.listComments" in script
    assert "github-actions[bot]" in script
    assert "github.rest.issues.updateComment" in script
    assert "github.rest.issues.createComment" in script
    assert script.index("updateComment") < script.index("createComment")


def test_pr_comment_is_limited_to_trusted_internal_non_dependabot_prs():
    _, workflow = _workflow()
    condition = _comment_step(workflow)["if"]

    assert "steps.sonar.outputs.should_scan == 'true'" in condition
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


def test_comment_body_is_informational_and_constructs_safe_links():
    _, workflow = _workflow()
    script = _comment_step(workflow)["with"]["script"]
    normalized = " ".join(script.split())

    for required in (
        "## SonarQube Cloud Analysis",
        "Workflow run",
        "reporting-only",
        "quality gate is not currently blocking",
        "Full findings are available in SonarQube Cloud",
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


def test_comment_does_not_expose_secrets_or_add_inline_review_comments():
    text, workflow = _workflow()
    script = _comment_step(workflow)["with"]["script"]
    lowered_script = script.lower()
    lowered_workflow = text.lower()

    assert "SONAR_TOKEN" not in script
    assert "secrets." not in lowered_script
    assert "printenv" not in lowered_script
    assert "process.env" not in lowered_script
    assert "pulls.createreviewcomment" not in lowered_workflow
    assert "createReviewComment" not in text
