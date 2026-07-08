from __future__ import annotations

import re
from pathlib import Path

import yaml


WORKFLOW_PATH = Path(".github/workflows/scorecard.yml")
WORKFLOW_DIR = Path(".github/workflows")


def _load(path: Path) -> tuple[str, dict]:
    text = path.read_text(encoding="utf-8")
    return text, yaml.load(text, Loader=yaml.BaseLoader)


def test_scorecard_workflow_is_informational_automatic_and_pinned():
    text, workflow = _load(WORKFLOW_PATH)

    assert workflow["name"] == "OpenSSF Scorecard"
    assert workflow["on"]["push"]["branches"] == ["main"]
    assert workflow["on"]["schedule"] == [{"cron": "17 4 * * 1"}]
    assert workflow["on"]["workflow_dispatch"] == ""
    assert "pull_request" not in workflow["on"]
    assert "pull_request_target" not in text
    assert workflow["permissions"] == {"contents": "read"}

    job = workflow["jobs"]["scorecard"]
    assert job["name"] == "Collect informational Scorecard evidence"
    uses = [step["uses"] for step in job["steps"] if "uses" in step]
    assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", use) for use in uses)
    action = job["steps"][0]
    assert action["uses"].startswith("ossf/scorecard-action@")
    assert action["with"]["publish_results"] == "false"
    assert action["with"]["repo_token"] == "${{ secrets.GITHUB_TOKEN }}"
    assert "security-events: write" not in text
    assert "id-token: write" not in text


def test_scorecard_evidence_has_bounded_non_mutating_artifact_upload():
    text, workflow = _load(WORKFLOW_PATH)
    upload = next(
        step
        for step in workflow["jobs"]["scorecard"]["steps"]
        if step["name"] == "Upload informational Scorecard evidence"
    )

    assert upload["with"] == {
        "name": "openssf-scorecard-results",
        "path": "scorecard-results.sarif",
        "if-no-files-found": "error",
        "retention-days": "30",
    }
    assert upload["if"] == "${{ always() }}"
    lowered = text.casefold()
    for forbidden in (
        "tailscale",
        "cloudflare",
        "docker push",
        "database-cutover",
        "bootstrap-container",
        "deploy-production",
        "deploy-staging",
        "issues: write",
        "contents: write",
        "packages: write",
    ):
        assert forbidden not in lowered


def test_workflow_write_permissions_are_narrow_and_reviewed():
    allowed_write_permissions = {
        ("bootstrap-ec2.yml", "bootstrap-staging", "id-token"),
        ("bootstrap-ec2.yml", "bootstrap-production", "id-token"),
        ("bootstrap-observability-ec2.yml", "bootstrap", "id-token"),
        ("ci-deploy.yml", "sonarqube-comment", "pull-requests"),
        ("ci-deploy.yml", "publish", "artifact-metadata"),
        ("ci-deploy.yml", "publish", "attestations"),
        ("ci-deploy.yml", "publish", "id-token"),
        ("ci-deploy.yml", "publish", "packages"),
        ("ci-deploy.yml", "release-verify", "id-token"),
        ("ci-deploy.yml", "release-verify", "packages"),
        ("ci-deploy.yml", "deploy-staging", "id-token"),
        ("ci-deploy.yml", "deploy-production", "id-token"),
        ("codeql.yml", "analyze-python", "security-events"),
        ("issue-labeler.yml", "label", "issues"),
        ("pr-labeler.yml", "label", "pull-requests"),
        ("pr-labeler.yml", "label", "issues"),
        ("retag-labels.yml", "retag", "issues"),
        ("retag-labels.yml", "retag", "pull-requests"),
    }
    observed_write_permissions: set[tuple[str, str, str]] = set()

    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        _, workflow = _load(path)
        top_permissions = workflow.get("permissions") or {}
        assert "write-all" not in top_permissions
        assert all(value != "write" for value in top_permissions.values()), path
        for job_name, job in (workflow.get("jobs") or {}).items():
            for permission, value in (job.get("permissions") or {}).items():
                if value == "write":
                    observed_write_permissions.add(
                        (path.name, job_name, permission)
                    )

    assert observed_write_permissions == allowed_write_permissions


def test_scorecard_supply_chain_evidence_is_categorized_without_overclaiming():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "docs/GITHUB_ACTIONS.md",
            "docs/security/assurance/test-automation-and-dependencies.md",
            "docs/security/governance/github-branch-protection-evidence.md",
        )
    )

    for required in (
        "Token-Permissions",
        "Branch-Protection",
        "SAST",
        "Packaging",
        "Signed-Releases",
        "CII-Best-Practices",
        "Fuzzing",
        "provider-state-only",
        "false positive",
        "accepted backlog",
        "GHCR",
        "Cosign",
        "SonarQube Cloud",
        "informational",
        "not a required pull-request check",
    ):
        assert required in docs
