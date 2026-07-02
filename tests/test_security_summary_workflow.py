from __future__ import annotations

from pathlib import Path

import yaml


WORKFLOW_PATH = Path(".github/workflows/security-summary.yml")
SECURITY_WORKFLOWS = {
    "codeql.yml": ["analyze-python"],
    "commit-message-policy.yml": ["commit-message-policy"],
    "dast-pr-smoke.yml": ["smoke"],
    "gitleaks.yml": ["scan"],
    "hadolint.yml": ["scan"],
    "pr-labeler.yml": ["label"],
    "pr-title-policy.yml": ["pr-title-policy"],
    "sbom.yml": ["source-sbom"],
    "scorecard.yml": ["scorecard"],
    "semgrep.yml": ["scan"],
    "shellcheck.yml": ["scan"],
}
PR_CHECK_NAMES = {
    "Python analysis",
    "Commit message",
    "Local ephemeral application",
    "Full-history secret scan",
    "Repository Dockerfiles",
    "Label pull request",
    "Pull request title",
    "Generate CycloneDX source SBOM",
    "High-severity SAST",
    "Repository shell scripts",
}
MAIN_CHECK_NAMES = {
    "Python analysis",
    "Full-history secret scan",
    "Repository Dockerfiles",
    "Generate CycloneDX source SBOM",
    "Collect informational Scorecard evidence",
    "High-severity SAST",
    "Repository shell scripts",
}


def _load(path: Path) -> tuple[str, dict]:
    text = path.read_text(encoding="utf-8")
    return text, yaml.load(text, Loader=yaml.BaseLoader)


def test_summary_workflow_is_independent_default_branch_evidence():
    text, workflow = _load(WORKFLOW_PATH)

    assert WORKFLOW_PATH.name != "ci-deploy.yml"
    assert workflow["name"] == "Non-deploy security summary"
    assert set(workflow["on"]) == {"pull_request", "push"}
    assert workflow["on"]["pull_request"]["branches"] == ["main"]
    assert workflow["on"]["push"]["branches"] == ["main"]
    assert workflow["permissions"] == {
        "checks": "read",
        "contents": "read",
    }
    assert "pull_request_target" not in text
    assert "workflow_dispatch" not in workflow["on"]
    assert "environment:" not in text
    assert "secrets." not in text
    assert "deploy" not in workflow["jobs"]


def test_rollup_represents_every_pr_and_main_security_check():
    text, workflow = _load(WORKFLOW_PATH)
    step = workflow["jobs"]["summarize"]["steps"][0]

    assert workflow["jobs"]["summarize"]["name"] == (
        "Consolidated non-deploy security"
    )
    assert step["uses"] == (
        "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3"
    )
    assert set(yaml.safe_load(step["env"]["PR_CHECKS"])) == PR_CHECK_NAMES
    assert set(yaml.safe_load(step["env"]["MAIN_CHECKS"])) == MAIN_CHECK_NAMES
    assert "GITHUB_STEP_SUMMARY" in step["with"]["script"]
    assert "Individual job summaries" in step["with"]["script"]
    assert "CI, publish, and deploy" in step["with"]["script"]
    assert ".github/workflows/ci-deploy.yml" in step["with"]["script"]
    assert "not in scope" in step["with"]["script"]
    assert "pull request rollup" in step["with"]["script"]
    assert "default-branch rollup" in step["with"]["script"]


def test_rollup_distinguishes_all_required_states_and_fails_unknown():
    script = _load(WORKFLOW_PATH)[1]["jobs"]["summarize"]["steps"][0]["with"][
        "script"
    ]

    for status in (
        "passed",
        "failed",
        "skipped",
        "expected-skipped",
        "pending",
        "unknown",
    ):
        assert f'"{status}"' in script
    assert "core.setFailed" in script
    assert "run.status !== \"completed\"" in script
    assert "const terminalFailure" in script
    assert "allTerminal || terminalFailure" in script
    assert "polling attempt" in script
    assert "read-only permissions" in script


def test_each_independent_security_job_writes_a_readable_summary():
    for filename, job_names in SECURITY_WORKFLOWS.items():
        path = Path(".github/workflows") / filename
        text, workflow = _load(path)
        assert filename != "ci-deploy.yml"
        for job_name in job_names:
            assert job_name in workflow["jobs"]
        assert "GITHUB_STEP_SUMMARY" in text, filename

    sbom = _load(Path(".github/workflows/sbom.yml"))[0]
    for required in (
        "sitbank-source-sbom",
        "CycloneDX JSON",
        "Components:",
        "Dependency entries:",
        "Services:",
    ):
        assert required in sbom

    for filename in ("hadolint.yml", "shellcheck.yml", "semgrep.yml"):
        text = _load(Path(".github/workflows") / filename)[0]
        assert "Findings" in text or "findings" in text
        assert "| Rule |" in text

    dast = _load(Path(".github/workflows/dast-pr-smoke.yml"))[0]
    assert "Blocking finding count" in dast
    assert "sanitized scope/outcome summary" in dast


def test_scanners_and_policy_jobs_remain_separate_and_named():
    observed_names = set()
    for filename, jobs in SECURITY_WORKFLOWS.items():
        _text, workflow = _load(Path(".github/workflows") / filename)
        assert len(workflow["jobs"]) == len(jobs)
        observed_names.update(job["name"] for job in workflow["jobs"].values())

    assert PR_CHECK_NAMES <= observed_names
    assert MAIN_CHECK_NAMES <= observed_names
