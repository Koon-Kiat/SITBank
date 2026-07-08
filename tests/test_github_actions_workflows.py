from __future__ import annotations

from pathlib import Path

import yaml


WORKFLOW_DIR = Path(".github/workflows")
CI_WORKFLOW_PATH = WORKFLOW_DIR / "ci-deploy.yml"


def _load_workflow(path: Path) -> dict:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _local_reusable_calls() -> list[tuple[str, dict, Path]]:
    workflow = _load_workflow(CI_WORKFLOW_PATH)
    calls = []
    for job_name, job in workflow["jobs"].items():
        uses = job.get("uses", "")
        if uses.startswith("./.github/workflows/"):
            calls.append((job_name, job, Path(uses.removeprefix("./"))))
    return calls


def test_ci_local_reusable_workflows_exist_and_accept_caller_inputs():
    calls = _local_reusable_calls()

    assert {job_name for job_name, _, _ in calls} == {
        "sonarqube",
        "verify-staging-tls",
        "verify-production-tls",
    }
    for job_name, caller, called_path in calls:
        assert called_path.is_file(), (job_name, called_path)
        called = _load_workflow(called_path)
        assert "workflow_call" in called["on"], (job_name, called_path)

        contract = called["on"]["workflow_call"] or {}
        required_inputs = {
            name
            for name, config in (contract.get("inputs") or {}).items()
            if config.get("required") == "true"
        }
        assert required_inputs <= set(caller.get("with") or {}), job_name

        required_secrets = {
            name
            for name, config in (contract.get("secrets") or {}).items()
            if config.get("required") == "true"
        }
        caller_secrets = caller.get("secrets") or {}
        if caller_secrets != "inherit":
            assert required_secrets <= set(caller_secrets), job_name


def test_workflow_yaml_parses_and_avoids_unsafe_triggers_and_permissions():
    workflow_paths = sorted(WORKFLOW_DIR.glob("*.yml"))

    assert workflow_paths
    for path in workflow_paths:
        text = path.read_text(encoding="utf-8")
        workflow = _load_workflow(path)
        assert isinstance(workflow, dict), path
        assert "pull_request_target" not in text, path
        assert "permissions: write-all" not in text, path


def test_ci_variables_have_explicit_safe_defaults():
    text = CI_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "vars.ENABLE_GITHUB_CODE_SECURITY" not in text
    assert "vars.STAGING_PUBLIC_HOST" not in text
    assert "vars.PROD_PUBLIC_HOST" not in text
    assert "(vars['ENABLE_GITHUB_CODE_SECURITY'] || 'false') == 'true'" in text
    assert (
        "vars['STAGING_PUBLIC_HOST'] || 'staging-sitbank.pp.ua'"
        in text
    )
    assert "vars['PROD_PUBLIC_HOST'] || 'sitbank.pp.ua'" in text


def test_dependency_review_is_reachable_for_public_main_pull_requests_only():
    text = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
    workflow = _load_workflow(CI_WORKFLOW_PATH)
    dependency_review = workflow["jobs"]["dependency-review"]

    assert workflow["on"]["pull_request"]["branches"] == ["main"]
    condition = dependency_review["if"]
    assert "github.event_name == 'pull_request'" in condition
    assert "github.event.repository.visibility == 'public'" in condition
    assert "(vars['ENABLE_GITHUB_CODE_SECURITY'] || 'false') == 'true'" in condition
    assert "github.event.repository.private == false" not in condition
    assert dependency_review["permissions"] == {
        "contents": "read",
        "pull-requests": "read",
    }
    checkout = dependency_review["steps"][0]
    assert checkout["with"]["persist-credentials"] == "false"
    review = dependency_review["steps"][1]
    assert review["uses"].startswith("actions/dependency-review-action@")
    assert len(review["uses"].split("@", 1)[1]) == 40
    summary = dependency_review["steps"][2]["run"]
    assert "PR-only job" in summary
    assert "Public repositories are eligible without ENABLE_GITHUB_CODE_SECURITY" in summary
    assert "Private repositories require ENABLE_GITHUB_CODE_SECURITY=true" in summary
    assert "pull_request_target" not in text


def test_dependabot_skips_only_the_human_pr_prose_policy():
    path = WORKFLOW_DIR / "pr-title-policy.yml"
    text = path.read_text(encoding="utf-8")
    workflow = _load_workflow(path)
    job = workflow["jobs"]["pr-title-policy"]

    assert job["if"] == "github.actor != 'dependabot[bot]'"
    assert "Validate PR title" in text
    assert "Validate PR description" in text
    assert "ops/security/validate_pr_body.py" in text
    assert "pull_request_target" not in text
    assert workflow["permissions"] == {
        "contents": "read",
        "pull-requests": "read",
    }


def test_commit_message_policy_validates_first_parent_pr_commits_only():
    text = (WORKFLOW_DIR / "commit-message-policy.yml").read_text(encoding="utf-8")

    assert "git log --first-parent --format='%H%x00%s%x00'" in text
    assert 'git rev-list --first-parent --count "${BASE_SHA}..${HEAD_SHA}"' in text


def test_label_workflows_share_bounded_trusted_policy_and_manual_safeguards():
    issue = _load_workflow(WORKFLOW_DIR / "issue-labeler.yml")
    pr = _load_workflow(WORKFLOW_DIR / "pr-labeler.yml")
    retag = _load_workflow(WORKFLOW_DIR / "retag-labels.yml")
    issue_text = (WORKFLOW_DIR / "issue-labeler.yml").read_text(encoding="utf-8")
    pr_text = (WORKFLOW_DIR / "pr-labeler.yml").read_text(encoding="utf-8")
    retag_text = (WORKFLOW_DIR / "retag-labels.yml").read_text(encoding="utf-8")

    assert "issues" in issue["on"]
    assert "pull_request" in pr["on"]
    assert set(retag["on"]) == {"workflow_dispatch"}
    for text in (issue_text, pr_text, retag_text):
        assert "ops/security/github_label_policy.py" in text
        assert "pull_request_target" not in text
        assert "< <(" not in text
    assert "ref: ${{ github.event.repository.default_branch }}" in issue_text
    assert "ref: ${{ github.event.pull_request.base.sha }}" in pr_text
    assert "Detect trusted label policy" in pr_text
    assert "steps.trusted-policy.outputs.available == 'true'" in pr_text
    assert "skipping this bootstrap run" in pr_text
    assert "--name-only" in pr_text
    assert "--patch" not in pr_text
    assert "sync-labels" not in pr_text
    assert retag["on"]["workflow_dispatch"]["inputs"]["dry_run"]["default"] == "true"
    assert "confirm_retag to equal RETAG" in retag_text
    assert "PROTECTED_LABELS" in retag_text
    assert not Path(".github/labeler.yml").exists()

    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "docs/development/github-labeling.md",
            "docs/GITHUB_ACTIONS.md",
            "docs/CONTRIBUTING.md",
        )
    )
    for required in (
        "At most six",
        "needs-triage",
        "dry_run: true",
        "confirm_retag: RETAG",
        "dependencies",
        "docker",
        "github-actions",
        "python",
        "triage aids",
    ):
        assert required in docs


def test_tls_workflow_rejects_invalid_hosts_and_has_reviewed_defaults():
    text = (WORKFLOW_DIR / "tls-scan.yml").read_text(encoding="utf-8")

    assert "default: staging-sitbank.pp.ua" in text
    assert "default: sitbank.pp.ua" in text
    assert "TLS scan target must be a hostname, not a URL or command fragment." in text
    assert 'readonly target_url="https://${target_host}"' in text


def test_github_actions_variables_and_secret_boundary_are_documented():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
    combined = f"{deployment}\n{operations}"

    for required in (
        "ENABLE_GITHUB_CODE_SECURITY",
        "STAGING_PUBLIC_HOST",
        "PROD_PUBLIC_HOST",
        "staging-sitbank.pp.ua",
        "sitbank.pp.ua",
        "repository variables",
        "not secrets",
        "protected environment secrets",
    ):
        assert required in combined
    assert "Defaults to `false`" in deployment
