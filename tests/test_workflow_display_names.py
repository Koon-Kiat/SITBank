from __future__ import annotations

import re
from pathlib import Path

import yaml


WORKFLOW_DIR = Path(".github/workflows")
CI_WORKFLOW = WORKFLOW_DIR / "ci-deploy.yml"
BOOTSTRAP_WORKFLOW = WORKFLOW_DIR / "bootstrap-ec2.yml"
RAW_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)+")
TEMPLATE_FRAGMENT = re.compile(r"\$\{\{.*?\}\}")
ALLOWED_DYNAMIC_JOB_NAMES = {
    ("tls-scan.yml", "scan"): "Scan ${{ matrix.target.label }}",
}
EXPECTED_CI_NAMES = {
    "resolve-source": "Resolve source",
    "workflow-security": "Workflow security",
    "dependency-review": "Dependency review",
    "test": "Test and security checks",
    "sonarqube": "SonarQube analysis",
    "sonarqube-comment": "SonarQube PR comment",
    "image-test": "Container image test",
    "deployment-preflight": "Deployment preflight",
    "publish": "Publish container image",
    "release-verify": "Release verification",
    "deploy-staging": "Deploy staging",
    "verify-staging-tls": "Verify staging TLS",
    "deploy-production": "Deploy production",
    "verify-production-tls": "Verify production TLS",
    "verify-private-admin-tailnet": "Verify private admin tailnet",
}


def _load_workflow(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _assert_human_readable_name(name: object, context: str) -> str:
    assert isinstance(name, str) and name.strip(), (
        f"{context} needs an explicit name"
    )
    assert name == name.strip(), f"{context} name has surrounding whitespace"
    assert name[0].isupper(), f"{context} name must start with a capital letter"
    assert not RAW_SLUG.fullmatch(name), f"{context} exposes a raw slug"
    return name


def test_every_workflow_job_and_visible_step_has_a_human_readable_name():
    workflow_paths = sorted(WORKFLOW_DIR.glob("*.yml"))

    assert workflow_paths
    for path in workflow_paths:
        workflow = _load_workflow(path)
        _assert_human_readable_name(workflow.get("name"), f"{path} workflow")

        jobs = workflow.get("jobs")
        assert isinstance(jobs, dict) and jobs, f"{path} must define jobs"
        for job_id, job in jobs.items():
            context = f"{path} job {job_id}"
            display_name = _assert_human_readable_name(job.get("name"), context)
            assert display_name != job_id, f"{context} exposes its internal ID"

            expected_dynamic_name = ALLOWED_DYNAMIC_JOB_NAMES.get(
                (path.name, job_id)
            )
            if expected_dynamic_name is None:
                assert not TEMPLATE_FRAGMENT.search(display_name), (
                    f"{context} has an unexpected template fragment"
                )
            else:
                assert display_name == expected_dynamic_name

            for index, step in enumerate(job.get("steps", []), start=1):
                step_context = f"{context} step {index}"
                step_name = _assert_human_readable_name(
                    step.get("name"), step_context
                )
                assert not TEMPLATE_FRAGMENT.search(step_name), (
                    f"{step_context} has an unresolved template fragment"
                )


def test_release_display_names_preserve_security_boundaries_and_ordering():
    ci = _load_workflow(CI_WORKFLOW)
    bootstrap = _load_workflow(BOOTSTRAP_WORKFLOW)

    assert {
        job_id: job["name"] for job_id, job in ci["jobs"].items()
    } == EXPECTED_CI_NAMES
    assert {
        job_id: job["name"] for job_id, job in bootstrap["jobs"].items()
    } == {
        "validate-request": "Validate bootstrap request",
        "bootstrap-staging": "Bootstrap staging EC2",
        "bootstrap-production": "Bootstrap production EC2",
    }

    assert ci["jobs"]["deploy-production"]["needs"] == [
        "release-verify",
        "deploy-staging",
        "verify-staging-tls",
    ]
    private_admin = ci["jobs"]["verify-private-admin-tailnet"]
    assert private_admin["needs"] == [
        "deploy-production",
        "verify-production-tls",
    ]
    assert private_admin["environment"] == {"name": "admin-tailscale"}
    assert "tag:github-ci-admin-verify" in str(private_admin)

    for target, expected_tag in (
        ("staging", "tag:github-ci-staging-deploy"),
        ("production", "tag:github-ci-prod-deploy"),
    ):
        job = ci["jobs"][f"deploy-{target}"]
        prefix = "STAGING" if target == "staging" else "PROD"
        tailnet_step = next(
            step
            for step in job["steps"]
            if step["name"] == f"Join the {target} deploy tailnet"
        )
        assert tailnet_step["with"]["tags"] == expected_tag
        assert "StrictHostKeyChecking=yes" in str(job)
        assert "BatchMode=yes" in str(job)
        assert "IdentitiesOnly=yes" in str(job)
        assert f"{prefix}_EC2_KNOWN_HOSTS" in str(job)
        assert f"{prefix}_EC2_SSH_PRIVATE_KEY_B64" in str(job)
        assert "tailscale logout" in job["steps"][-1]["run"]
        assert job["steps"][-1]["if"] == "${{ always() }}"


def test_workflow_display_name_documentation_matches_the_ci_workflow():
    github_actions = Path("docs/GITHUB_ACTIONS.md").read_text(encoding="utf-8")
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
    sonar = Path("docs/security/assurance/sonarqube.md").read_text(
        encoding="utf-8"
    )
    combined = "\n".join((github_actions, deployment, operations, sonar))

    for job_id, display_name in EXPECTED_CI_NAMES.items():
        assert f"`{job_id}`" in combined
        assert f"`{display_name}`" in combined
    assert "Internal job IDs remain stable kebab-case keys" in github_actions
    normalized_github_actions = re.sub(r"\s+", " ", github_actions)
    assert (
        "Repository files do not update GitHub rulesets"
        in normalized_github_actions
    )
