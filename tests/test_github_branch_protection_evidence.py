from pathlib import Path

import yaml


def test_branch_protection_evidence_matches_workflow_display_names():
    evidence = Path(
        "docs/security/governance/github-branch-protection-evidence.md"
    ).read_text(encoding="utf-8")
    expected = {
        "CI, publish, and deploy / Workflow security": (
            "ci-deploy.yml",
            "workflow-security",
        ),
        "CI, publish, and deploy / Test and security checks": (
            "ci-deploy.yml",
            "test",
        ),
        "CI, publish, and deploy / Dependency review": (
            "ci-deploy.yml",
            "dependency-review",
        ),
        "ShellCheck / Repository shell scripts": ("shellcheck.yml", "scan"),
        "Hadolint / Repository Dockerfiles": ("hadolint.yml", "scan"),
        "Semgrep / High-severity SAST": ("semgrep.yml", "scan"),
        "Gitleaks / Full-history secret scan": ("gitleaks.yml", "scan"),
        "CodeQL / Python analysis": ("codeql.yml", "analyze-python"),
        "Commit message policy / Commit message": (
            "commit-message-policy.yml",
            "commit-message-policy",
        ),
        "PR title policy / Pull request title": (
            "pr-title-policy.yml",
            "pr-title-policy",
        ),
    }
    for check_name, (filename, job_id) in expected.items():
        workflow = yaml.safe_load(
            Path(".github/workflows", filename).read_text(encoding="utf-8")
        )
        actual = f"{workflow['name']} / {workflow['jobs'][job_id]['name']}"
        assert actual == check_name
        assert f"`{check_name}`" in evidence

    assert "GitHub-hosted settings" in evidence
    assert "after merge to `main`" in evidence
    assert "PR DAST" in evidence and "reporting-only" in evidence


def test_codeowners_covers_sensitive_surfaces():
    codeowners = Path(".github/CODEOWNERS").read_text(encoding="utf-8")
    for path in (
        "* @Koon-Kiat",
        "/.github/ @Koon-Kiat",
        "/ops/ @Koon-Kiat",
        "/app/security/ @Koon-Kiat",
        "/app/admin/ @Koon-Kiat",
        "/migrations/ @Koon-Kiat",
        "/config.py @Koon-Kiat",
        "/admin_wsgi.py @Koon-Kiat",
        "/docs/security/ @Koon-Kiat",
    ):
        assert path in codeowners
