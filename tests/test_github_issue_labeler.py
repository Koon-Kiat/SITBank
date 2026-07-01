from __future__ import annotations

import json

import pytest

from ops.security import github_label_policy as policy


def test_issue_policy_ignores_generic_guardrail_and_validation_sections():
    labels = policy.compute_labels(
        kind="issue",
        title="Fix dependency-review startup for public pull requests",
        body="""
## Summary

Make dependency review reliable for public GitHub Actions pull requests.

## Guardrails

Do not weaken authentication, sessions, MFA, admin isolation, databases,
Cloudflare, Tailscale, staging deployment, audit logging, or frontend controls.

## Tests to add or update

Add pytest coverage and documentation consistency tests.

## Validation commands

Run the complete test suite with coverage.
""",
    )

    assert labels == ["needs-triage", "ci", "dependencies"]


@pytest.mark.parametrize(
    ("title", "body", "expected", "excluded"),
    [
        (
            "Harden TOTP recovery-code lifecycle",
            "## Summary\nStrengthen MFA recovery code handling.",
            {"security", "mfa"},
            {"database", "deployment", "staging"},
        ),
        (
            "Fix admin session revocation",
            "## Summary\nRevoke private admin server sessions safely.",
            {"admin", "session"},
            {"customer", "mfa"},
        ),
        (
            "Fix customer account balance display",
            "## Summary\nCorrect customer app account balance rendering.",
            {"customer", "banking"},
            {"admin", "database"},
        ),
    ],
)
def test_sensitive_issue_labels_require_focused_high_confidence_text(
    title,
    body,
    expected,
    excluded,
):
    labels = set(policy.compute_labels(kind="issue", title=title, body=body))

    assert expected <= labels
    assert not excluded & labels


def test_pr_policy_uses_narrow_paths_without_label_explosion():
    labels = policy.compute_labels(
        kind="pr",
        title="Disable Semgrep metrics in local scans",
        body="## Summary\nKeep local static analysis private and blocking.",
        head="303-disable-semgrep-metrics",
        paths=[
            ".github/workflows/semgrep.yml",
            "scripts/ci-local",
            "tests/test_static_analysis_workflows.py",
            "docs/GITHUB_ACTIONS.md",
        ],
    )

    assert set(labels) == {
        "security",
        "ci",
        "code-quality",
        "documentation",
        "tests",
    }


def test_pr_policy_caps_automatic_labels_and_leaves_broad_work_for_maintainers():
    labels = policy.compute_labels(
        kind="pr",
        title="Harden security auth sessions MFA admin database deployment Cloudflare staging",
        body="## Summary\nBroad architecture and secure SDLC change.",
        head="security-auth-session-mfa-admin-database-deploy-cloudflare-staging",
        paths=[
            "app/security/sessions.py",
            "app/admin/routes.py",
            "app/auth/mfa_policy.py",
            "migrations/versions/example.py",
            "ops/cloudflare/provision-staging-access",
            ".github/workflows/ci-deploy.yml",
            "tests/test_session_management.py",
            "docs/security/architecture/example.md",
        ],
    )

    assert len(labels) == policy.MAX_AUTO_LABELS
    assert len(labels) == len(set(labels))


def test_documentation_only_and_python_source_changes_stay_distinct():
    docs = policy.compute_labels(
        kind="pr",
        title="Clarify contributor guidance",
        paths=["docs/CONTRIBUTING.md"],
    )
    python = policy.compute_labels(
        kind="pr",
        title="Refactor helper naming",
        paths=["app/main/routes.py"],
    )

    assert docs == ["documentation"]
    assert python == ["customer", "python"]


def test_compute_command_reads_issue_event_and_emits_one_label_per_line(tmp_path, capsys):
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {
                "issue": {
                    "title": "Document SonarCloud quality gate evidence",
                    "body": "## Summary\nUpdate SonarCloud documentation.",
                }
            }
        ),
        encoding="utf-8",
    )

    assert policy.main(["compute", "--kind", "issue", "--input", str(event_path)]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "needs-triage",
        "code-quality",
        "documentation",
        "ci",
    ]


def test_compute_command_validates_kind_and_paths(tmp_path):
    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text(json.dumps({"title": "Example", "paths": "not-a-list"}), encoding="utf-8")

    with pytest.raises(ValueError, match="paths must be a list of strings"):
        policy.main(["compute", "--kind", "pr", "--input", str(invalid_path)])
    with pytest.raises(ValueError, match="kind must"):
        policy.compute_labels(kind="discussion", title="Example")


def test_definitions_are_complete_safe_and_cli_serializable(capsys):
    assert set(rule.label for rule in policy.RULES) <= set(policy.LABEL_DEFINITIONS)
    assert policy.ISSUE_DEFAULT_LABEL in policy.LABEL_DEFINITIONS
    assert all("\t" not in description for description, _ in policy.LABEL_DEFINITIONS.values())
    assert all(len(color) == 6 for _, color in policy.LABEL_DEFINITIONS.values())

    assert policy.main(["definitions"]) == 0
    rows = capsys.readouterr().out.splitlines()
    assert len(rows) == len(policy.LABEL_DEFINITIONS)
    assert all(len(row.split("\t")) == 3 for row in rows)
