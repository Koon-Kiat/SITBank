from __future__ import annotations

import json
from pathlib import Path

import pytest

from ops.security import validate_pr_body as policy
from ops.security.validate_pr_body import load_body_from_event, validate_body


VALID_BODY = """Summary
---
Adds server-side Payee management required for Local Transfer.

Why
---
Local Transfer needs trusted recipient records before transfer creation.

What changed
---
* Added Payee model and routes
* Added server-side validation
* Added tests for invalid recipient input

Security impact
---
Recipient names are loaded from the database and are not accepted from client input.

Deployment impact
---
No deployment action required.

Verification
---
* python -m pytest tests/test_payees.py

Notes
---
No follow-up required.
"""


def _messages(body: str) -> list[str]:
    return [error.message for error in validate_body(body)]


def test_valid_pr_body_passes_with_setext_headings():
    assert validate_body(VALID_BODY) == []


def test_valid_pr_body_still_accepts_plain_headings():
    body = VALID_BODY.replace("---\n", "")

    assert validate_body(body) == []


def test_valid_pr_body_passes_with_markdown_headings_and_notes_none():
    body = VALID_BODY.replace("Summary\n---", "## Summary", 1).replace("Notes\n---\nNo follow-up required.", "### Notes\nN/A")

    assert validate_body(body) == []


def test_empty_pr_body_fails():
    assert _messages(" \n\t ") == ["PR description must not be empty."]


def test_missing_required_section_fails():
    body = VALID_BODY.replace("Why\n---\nLocal Transfer needs trusted recipient records before transfer creation.\n\n", "")

    assert "Missing required PR description section: Why." in _messages(body)


def test_placeholder_template_left_below_custom_paragraph_fails():
    body = """Introduces the Payee feature as a prerequisite for Local Transfer.

Summary
---
Briefly describe what this PR improves or fixes.

Why
---
Explain the problem, risk, or reason this change is needed.

What changed
---

Security impact
---
Explain how this affects security controls, secrets, permissions, auth, CI/CD, deployment safety, or runtime behavior.

Deployment impact
---
Explain whether this PR requires:

EC2 bootstrap
staging deployment
production deployment
database migration
secret changes
no deployment action

Verification
---

Notes
---
Add any follow-up work, limitations, or operator instructions.
"""

    messages = _messages(body)

    assert "PR description still contains unchanged template placeholder text." in messages
    assert "PR description section 'What changed' must contain meaningful content." in messages
    assert "PR description section 'Verification' must contain meaningful content." in messages


def test_deployment_impact_requires_concrete_impact():
    body = VALID_BODY.replace("No deployment action required.", "Reviewed by operator.")

    assert "Deployment impact must state at least one concrete deployment impact." in _messages(body)


def test_verification_requires_meaningful_content():
    body = VALID_BODY.replace("* python -m pytest tests/test_payees.py", "*\n*\n*")

    assert "PR description section 'Verification' must contain meaningful content." in _messages(body)


def test_setext_underline_alone_does_not_make_section_meaningful():
    body = VALID_BODY.replace(
        "* Added Payee model and routes\n* Added server-side validation\n* Added tests for invalid recipient input",
        "",
    )

    assert "PR description section 'What changed' must contain meaningful content." in _messages(body)


def test_event_payload_body_is_loaded(tmp_path):
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"pull_request": {"body": VALID_BODY}}), encoding="utf-8")

    assert load_body_from_event(event_path, tmp_path) == VALID_BODY


def test_event_payload_path_must_stay_within_trusted_root(tmp_path):
    allowed_root = tmp_path / "events"
    allowed_root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"pull_request": {"body": VALID_BODY}}), encoding="utf-8")

    with pytest.raises(ValueError, match="escapes"):
        load_body_from_event(outside, allowed_root)


def test_input_root_and_file_must_be_distinct_existing_files(tmp_path):
    body = tmp_path / "body.md"
    body.write_text(VALID_BODY, encoding="utf-8")

    with pytest.raises(ValueError, match="root must be a directory"):
        policy._validated_input_path(body, body)
    with pytest.raises(ValueError, match="escapes"):
        policy._validated_input_path(tmp_path, tmp_path)


def test_main_accepts_body_and_event_files_and_reports_errors(tmp_path, capsys):
    body = tmp_path / "body.md"
    body.write_text(VALID_BODY, encoding="utf-8")
    assert policy.main(
        ["--input-root", str(tmp_path), "--body-file", str(body)]
    ) == 0
    assert "policy passed" in capsys.readouterr().out

    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"body": VALID_BODY}}), encoding="utf-8")
    assert policy.main(
        ["--input-root", str(tmp_path), "--event-path", str(event)]
    ) == 0

    body.write_text("", encoding="utf-8")
    assert policy.main(
        ["--input-root", str(tmp_path), "--body-file", str(body)]
    ) == 1
    output = capsys.readouterr().out
    assert "::error title=Invalid PR description::" in output
    assert "Valid PR description example:" in output


def test_annotation_and_normalization_helpers_are_safe():
    assert policy.annotation_escape("a%\r\nb") == "a%25%0D%0Ab"
    assert policy._canonical_section_name("  SECURITY   IMPACT ") == "Security impact"
    assert policy._has_deployment_impact("Staging deployment is required.")
    assert policy._has_meaningful_content("- N/A") is False
    assert policy._normalize_line("  -  Mixed   Spacing ") == "mixed spacing"


def test_agent_pr_and_commit_guidance_matches_repository_policy():
    agents = Path("AGENTS.md").read_text(encoding="utf-8")
    rules = Path("docs/codex/github-pr-rules.md").read_text(encoding="utf-8")

    for required in (
        ".github/workflows/pr-title-policy.yml",
        "docs/CONTRIBUTION_MESSAGE_POLICY.md",
        "12 to 72 characters",
        "Do not add `[codex]`",
        "Avoid category or Conventional Commit prefixes",
        "descriptive commit subject plus a commit body",
        "why the change is needed",
        "trust boundaries affected",
        "validation, deployment, migration, or provider impact",
    ):
        assert required in f"{agents}\n{rules}"
