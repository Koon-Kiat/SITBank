from __future__ import annotations

import json

import pytest

from ops.security.validate_pr_body import load_body_from_event, validate_body


VALID_BODY = """Summary
Adds server-side Payee management required for Local Transfer.

Why
Local Transfer needs trusted recipient records before transfer creation.

What changed
* Added Payee model and routes
* Added server-side validation
* Added tests for invalid recipient input

Security impact
Recipient names are loaded from the database and are not accepted from client input.

Deployment impact
No deployment action required.

Verification
* python -m pytest tests/test_payees.py

Notes
No follow-up required.
"""


def _messages(body: str) -> list[str]:
    return [error.message for error in validate_body(body)]


def test_valid_pr_body_passes_with_plain_headings():
    assert validate_body(VALID_BODY) == []


def test_valid_pr_body_passes_with_markdown_headings_and_notes_none():
    body = VALID_BODY.replace("Summary", "## Summary", 1).replace("Notes\nNo follow-up required.", "### Notes\nN/A")

    assert validate_body(body) == []


def test_empty_pr_body_fails():
    assert _messages(" \n\t ") == ["PR description must not be empty."]


def test_missing_required_section_fails():
    body = VALID_BODY.replace("Why\nLocal Transfer needs trusted recipient records before transfer creation.\n\n", "")

    assert "Missing required PR description section: Why." in _messages(body)


def test_placeholder_template_left_below_custom_paragraph_fails():
    body = """Introduces the Payee feature as a prerequisite for Local Transfer.

Summary
Briefly describe what this PR improves or fixes.

Why
Explain the problem, risk, or reason this change is needed.

What changed

Security impact
Explain how this affects security controls, secrets, permissions, auth, CI/CD, deployment safety, or runtime behavior.

Deployment impact
Explain whether this PR requires:

EC2 bootstrap
staging deployment
production deployment
database migration
secret changes
no deployment action

Verification

Notes
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
