from __future__ import annotations

from pathlib import Path


GOVERNANCE = Path("docs/security/security-governance.md")
GAP_REGISTER = Path("docs/security/security-gap-register.md")
DESIGN_REGISTER = Path("docs/security/design-risk-register.md")
FRAMEWORK = Path("docs/security/framework-control-matrix.md")


def _section(text: str, heading: str) -> str:
    marker = f"## {heading}"
    start = text.index(marker)
    next_heading = text.find("\n## ", start + len(marker))
    return text[start:] if next_heading == -1 else text[start:next_heading]


def _table_rows(section: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if cells and all(set(cell) <= {"-", " "} for cell in cells):
            continue
        rows.append(cells)
    return rows


def test_security_governance_doc_defines_roles_cadence_and_tracking():
    assert GOVERNANCE.exists()
    text = GOVERNANCE.read_text(encoding="utf-8")

    for required in (
        "Security Owner",
        "Backup Reviewer",
        "Application Owner",
        "Deployment Owner",
        "Documentation Owner",
        "Risk Owner",
        "Reviewer",
        "External operator / outside repo",
        "at least once per milestone or release cycle",
        "Accepted risks",
        "Off-Repo Ownership",
        "Stale Documentation Prevention",
        "Urgent Escalation",
        "Each important open security gap must have an explicit status",
        "not a certification",
    ):
        assert required in text


def test_framework_matrix_links_governance_to_ssdf_and_samm():
    matrix = FRAMEWORK.read_text(encoding="utf-8")

    assert "docs/security/security-governance.md" in matrix
    assert "| Prepare the organization | Implemented |" in matrix
    assert "| Governance | Implemented |" in matrix
    assert "Role-based ownership" in matrix
    assert "recurring review cadence" in matrix
    assert "tests/test_security_governance_docs.py" in matrix


def test_open_gap_register_rows_have_owner_status_and_review_tracking():
    register = GAP_REGISTER.read_text(encoding="utf-8")
    rows = _table_rows(_section(register, "Current Open Gaps"))
    header = rows[0]

    for required_column in ("Owner role", "Status / tracking", "Review trigger"):
        assert required_column in header

    owner_index = header.index("Owner role")
    status_index = header.index("Status / tracking")
    trigger_index = header.index("Review trigger")
    tracking_markers = (
        "needs-triage",
        "Accepted",
        "Deferred",
        "Open gap",
        "CI remains source of truth",
    )

    for row in rows[1:]:
        assert row[owner_index], row
        assert row[status_index], row
        assert row[trigger_index], row
        assert any(marker in row[status_index] for marker in tracking_markers), row


def test_design_risk_register_rows_have_owner_status_and_review_tracking():
    text = DESIGN_REGISTER.read_text(encoding="utf-8")
    rows = _table_rows(text)
    header = rows[0]

    for required_column in ("Owner role", "Status / tracking", "Review trigger"):
        assert required_column in header

    owner_index = header.index("Owner role")
    status_index = header.index("Status / tracking")
    trigger_index = header.index("Review trigger")
    for row in rows[1:]:
        assert row[owner_index], row
        assert row[status_index], row
        assert row[trigger_index], row

    assert "docs/security/security-governance.md" in text
    assert "External operator / outside repo" in text
    assert "Conditional accepted risk" in text


def test_security_docs_explain_closed_gap_stale_doc_prevention():
    combined = " ".join(
        path.read_text(encoding="utf-8")
        for path in (
            GOVERNANCE,
            Path("docs/CONTRIBUTING.md"),
            Path("docs/security/incident-response.md"),
        )
    ).replace("\n", " ")

    normalized = " ".join(
        combined.split()
    )

    for required in (
        "Every security change or gap closure should check whether these docs need updates",
        "Closing a security gap should update the gap register",
        "update the gap register, framework matrix, runbooks, and tests",
    ):
        assert required in normalized


def test_governance_docs_do_not_invent_people_or_certification_claims():
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            GOVERNANCE,
            GAP_REGISTER,
            DESIGN_REGISTER,
            FRAMEWORK,
            Path("SECURITY.md"),
        )
    )

    for forbidden in (
        "Alice",
        "Bob",
        "Charlie",
        "Jane Doe",
        "John Doe",
        "is certified",
        "certified compliant",
        "compliance approved",
        "formal security team exists",
    ):
        assert forbidden not in combined

    for stale_claim in (
        "Formal ownership and recurring review cadence are documentation follow-up",
        "Assign recurring risk owners outside the repo",
        "formal security ownership is unclear",
        "recurring security review cadence is unclear",
    ):
        assert stale_claim not in combined
