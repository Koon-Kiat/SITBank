from __future__ import annotations

import re
from pathlib import Path


GAP_REGISTER = Path("docs/security/security-gap-register.md")
DESIGN_REGISTER = Path("docs/security/design-risk-register.md")
ZERO_TRUST = Path("docs/security/admin-and-staging-zero-trust-access.md")


def _docs_text() -> str:
    paths = [Path("README.md"), Path("SECURITY.md")]
    paths.extend(sorted(Path("docs").rglob("*.md")))
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


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


def test_open_gaps_use_current_status_without_tracker_numbers():
    register = GAP_REGISTER.read_text(encoding="utf-8")
    current_open = _section(register, "Current Open Gaps")

    for title, status in (
        ("Password history beyond current-password reuse", "Open gap"),
        ("Admin audit-log viewer UI", "Open gap"),
        ("Automated retention and disposal jobs", "Open gap"),
        ("Device-bound session proof", "Accepted defense-in-depth gap"),
    ):
        row = next(line for line in current_open.splitlines() if title in line)
        assert status in row

    assert "Local Docker/Compose proof when Docker is unavailable" not in current_open
    assert "Strict Docker/Compose local CI mode" in register


def test_design_risk_register_uses_current_follow_up_status():
    design = DESIGN_REGISTER.read_text(encoding="utf-8")

    assert "Baseline review remains" in next(
        line for line in design.splitlines() if "Reporting-only SonarQube" in line
    )
    assert "Runtime verification hardening remains" in next(
        line for line in design.splitlines() if "Encrypted backup helper" in line
    )
    zero_trust_row = next(
        line for line in design.splitlines() if "Zero-trust/private admin-staging" in line
    )
    assert "Operator verification remains" in zero_trust_row


def test_zero_trust_docs_use_current_architecture_and_control_state():
    docs = ZERO_TRUST.read_text(encoding="utf-8")
    normalized_docs = " ".join(docs.split())

    assert "SITBank uses a hybrid zero-trust access model" in docs
    assert "Implemented repository controls include" in docs
    assert "https://admin-sitbank.tailca101b.ts.net/" in docs
    assert "Admins connect to the Tailscale VPN first, then open" in docs
    assert "Funnel would publish the service to the public internet" in docs
    assert "admin login, TOTP, CSRF, route authorization, and audit logging" in docs
    assert "does not replace Flask admin login, TOTP, CSRF protection" in normalized_docs
    assert "Protected GitHub CI tailnet verification is implemented only by" in docs
    assert "GitHub-hosted runner joins the tailnet" not in docs
    assert "temporarily joins a GitHub-hosted runner to the tailnet" in normalized_docs


def test_documentation_has_no_numbered_issue_references():
    docs = _docs_text()

    assert not re.search(
        r"(?i)\bissue\s*#?\s*\d+\b|(?<![\w-])#\d{2,4}\b",
        docs,
    )


def test_staging_domain_docs_match_implemented_active_cloudflare_hostname():
    docs = _docs_text()
    retired_staging = "staging-sitbank" + ".duckdns.org"

    assert "staging-sitbank.pp.ua" in docs
    assert "retired DuckDNS staging hostname is not an active" in docs
    assert f"{retired_staging} remains the active" not in docs
    assert "staging-sitbank.pp.ua` is the Cloudflare-managed staging hostname" in docs


def test_public_tls_docs_exclude_private_tailscale_admin_hostname_from_normal_scan():
    operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
    normalized_operations = " ".join(operations.split())
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    normalized_deployment = " ".join(deployment.split())
    workflow = Path(".github/workflows/tls-scan.yml").read_text(encoding="utf-8")

    assert "normal public TLS scan deliberately excludes the private Tailscale admin hostname" in operations
    assert (
        "manually approved `Admin-Tailscale` "
        "environment job that joins the tailnet"
        in normalized_operations
    )
    assert "admin-sitbank.tailca101b.ts.net" not in workflow
    assert "sitbank-admin.tailca101b.ts.net" not in workflow
    assert "sitbank-ec2.tailca101b.ts.net" not in workflow
    assert "Do not add the private Tailscale admin URL to public GitHub-hosted TLS scans." in normalized_deployment


def test_active_docs_tests_and_workflows_use_current_private_admin_hostname():
    current_admin_host = "admin-sitbank.tailca101b.ts.net"
    retired_ec2_host = "sitbank-ec2" + ".tailca101b.ts.net"
    retired_admin_host = "sitbank-admin" + ".tailca101b.ts.net"
    paths = [Path("README.md"), Path("SECURITY.md")]
    paths.extend(path for path in sorted(Path("docs").rglob("*.md")) if "archive" not in path.parts)
    paths.extend(sorted(Path("tests").glob("*.py")))
    paths.extend(sorted(Path(".github/workflows").glob("*.yml")))

    combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)

    assert current_admin_host in combined
    assert retired_ec2_host not in combined
    assert retired_admin_host not in combined


def test_current_open_gap_rows_have_tracking_state():
    register = GAP_REGISTER.read_text(encoding="utf-8")
    rows = _table_rows(_section(register, "Current Open Gaps"))
    header = rows[0]
    status_index = header.index("Status / tracking")
    tracking_markers = ("needs-triage", "Accepted", "Deferred", "Open gap")

    for row in rows[1:]:
        assert any(marker in row[status_index] for marker in tracking_markers), row


def test_governance_tracking_points_to_governance_doc_and_not_stale_gap_text():
    docs = _docs_text()

    assert "docs/security/security-governance.md" in docs
    assert "Formal ownership and recurring review cadence are documentation follow-up" not in docs
    assert "Assign recurring risk owners outside the repo" not in docs
    assert "formal security ownership is unclear" not in docs
    assert "recurring security review cadence is unclear" not in docs
