from __future__ import annotations

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


def test_known_issue_tracked_gaps_link_current_issue_numbers():
    register = GAP_REGISTER.read_text(encoding="utf-8")
    current_open = _section(register, "Current Open Gaps")

    for title, issue_ref in (
        ("Password history beyond current-password reuse", "#166"),
        ("Admin audit-log viewer UI", "#197"),
        ("Automated retention and disposal jobs", "#209"),
        ("Device-bound session proof", "#218"),
    ):
        row = next(line for line in current_open.splitlines() if title in line)
        assert issue_ref in row

    assert "Separate issue: No" not in register
    assert "Local Docker/Compose proof when Docker is unavailable" not in current_open
    assert "Strict Docker/Compose local CI mode" in register


def test_design_risk_register_links_sonar_backup_and_zero_trust_tracking():
    design = DESIGN_REGISTER.read_text(encoding="utf-8")

    assert "#188" in next(
        line for line in design.splitlines() if "Reporting-only SonarQube" in line
    )
    assert "#208" in next(
        line for line in design.splitlines() if "Encrypted backup helper" in line
    )
    zero_trust_row = next(
        line for line in design.splitlines() if "Zero-trust/private admin-staging" in line
    )
    for issue_ref in ("#198", "#199", "#200", "#210", "#211", "#215", "#218"):
        assert issue_ref in zero_trust_row


def test_zero_trust_docs_use_current_architecture_and_issue_set():
    docs = ZERO_TRUST.read_text(encoding="utf-8")
    normalized_docs = " ".join(docs.split())

    assert "Issue #184" not in docs
    assert "SITBank uses a hybrid zero-trust access model" in docs
    for issue_ref in ("#198", "#199", "#200", "#210", "#211", "#215", "#218"):
        assert issue_ref in docs
    assert "https://sitbank-ec2.tailca101b.ts.net/" in docs
    assert "Admins connect to the Tailscale VPN first, then open" in docs
    assert "Funnel would publish the service to the public internet" in docs
    assert "admin login, TOTP, CSRF, route authorization, and audit logging" in docs
    assert "does not replace Flask admin login, TOTP, CSRF protection" in normalized_docs
    assert "Protected GitHub CI tailnet verification is not implemented in normal public CI" in docs


def test_staging_domain_docs_match_implemented_active_cloudflare_hostname():
    docs = _docs_text()

    assert "staging-sitbank.pp.ua" in docs
    assert "retired DuckDNS staging hostname is not an active" in docs
    assert "staging-sitbank.duckdns.org remains the active" not in docs
    assert "staging-sitbank.pp.ua` is the Cloudflare-managed staging hostname" in docs


def test_public_tls_docs_exclude_private_tailscale_admin_hostname_from_normal_scan():
    operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
    normalized_operations = " ".join(operations.split())
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    normalized_deployment = " ".join(deployment.split())
    workflow = Path(".github/workflows/tls-scan.yml").read_text(encoding="utf-8")

    assert "normal public TLS scan deliberately excludes the private Tailscale admin hostname" in operations
    assert "job joins the tailnet or uses a tailnet self-hosted runner" in normalized_operations
    assert "sitbank-ec2.tailca101b.ts.net" not in workflow
    assert "Do not add the private Tailscale admin URL to public GitHub-hosted TLS scans." in normalized_deployment


def test_current_open_gap_rows_have_tracking_state():
    register = GAP_REGISTER.read_text(encoding="utf-8")
    rows = _table_rows(_section(register, "Current Open Gaps"))
    header = rows[0]
    status_index = header.index("Status / tracking")
    tracking_markers = ("#", "needs-triage", "Accepted", "Deferred", "Open gap")

    for row in rows[1:]:
        assert any(marker in row[status_index] for marker in tracking_markers), row


def test_governance_tracking_points_to_governance_doc_and_not_stale_gap_text():
    docs = _docs_text()

    assert "docs/security/security-governance.md" in docs
    assert "Formal ownership and recurring review cadence are documentation follow-up" not in docs
    assert "Assign recurring risk owners outside the repo" not in docs
    assert "formal security ownership is unclear" not in docs
    assert "recurring security review cadence is unclear" not in docs
