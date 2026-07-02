from __future__ import annotations

import re
from pathlib import Path


GAP_REGISTER = Path("docs/security/governance/security-gap-register.md")
DESIGN_REGISTER = Path("docs/security/governance/design-risk-register.md")
ZERO_TRUST = Path("docs/security/architecture/admin-and-staging-zero-trust-access.md")
SECURITY_DOCS = Path("docs/security")


def _docs_text() -> str:
    paths = [Path("README.md"), Path("SECURITY.md")]
    paths.extend(
        path
        for path in sorted(Path("docs").rglob("*.md"))
        if "codex" not in path.parts
    )
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
        ("Automated retention and disposal jobs", "Open gap"),
        ("Authenticated DAST on ordinary pull requests", "Accepted risk / policy tradeoff"),
        ("EC2 SSH/UFW/security-group hardening deferred", "Deferred external prerequisite"),
        ("Device-bound session proof", "Accepted defense-in-depth gap"),
    ):
        row = next(line for line in current_open.splitlines() if title in line)
        assert status in row

    implemented_controls = _section(register, "Implemented Controls")
    assert "Password history and forced password change" in implemented_controls
    assert "Single active customer/admin session cap" in implemented_controls

    recently_closed = _section(register, "Recently Closed Gaps")
    for title in ("Admin dashboard role separation", "Admin audit-log viewer hardening"):
        row = next(line for line in recently_closed.splitlines() if title in line)
        assert "Solved" in row

    assert "Separate issue: No" not in register
    assert "Local Docker/Compose proof when Docker is unavailable" not in current_open
    assert "Strict Docker/Compose local CI mode" in register
    assert "Admin audit-log viewer UI hardening follow-up" not in current_open


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
    # Exact static architecture-doc check; no untrusted URL is accepted.
    # lgtm[py/incomplete-url-substring-sanitization]
    assert "https://admin-sitbank.tailca101b.ts.net/" in docs
    assert "Admins connect to the Tailscale VPN first, then open" in docs
    assert "Funnel would publish the service to the public internet" in docs
    assert "admin login, TOTP, CSRF, route authorization, and audit logging" in docs
    assert "does not replace Flask admin login, TOTP, CSRF protection" in normalized_docs
    assert "Protected GitHub CI tailnet verification is implemented only by" in docs
    assert "direct production gate in `.github/workflows/ci-deploy.yml`" in normalized_docs
    assert "### EC2 Host-Side Tailscale Preflight" in docs
    assert "ops/deploy/verify-tailscale-admin-access" in docs
    assert "The two controls answer different questions." in docs
    assert "### EC2 Tailscale Provisioning Automation" in docs
    assert "ops/tailscale/README.md" in docs
    assert "GitHub-hosted runner joins the tailnet" not in docs
    assert "temporarily join a GitHub-hosted runner to the tailnet" in normalized_docs


def test_documentation_has_no_numbered_issue_references():
    docs = _docs_text()

    assert not re.search(
        r"(?i)\bissue\s*#?\s*\d+\b|(?<![\w-])#\d{2,4}\b",
        docs,
    )


def test_privileged_email_domain_docs_are_workplace_only():
    docs = _docs_text()
    normalized_docs = " ".join(docs.split()).casefold()

    assert "privileged root-admin, admin, and staff accounts use approved sit workplace email domains only" in normalized_docs
    assert "staff invites are delivered to the workplace email and do not collect personal backup email contacts" in normalized_docs
    assert "staff invites use the workplace email and do not collect personal backup email contacts" in normalized_docs
    assert "privileged_email_noncompliant_accounts" in normalized_docs
    assert "does not silently rewrite or delete accounts" in normalized_docs
    assert "staff_invite_personal_email_domains" not in normalized_docs


def test_operational_observability_keeps_loki_out_of_admin_app():
    observability = (
        SECURITY_DOCS / "assurance" / "operational-observability.md"
    ).read_text(encoding="utf-8")
    audit_docs = (
        SECURITY_DOCS / "assurance" / "audit-and-alerting.md"
    ).read_text(encoding="utf-8")
    combined = " ".join(f"{observability}\n{audit_docs}".split())

    for required in (
        "Grafana, Loki, and Grafana Alloy are implemented",
        "ops/observability/compose.observability.yml",
        "docs/runbooks/private-observability-grafana-loki.md",
        "Nginx, container, deployment, systemd",
        "Do not embed Loki or Grafana credentials in Flask",
        "admin app must not become a general log browser",
        "SecurityAuditEvent",
        "does not query Loki",
        "shell history",
        "environment dumps",
        "retention_period: 168h",
    ):
        assert required in combined
    for forbidden in (
        "Grafana admin password:",
        "loki_" + "token=",
        "datasource_" + "password=",
    ):
        assert forbidden.casefold() not in combined.casefold()


def test_security_alert_delivery_docs_match_admin_controls():
    audit_docs = (
        SECURITY_DOCS / "assurance" / "audit-and-alerting.md"
    ).read_text(encoding="utf-8")
    access_docs = (
        SECURITY_DOCS / "architecture" / "access-control.md"
    ).read_text(encoding="utf-8")
    operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
    combined = " ".join(f"{audit_docs}\n{access_docs}\n{operations}".split())

    for required in (
        "`GET /alerts`",
        "delivery disabled",
        "`POST /alerts/deliver`",
        "CSRF",
        "current TOTP step-up",
        "build_security_alert_report(deliver=True)",
        "SecurityAlertDedupe",
        "security_alert_delivery",
        "requested",
        "delivered",
        "deduped",
        "failed",
        "blocked",
        "no browser force-resend mode or Web Push channel",
    ):
        assert required in combined
    for forbidden in (
        "GET /alerts sends",
        "GET /alerts delivers",
        "delivery bypasses CSRF",
        "delivery bypasses TOTP",
        "delivery bypasses admin",
    ):
        assert forbidden.casefold() not in combined.casefold()


def test_payee_audit_docs_require_references_and_bounded_metadata():
    audit_docs = (
        SECURITY_DOCS / "assurance" / "audit-and-alerting.md"
    ).read_text(encoding="utf-8")
    privacy_docs = (
        SECURITY_DOCS / "governance" / "privacy-and-pdpa.md"
    ).read_text(encoding="utf-8")
    combined = " ".join(f"{audit_docs}\n{privacy_docs}".split()).casefold()

    for required in (
        "payee audit calls must avoid raw account identifiers",
        "customer-controlled free text at the call site",
        "payee_account_ref",
        "bounded lengths",
        "instead of raw account numbers or customer-entered nicknames",
    ):
        assert required in combined


def test_security_docs_are_grouped_and_indexed_by_purpose():
    assert sorted(path.name for path in SECURITY_DOCS.glob("*.md")) == ["README.md"]

    expected = {
        "architecture": {
            "access-control.md",
            "admin-and-staging-zero-trust-access.md",
            "cloudflare-staging-access.md",
            "cryptography-and-authentication.md",
            "production-cloudflare-origin-boundary.md",
            "session-management.md",
            "threat-model.md",
        },
        "assurance": {
            "audit-and-alerting.md",
            "operational-observability.md",
            "secret-scanning.md",
            "secure-coding.md",
            "sonarqube.md",
            "test-automation-and-dependencies.md",
        },
        "governance": {
            "data-retention-and-deactivation.md",
            "design-risk-register.md",
            "framework-control-matrix.md",
            "github-branch-protection-evidence.md",
            "incident-response.md",
            "legacy-and-out-of-scope-technology.md",
            "privacy-and-pdpa.md",
            "security-gap-register.md",
            "security-governance.md",
        },
    }
    index = (SECURITY_DOCS / "README.md").read_text(encoding="utf-8")

    assert {
        path.name for path in SECURITY_DOCS.iterdir() if path.is_dir()
    } == set(expected)
    for category, filenames in expected.items():
        category_dir = SECURITY_DOCS / category
        assert {path.name for path in category_dir.glob("*.md")} == filenames
        for filename in filenames:
            assert f"({category}/{filename})" in index
            assert f"Category: [Security {category}](../README.md#{category})." in (
                category_dir / filename
            ).read_text(encoding="utf-8")


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
        "manually approved `admin-tailscale` "
        "environment job that joins the tailnet"
        in normalized_operations
    )
    assert "admin-sitbank.tailca101b.ts.net" not in workflow
    assert "sitbank-admin" + ".tailca101b.ts.net" not in workflow
    assert "sitbank-ec2" + ".tailca101b.ts.net" not in workflow
    assert "Do not add the private Tailscale admin URL to public GitHub-hosted TLS scans." in normalized_deployment


def test_active_docs_tests_and_workflows_use_current_private_admin_hostname():
    current_admin_host = "admin-sitbank.tailca101b.ts.net"
    retired_ec2_host = "sitbank-ec2" + ".tailca101b.ts.net"
    retired_admin_host = "sitbank-admin" + ".tailca101b.ts.net"
    paths = [Path("README.md"), Path("SECURITY.md")]
    paths.extend(
        path
        for path in sorted(Path("docs").rglob("*.md"))
        if "archive" not in path.parts and "codex" not in path.parts
    )
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

    assert "docs/security/governance/security-governance.md" in docs
    assert "Formal ownership and recurring review cadence are documentation follow-up" not in docs
    assert "Assign recurring risk owners outside the repo" not in docs
    assert "formal security ownership is unclear" not in docs
    assert "recurring security review cadence is unclear" not in docs
