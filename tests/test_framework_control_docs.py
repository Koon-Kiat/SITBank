from pathlib import Path


MATRIX = Path("docs/security/framework-control-matrix.md")
GAP_REGISTER = Path("docs/security/security-gap-register.md")
LINKED_DOCS = [
    Path("README.md"),
    Path("SECURITY.md"),
    Path("docs/security/security-governance.md"),
    Path("docs/security/secure-coding.md"),
    Path("docs/security/access-control.md"),
    Path("docs/security/session-management.md"),
    Path("docs/security/cryptography-and-authentication.md"),
]


def _normalized(text: str) -> str:
    return " ".join(text.split())


def _section(text: str, heading: str) -> str:
    marker = f"## {heading}"
    start = text.index(marker)
    next_heading = text.find("\n## ", start + len(marker))
    return text[start:] if next_heading == -1 else text[start:next_heading]


def test_framework_control_matrix_covers_requested_frameworks_and_statuses():
    matrix = MATRIX.read_text(encoding="utf-8")

    for framework in (
        "OWASP ASVS 5.0.0",
        "OWASP Top 10 2025",
        "NIST SP 800-218 SSDF",
        "OWASP SAMM",
        "Singapore PDPA",
        "OWASP API Security Top 10",
        "CIS Controls v8",
        "NIST SP 800-63B",
        "MAS TRM / MAS Cyber Hygiene",
        "CWE Top 25",
    ):
        assert framework in matrix

    for status in (
        "Implemented",
        "Partially implemented",
        "Not applicable",
        "Open gap",
        "Needs verification",
    ):
        assert status in matrix

    for evidence in (
        "tests/test_payee_management_security.py",
        "tests/test_session_absolute_lifetime.py",
        "tests/test_admin_route_inventory_security.py",
        "tests/test_backup_security.py",
        "tests/test_audit_alerting.py",
    ):
        assert evidence in matrix


def test_security_gap_register_is_single_source_with_required_fields():
    register = GAP_REGISTER.read_text(encoding="utf-8")
    current_open = _section(register, "Current Open Gaps")

    for required_column in (
        "Owner role",
        "Status / tracking",
        "Framework mapping",
        "Risk level",
        "Current evidence",
        "Recommended fix / next action",
        "Relevant files/tests",
        "Review trigger",
    ):
        assert required_column in current_open

    for open_gap in (
        "Password history beyond current-password reuse",
        "Automated retention and disposal jobs",
        "Authenticated DAST on ordinary pull requests",
        "EC2 SSH/UFW/security-group hardening deferred",
        "Active-session count cap",
        "Device-bound session proof",
    ):
        assert open_gap in current_open

    assert "Local Docker/Compose proof when Docker is unavailable" not in current_open
    assert "Admin audit-log viewer UI hardening follow-up" not in current_open

    for fixed_item in (
        "independent absolute maximum lifetime",
        "generated admin route authorization inventory policy",
        "fresh TOTP step-up before recovery-code regeneration",
        "admin manual recovery review/completion routes",
        "safer production payee cooldown minimum",
        "production startup fail-closed security guard",
        "dedicated payee IDOR regression test missing",
        "backup encryption and restore access-control evidence missing",
        "PDPA data inventory and retention schedule",
        "Dedicated incident response runbook",
        "Threat model and design risk record",
    ):
        assert fixed_item not in current_open

    implemented = _section(register, "Implemented Controls")
    assert "Absolute authenticated session lifetime" in implemented
    assert "Generated admin route inventory" in implemented
    assert "Payee IDOR and enumeration regression tests" in implemented
    assert "Encrypted database backup tooling" in implemented
    assert "Audit review workflow" in implemented
    assert "Admin dashboard separation of duties" in implemented
    assert "Privacy and PDPA documentation" in implemented
    assert "Incident response runbook" in implemented
    assert "Threat model and design risk register" in implemented
    assert "Security governance process" in implemented
    assert "Strict Docker/Compose local CI mode" in implemented
    assert "EC2 Tailscale admin host preflight" in implemented
    assert "Tailscale production-admin provisioning automation" in implemented
    recently_closed = _section(register, "Recently Closed Gaps")
    assert "Admin audit-log viewer UI" in recently_closed
    assert "Admin dashboard role separation" in recently_closed
    assert "Admin audit-log viewer hardening" in recently_closed


def test_issue_186_ssh_hardening_is_deferred_without_stale_artifacts():
    register = GAP_REGISTER.read_text(encoding="utf-8")
    matrix = MATRIX.read_text(encoding="utf-8")
    current_open = _section(register, "Current Open Gaps")
    recently_closed = _section(register, "Recently Closed Gaps")

    assert "EC2 SSH/UFW/security-group hardening deferred" in current_open
    assert "No OpenSSH drop-in, UFW rollout" in current_open
    assert "EC2 SSH hardening lacked repository-side support" not in recently_closed
    assert "tests/test_ec2_ssh_hardening_docs.py" not in matrix
    assert "ops/ssh/99-sitbank-hardening.conf" not in matrix
    assert "OpenSSH drop-in template" not in matrix
    assert not Path("tests/test_ec2_ssh_hardening_docs.py").exists()
    assert not Path("ops/ssh/99-sitbank-hardening.conf").exists()
    assert not Path("docs/security/ec2-ssh-and-deployment-access.md").exists()


def test_requested_docs_link_to_matrix_and_gap_register():
    for path in LINKED_DOCS:
        text = path.read_text(encoding="utf-8")
        assert "docs/security/security-gap-register.md" in text, path
        assert "docs/security/framework-control-matrix.md" in text, path


def test_active_security_docs_do_not_have_scattered_current_gap_tables():
    active_docs = [
        path
        for path in Path("docs").rglob("*.md")
        if path != GAP_REGISTER
    ] + [Path("README.md"), Path("SECURITY.md")]
    combined = _normalized(
        "\n".join(path.read_text(encoding="utf-8") for path in active_docs)
    ).lower()

    assert "current gap:" not in combined
    assert "current test gap:" not in combined
    assert "no generated admin route inventory" not in combined
    assert "no independent absolute lifetime" not in combined
