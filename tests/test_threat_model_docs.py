from pathlib import Path


THREAT_MODEL = Path("docs/security/threat-model.md")
DESIGN_REGISTER = Path("docs/security/design-risk-register.md")
FRAMEWORK = Path("docs/security/framework-control-matrix.md")
GAP_REGISTER = Path("docs/security/security-gap-register.md")


def _normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_threat_model_exists_and_covers_major_risks():
    text = _normalized(THREAT_MODEL)

    for required in (
        "Customer account takeover",
        "Staff/admin account takeover",
        "Admin/customer boundary bypass",
        "Session theft or fixation",
        "CSRF on state-changing routes",
        "IDOR/object-level authorization",
        "MFA bypass",
        "Password reset or manual recovery abuse",
        "Audit log tampering",
        "Alert tampering or failure",
        "Backup exposure",
        "Deployment compromise",
        "CI/CD compromise",
        "Public EC2 edge exposure",
        "Staging/admin exposure",
        "Data retention/privacy failure",
    ):
        assert required in text

    for column in (
        "Asset",
        "Attacker",
        "Attack path",
        "Existing controls",
        "Tests/evidence",
        "Remaining gap",
        "Priority",
    ):
        assert column in text


def test_design_risk_register_covers_required_decisions():
    text = _normalized(DESIGN_REGISTER)

    for required in (
        "Separate admin/customer deployment boundary",
        "TOTP baseline MFA",
        "No WebAuthn/passkeys in approved staff/admin flow",
        "PostgreSQL-backed server-side session architecture",
        "Production startup fail-closed guard",
        "Admin route inventory testing",
        "Audit hash/HMAC integrity",
        "Zero-trust/private admin-staging access direction",
        "Read-only EC2 Tailscale admin preflight",
        "GitHub-hosted runner SSH conflict",
        "Reporting-only SonarQube initial rollout",
        "Design decision",
        "Security impact",
        "Accepted risk",
        "Related framework controls",
        "Owner role",
        "Status / tracking",
        "Review trigger",
    ):
        assert required in text


def test_framework_and_gap_docs_reference_threat_model_and_design_risks():
    for path in (
        Path("SECURITY.md"),
        Path("docs/security/secure-coding.md"),
        FRAMEWORK,
        GAP_REGISTER,
        Path("docs/security/security-governance.md"),
    ):
        text = path.read_text(encoding="utf-8")
        assert "docs/security/threat-model.md" in text, path
        assert "docs/security/design-risk-register.md" in text, path


def test_gap_register_closes_threat_model_gap_but_keeps_other_open_items():
    register = GAP_REGISTER.read_text(encoding="utf-8")
    current_open = register.split("## Current Open Gaps", 1)[1].split("## Partially Implemented Controls", 1)[0]
    implemented = register.split("## Implemented Controls", 1)[1].split("## Not Applicable Or Out Of Scope", 1)[0]

    assert "Threat model and design risk record" not in current_open
    assert "Automated retention and disposal jobs" in current_open
    assert "Threat model and design risk register" in implemented
