from pathlib import Path


PRIVACY = Path("docs/security/governance/privacy-and-pdpa.md")
RETENTION = Path("docs/security/governance/data-retention-and-deactivation.md")
INCIDENT = Path("docs/security/governance/incident-response.md")
GAP_REGISTER = Path("docs/security/governance/security-gap-register.md")
FRAMEWORK = Path("docs/security/governance/framework-control-matrix.md")


def _normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_privacy_pdpa_docs_exist_and_cover_data_categories():
    text = _normalized(PRIVACY)

    for required in (
        "Customer name",
        "Customer email",
        "Customer phone",
        "Account identifiers",
        "Payee records",
        "Transaction records",
        "Staff/admin identity",
        "Staff/admin workplace email",
        "Staff invite metadata",
        "Audit event metadata",
        "Alert metadata",
        "Session/security metadata",
        "Backup data",
        "Protected health or medical data is Not applicable",
        "Health/medical data must not be added without a separate privacy and security review",
    ):
        assert required in text


def test_privacy_docs_forbid_raw_secret_logging_and_describe_redaction():
    text = _normalized(PRIVACY)

    for required in (
        "Do not log, paste, or send through alert channels",
        "passwords",
        "TOTP codes",
        "recovery codes",
        "raw session IDs",
        "CSRF tokens",
        "private SSH keys",
        "database dumps",
        "sanitizes audit metadata",
        "final sanitization pass before webhook delivery",
        "audit_reference()",
        "principal_reference()",
    ):
        assert required in text


def test_retention_doc_distinguishes_deactivation_deletion_and_anonymization():
    text = _normalized(RETENTION)

    for required in (
        "Deactivation",
        "Deletion",
        "Anonymization",
        "Not exposed as a normal customer/admin self-service feature",
        "No automated workflow exists",
        "Security audit rows must not be silently auto-deleted",
        "Approved Preserved-Category Procedures",
        "operator-approved maintenance record",
        "Customer and staff/admin account records",
        "Manual recovery requests",
        "Staff invite metadata",
        "Alert reports",
        "Encrypted backup archives",
        "No weekly timer or application route performs destructive disposal",
        "category allowlist",
        "No complete retention/disposal scheduler across those preserved categories exists by design",
    ):
        assert required in text
    for scheduled_control in (
        "sitbank-retention-review@staging.timer",
        "sitbank-retention-review@production.timer",
        "aggregate-only dry-run report",
        "timer never passes that flag",
        "future scheduler must be reviewed as a new change",
    ):
        assert scheduled_control in text


def test_incident_response_doc_covers_required_workflows_and_evidence_rules():
    text = _normalized(INCIDENT)

    for required in (
        "Suspected Data Breach",
        "Suspicious Admin Action",
        "Audit Chain Degradation",
        "Alert Delivery Failure",
        "Leaked Secret",
        "Compromised Customer Account",
        "Compromised Staff/Admin Account",
        "Backup Exposure",
        "who took each action",
        "Never share passwords",
        "Do not run manual SQL updates or deletes against `security_audit_events`",
        "Do not delete or anonymize accounts during active investigation",
    ):
        assert required in text


def test_security_docs_link_privacy_retention_and_incident_response():
    for path in (
        Path("SECURITY.md"),
        Path("docs/OPERATIONS.md"),
        Path("docs/security/architecture/access-control.md"),
        Path("docs/security/assurance/audit-and-alerting.md"),
        FRAMEWORK,
    ):
        text = path.read_text(encoding="utf-8")
        assert "docs/security/governance/privacy-and-pdpa.md" in text, path
        assert "docs/security/governance/data-retention-and-deactivation.md" in text, path
        assert "docs/security/governance/incident-response.md" in text, path


def test_gap_register_updated_for_privacy_docs_and_retention_automation_gap():
    register = GAP_REGISTER.read_text(encoding="utf-8")
    current_open = register.split("## Current Open Gaps", 1)[1].split("## Partially Implemented Controls", 1)[0]
    implemented = register.split("## Implemented Controls", 1)[1].split("## Not Applicable Or Out Of Scope", 1)[0]
    recently_closed = register.split("## Recently Closed Gaps", 1)[1]

    assert "PDPA data inventory and retention schedule" not in current_open
    assert "Dedicated incident response runbook" not in current_open
    assert "Automated retention and disposal jobs" not in current_open
    assert "Approved preserved-category retention/disposal procedures" in implemented
    assert "Automated retention and disposal jobs" in recently_closed
    assert "Privacy and PDPA documentation" in register
    assert "Incident response runbook" in register
