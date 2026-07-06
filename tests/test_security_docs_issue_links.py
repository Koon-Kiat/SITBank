from __future__ import annotations

import re
from pathlib import Path


GAP_REGISTER = Path("docs/security/governance/security-gap-register.md")
DESIGN_REGISTER = Path("docs/security/governance/design-risk-register.md")
ZERO_TRUST = Path("docs/security/architecture/admin-and-staging-zero-trust-access.md")
SECURITY_DOCS = Path("docs/security")
GLOBAL_RUNBOOK = Path("docs/runbooks/global-verification.md")


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


def _subsection(text: str, heading: str) -> str:
    marker = f"### {heading}"
    start = text.index(marker)
    next_heading = text.find("\n### ", start + len(marker))
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
        ("Authenticated DAST on ordinary pull requests", "Accepted risk / policy tradeoff"),
        ("EC2 SSH/UFW/security-group hardening deferred", "Deferred external prerequisite"),
        ("Device-bound session proof", "Accepted defense-in-depth gap"),
    ):
        row = next(line for line in current_open.splitlines() if title in line)
        assert status in row

    implemented_controls = _section(register, "Implemented Controls")
    assert "Password history and forced password change" in implemented_controls
    assert "Single active customer/admin session cap" in implemented_controls
    assert "Approved preserved-category retention/disposal procedures" in implemented_controls

    recently_closed = _section(register, "Recently Closed Gaps")
    for title in ("Admin dashboard role separation", "Admin audit-log viewer hardening"):
        row = next(line for line in recently_closed.splitlines() if title in line)
        assert "Solved" in row
    row = next(line for line in recently_closed.splitlines() if "Automated retention and disposal jobs" in line)
    assert "Solved" in row

    assert "Separate issue: No" not in register
    assert "Local Docker/Compose proof when Docker is unavailable" not in current_open
    assert "Strict Docker/Compose local CI mode" in register
    assert "Admin audit-log viewer UI hardening follow-up" not in current_open


def test_design_risk_register_uses_current_follow_up_status():
    design = DESIGN_REGISTER.read_text(encoding="utf-8")

    sonar_line = next(
        line for line in design.splitlines() if "Blocking SonarQube quality gate" in line
    )
    assert "Implemented as a blocking trusted-run gate" in sonar_line
    assert "Provider plan, token, and ruleset evidence remain external" in sonar_line
    backup_line = next(
        line for line in design.splitlines() if "Encrypted backup helper" in line
    )
    assert "Backup schedule and restore-drill evidence remain external" in backup_line
    assert "Archive pruning remains operator-approved" in backup_line
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


def test_global_verification_runbook_is_linked_from_main_docs():
    assert GLOBAL_RUNBOOK.is_file()
    for path in (
        Path("README.md"),
        Path("docs/OPERATIONS.md"),
        Path("docs/DEPLOYMENT.md"),
        Path("docs/security/README.md"),
    ):
        text = path.read_text(encoding="utf-8")
        assert "global-verification.md" in text, path


def test_global_verification_runbook_keeps_required_contexts_and_baselines():
    runbook = GLOBAL_RUNBOOK.read_text(encoding="utf-8")

    for heading in (
        "Local Windows/PowerShell Checks",
        "Normal CI-Equivalent Checks",
        "Docker And Image Checks",
        "EC2 Host Checks",
        "Nginx And TLS Checks",
        "Certbot Renewal Checks",
        "Cloudflare Access And Staging Boundary Checks",
        "Tailscale And Private Admin Checks",
        "Database Privilege And Migration-Baseline Checks",
        "Audit Chain, Audit Anchor, And Security Alerts",
        "Backup And Restore Verification",
        "Grafana/Loki Observability Checks",
        "Emergency And Break-Glass Checks",
    ):
        assert f"### {heading}" in runbook

    for required in (
        "git diff --check",
        ".\\.venv\\Scripts\\python.exe -m pytest -q -n auto",
        ".\\.venv\\Scripts\\python.exe -m pytest -q -n auto --cov=. --cov-config=.coveragerc --cov-report=xml:coverage.xml --cov-report=term",
        "python -m flask --app wsgi:app verify-migration-baseline",
        "python -m flask --app wsgi:app verify-runtime-db-privileges",
        "python -m flask --app wsgi:app verify-audit-log-chain",
        "python -m flask --app wsgi:app check-security-alerts --report-only --no-delivery",
        "sudo /usr/local/sbin/verify-tailscale-admin-access --mode serve",
        "sudo certbot certificates",
        "sudo nginx -t",
    ):
        assert required in runbook

    local_section = _subsection(runbook, "Local Windows/PowerShell Checks")
    ec2_section = _subsection(runbook, "EC2 Host Checks")
    assert "sudo " not in local_section
    assert "Run on the relevant EC2 host" in ec2_section
    assert "sudo systemctl" in ec2_section


def test_global_verification_runbook_documents_current_domains_and_path_groups():
    runbook = GLOBAL_RUNBOOK.read_text(encoding="utf-8")

    for required in (
        "sitbank.pp.ua",
        "www.sitbank.pp.ua",
        "staging-sitbank.pp.ua",
        "https://admin-sitbank.tailca101b.ts.net/",
        "/etc/nginx/sites-enabled",
        "/etc/nginx/sites-available",
        "/etc/nginx/snippets",
        "/etc/nginx/conf.d",
        "/var/log/nginx",
        "/etc/letsencrypt/live/sitbank.pp.ua",
        "/etc/letsencrypt/live/staging-sitbank.pp.ua",
        "/etc/letsencrypt/renewal",
        "/etc/letsencrypt/archive",
        "/root/.secrets/certbot/production.ini",
        "/root/.secrets/certbot/staging.ini",
        "/etc/systemd/system/sitbank*.service",
        "/etc/systemd/system/sitbank*.timer",
        "/opt/sitbank-bootstrap",
        "/usr/local/sbin/sitbank-container-deploy",
        "/etc/sudoers.d",
        "/var/lib/sitbank/evidence",
        "/var/backups/sitbank",
        "/root/.config/sitbank-backups/age-identity.txt",
        "/var/lib/sitbank/security-audit.anchor",
        "/run/state/security-alert-state.json",
        "/etc/sitbank-observability",
        "ops/cloudflare/provision-staging-access",
        "ops/tailscale/*",
    ):
        assert required in runbook

    assert "duckdns.org" not in runbook.casefold()
    assert "admin.sitbank.pp.ua" not in runbook
    assert "admin-sitbank.pp.ua" not in runbook


def test_global_verification_runbook_marks_secret_paths_as_not_safe_to_print():
    runbook = GLOBAL_RUNBOOK.read_text(encoding="utf-8")
    lines = runbook.splitlines()

    for path in (
        "/root/.secrets/certbot/production.ini",
        "/root/.secrets/certbot/staging.ini",
        "/etc/sitbank/secrets",
        "/etc/sitbank-staging/secrets",
        "/run/secrets",
        "/root/.config/sitbank-backups/age-identity.txt",
        "/etc/sitbank-observability/secrets",
        "/etc/letsencrypt/archive",
    ):
        assert any(
            path in line and "never print" in line.casefold()
            for line in lines
        ), path


def test_global_verification_runbook_avoids_unsafe_secret_discovery_commands():
    runbook = GLOBAL_RUNBOOK.read_text(encoding="utf-8").casefold()

    for forbidden in (
        "cat /run/secrets",
        "cat /etc/sitbank/secrets",
        "cat /etc/sitbank-staging/secrets",
        "cat /root/.secrets/certbot",
        "cat /root/.config/sitbank-backups/age-identity.txt",
        "printenv",
        "env |",
        "docker inspect",
        "set -x",
        "private key-----",
        "paste raw provider exports",
        "ln -s /etc/letsencrypt",
    ):
        assert forbidden not in runbook


def test_privileged_email_domain_docs_are_workplace_only():
    docs = _docs_text()
    normalized_docs = " ".join(docs.split()).casefold()

    assert "privileged root-admin, admin, and staff accounts use approved sit workplace email domains only" in normalized_docs
    assert "staff invites are delivered to the workplace email and do not collect personal backup email contacts" in normalized_docs
    assert "staff invites use the workplace email and do not collect personal backup email contacts" in normalized_docs
    assert "privileged_email_noncompliant_accounts" in normalized_docs
    assert "does not silently rewrite or delete accounts" in normalized_docs
    assert "staff_invite_personal_email_domains" not in normalized_docs


def test_staff_invite_acceptance_docs_cover_minimal_metadata_and_restart_controls():
    docs = _docs_text()
    normalized_docs = " ".join(docs.split()).casefold()

    for required in (
        "public invite lookup returns only a generic valid-link message",
        "exposes no acceptance metadata, setup state, workplace email, role, status, user id, counter, or lock timestamp",
        "referrer-policy: no-referrer",
        "bound to the browser session that started setup",
        "repeated setup restarts are capped",
        "root-admin totp reset",
        "normal staff/admin invites reject addresses in `root_admin_emails`",
        "delivery state is stored as the allowlisted value `unconfirmed`, `queued`, or `failed`",
        "`queued` means sitbank handed the message to the configured email backend",
        "normal browser get renders the onboarding page while an explicit json client receives the minimal api response",
        "viewing the page leaves the invite pending and creates no account",
        "use the root-admin reissue action to rotate the stored invite token hash",
        "invite is moved out of active pending state so it does not block safe retry",
        "do not repair locked invites by editing production rows ad hoc",
        "staff invite password fields are length-bounded at the request schema",
        "migration `20260704_0026` persists staff invite acceptance session binding",
        "migration `20260707_0032` adds only this bounded delivery state",
        "staff_invite_accept_reset",
    ):
        assert required in normalized_docs

    for stale_claim in (
        "invite lookup exposes workplace email",
        "invite info returns workplace email and role",
        "restarting invite acceptance is unlimited",
    ):
        assert stale_claim not in normalized_docs


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


def test_manual_recovery_docs_cover_browser_root_admin_workflow():
    operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
    combined = " ".join(operations.split())

    for required in (
        "isolated admin browser UI",
        "`GET /manual-recovery/requests`",
        "Accept: application/json",
        "browser CSRF",
        "fresh TOTP code",
        "maker-checker",
        "Unlinked or unknown requests stay generic",
        "Browser admin logout clears the admin session and redirects to `/login`",
    ):
        assert required in combined
    for forbidden in (
        "manual recovery review is JSON-only",
        "complete without approval",
        "complete without TOTP",
    ):
        assert forbidden.casefold() not in combined.casefold()


def test_root_admin_allowlist_docs_treat_identities_as_sensitive_secrets():
    combined = " ".join(
        path.read_text(encoding="utf-8")
        for path in (
            Path("docs/GITHUB_ACTIONS.md"),
            Path("docs/DEPLOYMENT.md"),
            Path("docs/OPERATIONS.md"),
            Path("docs/security/architecture/cloudflare-staging-access.md"),
        )
    )
    normalized = " ".join(combined.split())

    for required in (
        "`STAGING_ROOT_ADMIN_EMAILS`",
        "`PROD_ROOT_ADMIN_EMAILS`",
        "staging must contain exactly 2",
        "production must contain exactly 3",
        "sensitive privileged-identity configuration",
        "/etc/sitbank*/secrets/root_admin_emails",
        "ROOT_ADMIN_EMAILS_FILE",
        "Normal staff/admin invite creation rejects addresses listed in `ROOT_ADMIN_EMAILS`",
        "at least one active MFA-enabled workplace-verified root admin remains available",
        "Do not copy the real allowlist into issues, pull requests, screenshots, logs, or job summaries",
        "without printing the identities",
    ):
        assert required in normalized
    for forbidden in (
        "vars.ROOT_ADMIN_EMAILS",
        "non-secret allowlist",
        "printenv ROOT_ADMIN_EMAILS",
        "protected GitHub environment variable in both `staging` and `production`",
    ):
        assert forbidden.casefold() not in normalized.casefold()


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


def test_audit_anchor_docs_distinguish_stale_drift_from_tampering():
    audit_docs = (
        SECURITY_DOCS / "assurance" / "audit-and-alerting.md"
    ).read_text(encoding="utf-8")
    operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
    runbook = GLOBAL_RUNBOOK.read_text(encoding="utf-8")
    combined = " ".join(f"{audit_docs}\n{operations}\n{runbook}".split())

    for required in (
        "anchor_validated=true",
        "anchor_stale=true",
        "anchor_refresh_required=true",
        "anchor_event_id",
        "latest_event_id",
        "events_since_anchor",
        "normal append-only audit rows",
        "does not emit a critical `audit_anchor_mismatch` alert",
        "audit_chain_verification_failed",
        "event_hash_mismatch",
        "previous_hash_mismatch",
        "unsupported hash algorithms",
        "Do not blindly refresh anchors",
        "preserving evidence",
        "check-security-alerts --report-only --no-delivery",
        "alert_count=0",
    ):
        assert required in combined
    for scheduled_control in (
        "sitbank-audit-anchor-refresh@{staging,production}.timer",
        "refresh-audit-log-anchor",
        "rebaseline-security-alert-state",
        "--intentional-reset",
    ):
        assert scheduled_control in combined

    for forbidden in (
        "refresh anchors until alerts stop",
        "ignore audit_anchor_mismatch",
        "delete the old anchor",
        "overwrite the anchor before preserving evidence",
    ):
        assert forbidden.casefold() not in combined.casefold()


def test_session_management_docs_match_single_session_review_ui():
    template = Path("app/templates/sessions.html").read_text(encoding="utf-8")
    session_docs = (
        SECURITY_DOCS / "architecture" / "session-management.md"
    ).read_text(encoding="utf-8")
    access_docs = (
        SECURITY_DOCS / "architecture" / "access-control.md"
    ).read_text(encoding="utf-8")
    combined = " ".join(f"{session_docs}\n{access_docs}".split()).casefold()

    for required in (
        "only one active customer/admin session is allowed per runtime namespace",
        "a new successful login replaces previous active sessions in that namespace",
        "old browser tabs may still display stale html until the next request",
        "the session-management page is for reviewing the current active session and recent past sessions",
        "protected revoke-other endpoint",
        "not linked from the session-management page",
    ):
        assert required in combined

    assert "Current session" in template
    assert "Past Sessions" in template
    assert "ended_reason_display" in template
    assert "url_for('web.sessions_revoke_others_submit')" not in template
    assert "Revoke all other sessions" not in template
    assert "session-revoke-totp-code" not in template


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


def test_mfa_kek_rotation_docs_match_rewrap_cli_safety():
    operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
    crypto_docs = (
        SECURITY_DOCS / "architecture" / "cryptography-and-authentication.md"
    ).read_text(encoding="utf-8")
    combined = " ".join(f"{operations}\n{crypto_docs}".split())

    for required in (
        "### MFA KEK Rotation",
        "Rotate MFA KEKs in staging first, then production",
        "Target MFA KEK id is not configured",
        "rewrap-mfa-deks --from-kek-id <old-kek-id> --to-kek-id <new-kek-id> --dry-run",
        "commits only if all matching rows rewrap successfully",
        "Remove the old KEK",
        "post-verification action",
        "rollback window",
        "Do not print, paste, or commit KEK values",
        "or decrypted MFA material",
    ):
        assert required in combined
    for forbidden in (
        "cat /etc/sitbank/secrets/mfa_kek_keys_json",
        "print MFA_KEK_KEYS_JSON",
        "echo $MFA_KEK_KEYS_JSON",
    ):
        assert forbidden.casefold() not in combined.casefold()


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
            "feature-security-checklist.md",
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
