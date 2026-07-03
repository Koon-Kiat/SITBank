from pathlib import Path


def test_public_repository_and_readme_index_wording_is_current():
    sonarqube = Path("docs/security/assurance/sonarqube.md").read_text(
        encoding="utf-8"
    )
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "Mode And Private-Repository Decision" not in sonarqube
    assert "private `Koon-Kiat/SITBank`" not in sonarqube
    assert "`Koon-Kiat/SITBank` is public" in sonarqube
    assert "[SonarQube Cloud](" in readme
    assert "[Secret scanning](" in readme
    assert "Archived EC2 transition notes" not in readme


def test_turnstile_docs_match_deployment_wiring_without_secret_values():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in ("docs/DEPLOYMENT.md", "docs/OPERATIONS.md")
    )

    assert "TURNSTILE_*_ENABLED" in docs
    assert "PROD_TURNSTILE_SECRET_KEY" in docs
    assert "STAGING_TURNSTILE_SECRET_KEY" in docs
    assert "TURNSTILE_SECRET_KEY_FILE=/run/secrets/turnstile_secret_key" in docs
    assert "admin app remains private behind Tailscale" in docs
    assert "TURNSTILE_CUSTOMER_MANUAL_RECOVERY_ENABLED" in docs
    assert "TURNSTILE_FAIL_CLOSED_IN_PRODUCTION" in docs
    assert "Keep both\nadmin route flags false" not in docs


def test_root_admin_docs_match_environment_specific_counts():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "docs/DEPLOYMENT.md",
            "docs/GITHUB_ACTIONS.md",
            "docs/OPERATIONS.md",
        )
    )
    docs = " ".join(docs.split())

    assert "exactly 7" not in docs
    assert "STAGING_ROOT_ADMIN_EMAILS" in docs
    assert "PROD_ROOT_ADMIN_EMAILS" in docs
    assert "exactly 2" in docs
    assert "exactly 5" in docs


def test_authentication_boundary_docs_cover_current_contracts():
    auth = Path(
        "docs/security/architecture/cryptography-and-authentication.md"
    ).read_text(encoding="utf-8")
    operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")

    assert "scanner-safe GET landing page" in auth
    assert "CSRF-protected POST" in auth
    assert "user-and-purpose-bound HMACs" in auth
    assert "Retired browser-credential reset URLs are not" in auth
    assert "registered and return `404`" in auth
    assert "canonicalized before OTP issuance" in operations
    assert "temporary-email domains are rejected" in operations


def test_private_admin_docs_reject_wildcard_public_https():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    architecture = Path(
        "docs/security/architecture/admin-and-staging-zero-trust-access.md"
    ).read_text(encoding="utf-8")

    assert "`PUBLIC_BIND_ADDRESS`" in deployment
    assert "without wildcard public listeners" in deployment
    assert "reject wildcard\nport `443`" in architecture


def test_payup_security_docs_match_current_banking_contract():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "docs/OPERATIONS.md",
            "docs/DEPLOYMENT.md",
            "docs/security/architecture/access-control.md",
            "docs/security/assurance/secure-coding.md",
            "docs/security/assurance/feature-security-checklist.md",
        )
    )
    docs = " ".join(docs.split())

    for required in (
        "PayUp lookup requires an authenticator code",
        "Invalid phone number",
        "daily limit stored on `users.payup_daily_limit`",
        "midnight Singapore time",
        "at least 80% of the limit",
        "The Local Transfer daily limit remains a documented placeholder",
        "keyed verifier",
        "HMAC-SHA256 transaction hash",
        "Migration `20260703_0022` adds PayUp support",
        "`payup_pending_transfers`",
        "`transactions.transaction_type`",
        "Migration `20260703_0024` enforces exactly 12 decimal digits",
        "account numbers are exactly 12 decimal digits",
    ):
        assert required in docs

    stale_phrases = (
        "PayUp lookup reveals recipient name before MFA",
        "PayUp lookup does not require MFA",
        "Local Transfer daily limit is enforced",
    )
    for stale in stale_phrases:
        assert stale not in docs


def test_auth_schema_reset_and_customer_unlock_docs_match_current_contract():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "docs/DEPLOYMENT.md",
            "docs/OPERATIONS.md",
            "docs/security/architecture/access-control.md",
            "docs/security/architecture/session-management.md",
            "docs/security/governance/legacy-and-out-of-scope-technology.md",
        )
    )

    for required in (
        "reset-demo-database --target staging",
        'RESET STAGING DEMO DATABASE"',
        "reset-demo-database --target production",
        "--staging-verified --approved --backup-file",
        "exactly 12 decimal digits",
        "different active\nroot admin",
        "missing, malformed, or unsupported structured context",
        "retired URLs are unregistered",
    ):
        assert required in docs
    for stale in (
        "legacy 9-digit rows remain valid",
        "A matching legacy `risk_fingerprint` is accepted",
        "disabled\ncompatibility code",
        "`staff_invites.personal_email_normalized` nullable",
    ):
        assert stale not in docs


def test_feature_security_checklist_is_indexed_and_avoids_external_overclaims():
    index = Path("docs/security/README.md").read_text(encoding="utf-8")
    checklist = Path("docs/security/assurance/feature-security-checklist.md").read_text(
        encoding="utf-8"
    )

    assert "Feature security checklist" in index
    for required in (
        "Current Feature Status",
        "PayUp",
        "Root-admin bootstrap and allowlist",
        "Staff/admin maker-checker",
        "Browser E2E",
        "do not prove live staging or production provider state",
        "stale-documentation test",
    ):
        assert required in checklist
    for forbidden in (
        "live provider state is verified",
        "branch protection is enforced",
        "SonarQube gate is passing",
    ):
        assert forbidden not in checklist
