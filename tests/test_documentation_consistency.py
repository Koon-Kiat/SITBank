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
    assert "`410 Gone`" in auth
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
