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
