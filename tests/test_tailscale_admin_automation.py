from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


TAILSCALE_ROOT = Path("ops/tailscale")
INSTALLER = TAILSCALE_ROOT / "install-tailscale"
CONFIGURATOR = TAILSCALE_ROOT / "configure-admin-access"
VERIFIER = TAILSCALE_ROOT / "verify-admin-access"
README = TAILSCALE_ROOT / "README.md"
POLICY = TAILSCALE_ROOT / "acl-policy.hujson"


def _bash_executable() -> str:
    if os.name != "nt":
        executable = shutil.which("bash")
        if executable:
            return executable
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    git_bash = program_files / "Git" / "bin" / "bash.exe"
    if git_bash.exists():
        return str(git_bash)
    pytest.skip("A Bash implementation is required for script contract tests")


def _run_bash(script: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_bash_executable(), str(script), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def test_tailscale_automation_files_exist_and_are_lf_text():
    attributes = Path(".gitattributes").read_text(encoding="utf-8")

    assert TAILSCALE_ROOT.is_dir()
    for path in (INSTALLER, CONFIGURATOR, VERIFIER, README, POLICY):
        assert path.is_file(), path
        assert b"\r\n" not in path.read_bytes(), path
    for path in (INSTALLER, CONFIGURATOR, VERIFIER):
        assert path.read_text(encoding="utf-8").startswith(
            "#!/usr/bin/env bash\n"
        )
    assert "ops/tailscale/* text eol=lf" in attributes


def test_install_dry_run_is_non_mutating_and_confirmation_is_mandatory():
    installer = INSTALLER.read_text(encoding="utf-8")
    dry_run = _run_bash(INSTALLER, "--dry-run")
    no_mode = _run_bash(INSTALLER)

    assert dry_run.returncode == 0
    assert "PLAN:" in dry_run.stdout
    assert "Do not authenticate a node" in dry_run.stdout
    assert no_mode.returncode == 2
    assert "Choose exactly one" in no_mode.stderr
    assert installer.index('if [[ "${dry_run}" -eq 1 ]]') < installer.index(
        "curl --fail"
    )
    assert installer.index('if [[ "${EUID}" -ne 0 ]]') < installer.index(
        "apt-get update"
    )
    assert re.search(r'KEY_SHA256="[0-9a-f]{64}"', installer)
    assert re.search(r'LIST_SHA256="[0-9a-f]{64}"', installer)
    assert "curl -fsSL https://tailscale.com/install.sh | sh" not in installer
    assert "tailscale up" not in installer
    assert "tailscale serve" not in installer
    assert "tailscale funnel" not in installer


@pytest.mark.parametrize("auth_mode", ("oauth", "authkey", "interactive"))
def test_configure_dry_run_supports_every_explicit_auth_mode_without_secrets(
    auth_mode: str,
):
    result = _run_bash(
        CONFIGURATOR,
        "--dry-run",
        "--auth-mode",
        auth_mode,
    )

    assert result.returncode == 0
    assert f"Authentication mode: {auth_mode}" in result.stdout
    assert "http://127.0.0.1:5002" in result.stdout
    assert "No customer or staging service is exposed." in result.stdout
    assert "tskey-" not in result.stdout


def test_configure_script_requires_confirmation_and_handles_both_secret_modes_safely():
    script = CONFIGURATOR.read_text(encoding="utf-8")

    assert "--dry-run" in script
    assert "--confirm" in script
    assert "--auth-mode" in script
    assert "oauth|authkey|interactive" in script
    assert 'client_id="${TS_OAUTH_CLIENT_ID:-}"' in script
    assert 'client_secret="${TS_OAUTH_SECRET:-}"' in script
    assert 'auth_key="${TAILSCALE_AUTH_KEY:-}"' in script
    assert "--client-secret=file:/dev/fd/3" in script
    assert "--auth-key=file:/dev/fd/3" in script
    assert '3<<<"${client_secret}"' in script
    assert '3<<<"${auth_key}"' in script
    assert "set -x" not in script
    assert "printenv" not in script
    assert "env |" not in script
    assert not re.search(r"(?m)^\s*(?:export\s+)?TAILSCALE_AUTH_KEY=.+$", script)
    assert not re.search(r"(?m)^\s*(?:export\s+)?TS_OAUTH_SECRET=.+$", script)
    assert not re.search(r"tskey-(?:auth|client)-[A-Za-z0-9_-]+", script)

    confirmation_gate = script.index('if [[ "${dry_run}" -eq 1 ]]')
    mutation = script.index("tailscale up")
    assert confirmation_gate < mutation


def test_configure_script_fails_closed_around_serve_funnel_and_bindings():
    script = CONFIGURATOR.read_text(encoding="utf-8")

    assert 'ADMIN_TARGET="http://127.0.0.1:5002"' in script
    assert '"${verifier}" --mode ssh' in script
    assert '"${verifier}" --mode serve' in script
    assert "tailscale serve status --json" in script
    assert "Existing Serve configuration is non-empty" in script
    assert "tailscale serve --bg --https=443" in script
    assert "tailscale serve --https=443 off" in script
    assert "tailscale funnel " not in script
    assert "0.0.0.0" not in script
    assert "[::]" not in script
    assert "127.0.0.1:5000" not in script
    assert "127.0.0.1:5003" not in script
    assert "--advertise-exit-node=false" in script
    assert "--advertise-routes=" in script
    assert "--ssh=false" in script


def test_verify_wrapper_delegates_to_one_canonical_non_mutating_verifier():
    wrapper = VERIFIER.read_text(encoding="utf-8")

    assert "/usr/local/sbin/verify-tailscale-admin-access" in wrapper
    assert "ops/deploy/verify-tailscale-admin-access" in wrapper
    assert 'exec "${verifier}" --mode "${mode}"' in wrapper
    for forbidden in (
        "tailscale up",
        "tailscale serve",
        "tailscale funnel",
        "systemctl",
        "apt-get",
    ):
        assert forbidden not in wrapper


def test_reference_policy_separates_admin_and_environment_deploy_paths():
    policy = POLICY.read_text(encoding="utf-8")

    assert "group:sitbank-production-admins" in policy
    assert '"tag:admin-sitbank:443"' in policy
    assert '"tag:github-ci-admin-verify"' in policy
    assert '"tag:github-ci-staging-deploy"' in policy
    assert '"tag:sitbank-staging-ec2:22"' in policy
    assert '"tag:github-ci-prod-deploy"' in policy
    assert '"tag:sitbank-prod-ec2:22"' in policy
    assert '"tag:github-ci-observability-bootstrap"' in policy
    assert '"tag:sitbank-observability-ec2:22"' in policy
    assert '"ssh": []' in policy
    assert "autogroup:member" not in policy
    assert "autogroup:internet" not in policy
    assert '"*"' not in policy
    assert "0.0.0.0/0" not in policy
    assert "tag:admin-sitbank:*" not in policy
    assert "staging-admin" not in policy

    acl_paths = set(
        re.findall(
            r'"src": \["([^"]+)"\],\s+"dst": \["([^"]+)"\]',
            policy,
        )
    )
    assert acl_paths == {
        ("group:sitbank-production-admins", "tag:admin-sitbank:443"),
        ("tag:github-ci-admin-verify", "tag:admin-sitbank:443"),
        ("tag:github-ci-staging-deploy", "tag:sitbank-staging-ec2:22"),
        ("tag:github-ci-prod-deploy", "tag:sitbank-prod-ec2:22"),
        (
            "tag:github-ci-observability-bootstrap",
            "tag:sitbank-observability-ec2:22",
        ),
    }


def test_admin_configurator_uses_the_canonical_destination_tag():
    script = CONFIGURATOR.read_text(encoding="utf-8")

    assert 'readonly ADMIN_TAG="tag:admin-sitbank"' in script
    assert "tag:sitbank-admin" not in script


def test_production_bootstrap_installs_scripts_without_running_them():
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(
        encoding="utf-8"
    )

    for source in (
        "ops/tailscale/install-tailscale",
        "ops/tailscale/configure-admin-access",
        "ops/tailscale/verify-admin-access",
    ):
        assert f'"${{repo_root}}/{source}"' in bootstrap
    for destination in (
        "/usr/local/sbin/sitbank-install-tailscale",
        "/usr/local/sbin/sitbank-configure-tailscale-admin",
        "/usr/local/sbin/sitbank-verify-tailscale-admin",
    ):
        assert destination in bootstrap
    assert "install -o root -g root -m 0755" in bootstrap
    assert "/usr/local/sbin/sitbank-configure-tailscale-admin --confirm" not in bootstrap


def test_readme_documents_primary_model_credentials_and_evidence_boundaries():
    readme = README.read_text(encoding="utf-8")

    for required in (
        "private HTTPS through Tailscale Serve",
        "https://admin-sitbank.tailca101b.ts.net/",
        "http://127.0.0.1:5002",
        "There is no public admin hostname.",
        "Tailscale Funnel is forbidden.",
        "TS_OAUTH_CLIENT_ID",
        "TS_OAUTH_SECRET",
        "TAILSCALE_AUTH_KEY",
        "--auth-mode oauth",
        "--auth-mode authkey",
        "Flask admin password login and TOTP",
        "Onboarding",
        "Offboarding",
        "Emergency Disable",
        "protected GitHub workflow",
        "operator-reviewed external state",
    ):
        assert required in readme
    assert "Staging private admin access is not configured" in readme
    assert "SSH/port-forward remains fallback diagnostics only" in readme
    assert "admin-sitbank" + ".duckdns.org" not in readme


def test_repository_docs_distinguish_provisioning_preflight_and_ci_reachability():
    paths = (
        Path("README.md"),
        Path("SECURITY.md"),
        Path("docs/DEPLOYMENT.md"),
        Path("docs/OPERATIONS.md"),
        Path("docs/GITHUB_ACTIONS.md"),
        Path("docs/security/architecture/admin-and-staging-zero-trust-access.md"),
        Path("docs/security/architecture/access-control.md"),
        Path("docs/security/governance/framework-control-matrix.md"),
        Path("docs/security/governance/security-gap-register.md"),
        Path("docs/security/governance/design-risk-register.md"),
        Path("docs/security/architecture/threat-model.md"),
        Path("docs/security/assurance/test-automation-and-dependencies.md"),
    )
    docs = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    normalized_docs = " ".join(docs.split())

    for required in (
        "ops/tailscale/",
        "sitbank-install-tailscale",
        "sitbank-configure-tailscale-admin",
        "sitbank-verify-tailscale-admin",
        "acl-policy.hujson",
        "auth_mode: oauth",
        "TAILSCALE_AUTH_KEY",
        "TS_OAUTH_CLIENT_ID",
        "TS_OAUTH_SECRET",
        "--auth-mode oauth",
        "--auth-mode authkey",
        "--dry-run",
        "--confirm",
        "127.0.0.1:5002",
        "normal CI",
        "operator-owned",
        "Flask admin login",
        "TOTP",
    ):
        assert required in docs
    assert "live provisioning plus ACL" not in docs
    assert "admin-sitbank" + ".duckdns.org" not in docs
    assert "Staging admin is deliberately not configured" in normalized_docs
