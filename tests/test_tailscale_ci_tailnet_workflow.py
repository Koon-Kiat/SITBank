from __future__ import annotations

import re
from pathlib import Path

import yaml


WORKFLOW_PATH = Path(".github/workflows/tailscale-private-admin-verify.yml")
PUBLIC_TLS_WORKFLOW_PATH = Path(".github/workflows/tls-scan.yml")
PRIVATE_HOST = "sitbank-admin.tailca101b.ts.net"
STALE_PRIVATE_HOST = "sitbank-ec2.tailca101b.ts.net"


def _load_workflow() -> tuple[str, dict]:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    return text, yaml.load(text, Loader=yaml.BaseLoader)


def test_private_tailnet_workflow_is_manual_environment_protected_and_least_privilege():
    text, workflow = _load_workflow()
    triggers = workflow["on"]
    verify = workflow["jobs"]["verify"]

    assert workflow["name"] == "Verify private Tailscale admin access"
    assert set(triggers) == {"workflow_dispatch"}
    assert "pull_request" not in text
    assert "push:" not in text
    assert workflow["permissions"] == {"contents": "read"}
    assert verify["runs-on"] == "ubuntu-24.04"
    assert verify["environment"] == {
        "name": "tailscale-private-admin-verification"
    }
    assert verify["timeout-minutes"] == "10"


def test_private_tailnet_workflow_uses_only_the_protected_tailscale_secret():
    text, workflow = _load_workflow()

    assert "${{ secrets.TAILSCALE_AUTH_KEY }}" in text
    assert set(re.findall(r"secrets\.([A-Z0-9_]+)", text)) == {
        "TAILSCALE_AUTH_KEY"
    }
    assert "env:" in text
    assert "printenv" not in text
    assert "env |" not in text
    assert "set -x" not in text
    assert "actions/checkout" not in text

    uses = [
        step["uses"]
        for step in workflow["jobs"]["verify"]["steps"]
        if "uses" in step
    ]
    assert uses == [
        "tailscale/github-action@306e68a486fd2350f2bfc3b19fcd143891a4a2d8"
    ]
    assert re.fullmatch(r"tailscale/github-action@[0-9a-f]{40}", uses[0])


def test_private_tailnet_workflow_checks_reachability_tls_and_public_admin_denial():
    text, workflow = _load_workflow()
    verify = workflow["jobs"]["verify"]

    assert STALE_PRIVATE_HOST not in text
    assert verify["env"]["PRIVATE_ADMIN_HOST"] == PRIVATE_HOST
    assert verify["env"]["PRIVATE_ADMIN_URL"] == f"https://{PRIVATE_HOST}"
    assert (
        verify["env"]["PUBLIC_ADMIN_DENIAL_URL"]
        == "https://sitbank.duckdns.org/admin"
    )
    assert f"ping: {PRIVATE_HOST}" in text
    assert '"${PRIVATE_ADMIN_URL}/login"' in text
    assert "getent ahostsv4" in text
    assert "--write-out '%{http_code}'" in text
    assert '"${private_status}" != "200"' in text
    assert '"${public_status}" != "404"' in text
    assert "--insecure" not in text
    assert "before joining the tailnet" in text


def test_private_tailnet_workflow_has_no_mutating_or_secret_artifact_operations():
    text = WORKFLOW_PATH.read_text(encoding="utf-8").casefold()

    for forbidden in (
        "tailscale funnel",
        "tailscale serve",
        "tailscale up",
        "upload-artifact",
        "download-artifact",
        "db upgrade",
        "docker run",
        "docker compose",
        "./deploy",
        " deploy ",
        "bootstrap-root-admin",
        "admin_password",
        "admin_username",
        "cookie:",
        "authorization:",
    ):
        assert forbidden not in text
    assert "tailscale logout" in text


def test_public_tls_scan_remains_separate_from_private_tailnet_verification():
    public_tls = PUBLIC_TLS_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert PRIVATE_HOST not in public_tls
    assert STALE_PRIVATE_HOST not in public_tls
    assert "TAILSCALE_AUTH_KEY" not in public_tls
    assert "tailscale/github-action" not in public_tls


def test_docs_describe_option_b_rotation_offboarding_and_scan_separation():
    docs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            Path("docs/DEPLOYMENT.md"),
            Path("docs/GITHUB_ACTIONS.md"),
            Path("docs/OPERATIONS.md"),
            Path("docs/security/admin-and-staging-zero-trust-access.md"),
            Path("docs/security/access-control.md"),
            Path("docs/security/framework-control-matrix.md"),
            Path("docs/security/security-gap-register.md"),
            Path("docs/security/design-risk-register.md"),
            Path("docs/security/threat-model.md"),
            Path("docs/security/test-automation-and-dependencies.md"),
        )
    )

    for required in (
        "GitHub-hosted runner",
        "tailscale-private-admin-verification",
        "TAILSCALE_AUTH_KEY",
        PRIVATE_HOST,
        f"https://{PRIVATE_HOST}",
        "rotation",
        "offboarding",
        "manual approval",
        "public TLS",
        "Tailscale Funnel",
        "Flask admin login",
        "TOTP",
        "must not be used",
    ):
        assert required in docs
    assert (
        f"The retired hostname `{STALE_PRIVATE_HOST}` must not be used"
        in docs
    )
