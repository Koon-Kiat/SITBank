from __future__ import annotations

import re
from pathlib import Path

import yaml


WORKFLOW_PATH = Path(".github/workflows/tailscale-private-admin-verify.yml")
PUBLIC_TLS_WORKFLOW_PATH = Path(".github/workflows/tls-scan.yml")
CI_WORKFLOW_PATH = Path(".github/workflows/ci-deploy.yml")
PRIVATE_HOST = "admin-sitbank.tailca101b.ts.net"
PREVIOUS_PRIVATE_HOST = "sitbank-admin" + ".tailca101b.ts.net"
STALE_PRIVATE_HOST = "sitbank-ec2" + ".tailca101b.ts.net"


def _load_workflow() -> tuple[str, dict]:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    return text, yaml.load(text, Loader=yaml.BaseLoader)


def test_private_tailnet_workflow_is_manual_environment_protected_and_least_privilege():
    text, workflow = _load_workflow()
    triggers = workflow["on"]
    verify = workflow["jobs"]["verify"]

    assert workflow["name"] == "Verify private Tailscale admin access"
    assert set(triggers) == {"workflow_dispatch"}
    dispatch_inputs = triggers["workflow_dispatch"]["inputs"]
    assert set(dispatch_inputs) == {"auth_mode"}
    assert dispatch_inputs["auth_mode"] == {
        "description": "Protected Tailscale credential mode.",
        "required": "true",
        "default": "oauth",
        "type": "choice",
        "options": ["oauth", "authkey"],
    }
    assert "pull_request" not in text
    assert "pull_request_target" not in text
    assert "push:" not in text
    assert workflow["permissions"] == {"contents": "read"}
    assert verify["if"] == "github.ref == 'refs/heads/main'"
    assert verify["runs-on"] == "ubuntu-24.04"
    assert workflow["concurrency"]["group"] == "admin-tailscale-verification"
    assert verify["environment"] == {"name": "admin-tailscale"}
    assert verify["timeout-minutes"] == "10"


def test_private_tailnet_workflow_supports_protected_oauth_and_auth_key_modes():
    text, workflow = _load_workflow()

    assert "authkey: ${{ secrets.TAILSCALE_AUTH_KEY }}" in text
    assert "oauth-client-id: ${{ secrets.TS_OAUTH_CLIENT_ID }}" in text
    assert "oauth-secret: ${{ secrets.TS_OAUTH_SECRET }}" in text
    assert "tags: tag:github-ci-admin-verify" in text
    assert "if: inputs.auth_mode == 'oauth'" in text
    assert "if: inputs.auth_mode == 'authkey'" in text
    assert set(re.findall(r"secrets\.([A-Z0-9_]+)", text)) == {
        "TAILSCALE_AUTH_KEY",
        "TS_OAUTH_CLIENT_ID",
        "TS_OAUTH_SECRET",
    }
    assert "env:" in text
    assert "printenv" not in text
    assert "env |" not in text
    assert "set -x" not in text
    assert "actions/checkout" not in text
    credential_check = next(
        step
        for step in workflow["jobs"]["verify"]["steps"]
        if step["name"] == "Validate selected Tailscale credential"
    )
    assert set(credential_check["env"]) == {
        "TAILSCALE_AUTH_KEY",
        "TS_OAUTH_CLIENT_ID",
        "TS_OAUTH_SECRET",
    }
    assert "OAuth mode requires TS_OAUTH_CLIENT_ID and TS_OAUTH_SECRET" in (
        credential_check["run"]
    )
    assert "Auth-key mode requires TAILSCALE_AUTH_KEY" in credential_check["run"]

    uses = [
        step["uses"]
        for step in workflow["jobs"]["verify"]["steps"]
        if "uses" in step
    ]
    assert uses == [
        "tailscale/github-action@306e68a486fd2350f2bfc3b19fcd143891a4a2d8",
        "tailscale/github-action@306e68a486fd2350f2bfc3b19fcd143891a4a2d8",
    ]
    assert all(
        re.fullmatch(r"tailscale/github-action@[0-9a-f]{40}", action)
        for action in uses
    )


def test_private_tailnet_workflow_checks_private_reachability_and_tls():
    text, workflow = _load_workflow()
    verify = workflow["jobs"]["verify"]

    assert STALE_PRIVATE_HOST not in text
    assert PREVIOUS_PRIVATE_HOST not in text
    assert (
        verify["env"]["TAILSCALE_PRIVATE_ADMIN_HOST"]
        == "${{ vars.TAILSCALE_PRIVATE_ADMIN_HOST }}"
    )
    assert verify["env"]["TAILSCALE_AUTH_MODE"] == "${{ inputs.auth_mode }}"
    assert set(verify["env"]) == {
        "TAILSCALE_PRIVATE_ADMIN_HOST",
        "TAILSCALE_AUTH_MODE",
    }
    assert "ping: ${{ env.TAILSCALE_PRIVATE_ADMIN_HOST }}" in text
    assert "auth_mode must be oauth or authkey" in text
    assert "must be a private Tailscale DNS hostname" in text
    assert "staging-sitbank.pp.ua" in text
    assert '"https://${TAILSCALE_PRIVATE_ADMIN_HOST}/login"' in text
    assert "The admin verification target must be a hostname" in text
    assert "getent ahostsv4" in text
    assert "--request GET" in text
    assert "--head" not in text
    assert "--write-out '%{http_code}'" in text
    assert '"${private_status}" != "200"' in text
    assert "--insecure" not in text
    assert "before joining the tailnet" in text
    assert "Required private admin gate passed." in text
    summary = next(
        step["run"]
        for step in verify["steps"]
        if step["name"] == "Verify private admin entrypoint"
    )
    expected_bullets = (
        'echo "- Private admin is not reachable from the public runner context."\n'
        '  echo "- Protected runner joined the approved tailnet."'
    )
    assert expected_bullets in summary
    assert (
        'echo "- Private admin is not reachable from the public runner context."\n'
        "  echo\n"
    ) not in summary


def test_reference_acl_limits_observability_bootstrap_to_ssh():
    policy = Path("ops/tailscale/acl-policy.hujson").read_text(encoding="utf-8")

    assert (
        '"tag:github-ci-observability-bootstrap": '
        '["group:sitbank-tailnet-owners"]'
    ) in policy
    assert (
        '"src": ["tag:github-ci-observability-bootstrap"],\n'
        '      "dst": ["tag:sitbank-observability-ec2:22"]'
    ) in policy
    assert "tag:sitbank-observability-ec2:443" not in policy
    assert "tag:github-ci-observability-bootstrap:443" not in policy
    assert "*:22" not in policy
    assert '"ssh": []' in policy


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
    assert PREVIOUS_PRIVATE_HOST not in public_tls
    assert STALE_PRIVATE_HOST not in public_tls
    assert "TS_OAUTH_CLIENT_ID" not in public_tls
    assert "TS_OAUTH_SECRET" not in public_tls
    assert "TAILSCALE_AUTH_KEY" not in public_tls
    assert "tailscale/github-action" not in public_tls


def test_production_workflow_requires_private_gate_after_deploy_and_public_tls():
    ci_text = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
    ci = yaml.load(ci_text, Loader=yaml.BaseLoader)
    gate = ci["jobs"]["verify-private-admin-tailnet"]

    assert gate["name"] == "Verify private admin tailnet"
    assert gate["needs"] == ["deploy-production", "verify-production-tls"]
    assert "needs.deploy-production.result == 'success'" in gate["if"]
    assert "needs.verify-production-tls.result == 'success'" in gate["if"]
    assert gate["permissions"] == {"contents": "read"}
    assert gate["environment"] == {"name": "admin-tailscale"}
    assert gate["runs-on"] == "ubuntu-24.04"
    assert gate["timeout-minutes"] == "10"
    assert gate["env"] == {
        "TAILSCALE_PRIVATE_ADMIN_HOST": "${{ vars.TAILSCALE_PRIVATE_ADMIN_HOST }}",
    }
    assert "secrets" not in gate
    validate = gate["steps"][0]
    assert set(validate["env"]) == {"TS_OAUTH_CLIENT_ID", "TS_OAUTH_SECRET"}
    assert "production gate requires TS_OAUTH_CLIENT_ID and TS_OAUTH_SECRET" in (
        validate["run"]
    )
    join = gate["steps"][1]
    assert join["uses"] == (
        "tailscale/github-action@306e68a486fd2350f2bfc3b19fcd143891a4a2d8"
    )
    assert join["with"] == {
        "oauth-client-id": "${{ secrets.TS_OAUTH_CLIENT_ID }}",
        "oauth-secret": "${{ secrets.TS_OAUTH_SECRET }}",
        "tags": "tag:github-ci-admin-verify",
        "ping": "${{ env.TAILSCALE_PRIVATE_ADMIN_HOST }}",
    }
    assert "tailscale logout" in gate["steps"][-1]["run"]
    assert "continue-on-error" not in gate
    assert ci_text.index("verify-production-tls:") < ci_text.index(
        "verify-private-admin-tailnet:"
    )


def test_docs_describe_protected_tailnet_rotation_offboarding_and_scan_separation():
    docs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            Path("docs/DEPLOYMENT.md"),
            Path("docs/GITHUB_ACTIONS.md"),
            Path("docs/OPERATIONS.md"),
            Path("docs/security/architecture/admin-and-staging-zero-trust-access.md"),
            Path("docs/security/architecture/access-control.md"),
            Path("docs/security/governance/framework-control-matrix.md"),
            Path("docs/security/governance/security-gap-register.md"),
            Path("docs/security/governance/design-risk-register.md"),
            Path("docs/security/architecture/threat-model.md"),
            Path("docs/security/assurance/test-automation-and-dependencies.md"),
        )
    )

    for required in (
        "GitHub-hosted runner",
        "admin-tailscale",
        "sitbank-verify-tailscale-admin",
        "TS_OAUTH_CLIENT_ID",
        "TS_OAUTH_SECRET",
        "TAILSCALE_AUTH_KEY",
        PRIVATE_HOST,
        f"https://{PRIVATE_HOST}",
        "rotation",
        "offboarding",
        "manual approval",
        "required protected post-production-deploy gate",
        "after production public TLS verification",
        "public TLS",
        "Tailscale Funnel",
        "Flask admin login",
        "TOTP",
        "must not be used",
    ):
        assert required in docs
    assert PREVIOUS_PRIVATE_HOST not in docs
    assert STALE_PRIVATE_HOST not in docs
