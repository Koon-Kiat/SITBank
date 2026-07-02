from __future__ import annotations

from pathlib import Path


DECISION_DOCS = (
    Path("SECURITY.md"),
    Path("docs/OPERATIONS.md"),
    Path("docs/security/architecture/session-management.md"),
    Path("docs/security/architecture/access-control.md"),
    Path("docs/security/architecture/admin-and-staging-zero-trust-access.md"),
    Path("docs/security/governance/design-risk-register.md"),
    Path("docs/security/governance/framework-control-matrix.md"),
    Path("docs/security/governance/security-gap-register.md"),
)


def test_customer_device_bound_session_decision_is_explicit_and_layered():
    docs = "\n".join(path.read_text(encoding="utf-8") for path in DECISION_DOCS)
    normalized = " ".join(docs.casefold().split())

    assert "does not implement cryptographic device-bound sessions" in normalized
    assert "accepted defense-in-depth" in normalized
    assert "risk-based" in normalized
    for required in (
        "server-side session",
        "secure cookies",
        "idle",
        "absolute lifetime",
        "csrf",
        "totp",
        "revocation",
        "audit",
    ):
        assert required in normalized


def test_admin_device_boundary_remains_private_and_layered():
    docs = "\n".join(path.read_text(encoding="utf-8") for path in DECISION_DOCS)
    normalized = " ".join(docs.casefold().split())

    assert "admins connect to the tailscale vpn first" in normalized
    assert "tailscale is the private network/device boundary" in normalized
    assert "does not replace flask admin login, totp, csrf protection" in normalized
    assert "route authorization" in normalized
    assert "audit logging" in normalized
    assert "tailscale funnel" in normalized

    production_nginx = Path("ops/nginx/sitbank-production.conf").read_text(
        encoding="utf-8"
    )
    public_tls = Path(".github/workflows/tls-scan.yml").read_text(
        encoding="utf-8"
    )
    assert "proxy_pass http://127.0.0.1:5002;" not in production_nginx
    assert "tailca101b.ts.net" not in public_tls


def test_private_admin_workflows_use_one_protected_hostname_source():
    manual = Path(
        ".github/workflows/tailscale-private-admin-verify.yml"
    ).read_text(encoding="utf-8")
    deployment = Path(".github/workflows/ci-deploy.yml").read_text(
        encoding="utf-8"
    )

    for workflow in (manual, deployment):
        assert (
            "TAILSCALE_PRIVATE_ADMIN_HOST: "
            "${{ vars.TAILSCALE_PRIVATE_ADMIN_HOST }}"
        ) in workflow
        assert "admin-sitbank.tailca101b.ts.net" not in workflow
        assert "sitbank-ec2" + ".tailca101b.ts.net" not in workflow
    assert "private_admin_host:" not in manual
    assert "environment:\n      name: admin-tailscale" in manual
    assert "environment:\n      name: admin-tailscale" in deployment
    assert "tag:github-ci-admin-verify" in manual
    assert "tag:github-ci-admin-verify" in deployment
