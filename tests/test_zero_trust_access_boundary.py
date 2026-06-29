from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml


def _docs_text() -> str:
    paths = [Path("README.md"), Path("SECURITY.md")]
    paths.extend(sorted(Path("docs").rglob("*.md")))
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def _nginx_location_bodies(config: str, selector: str) -> list[str]:
    return re.findall(
        rf"location\s+{re.escape(selector)}\s*\{{(.*?)\n\s*\}}",
        config,
        flags=re.DOTALL,
    )


def _nginx_server_block(config: str, server_name: str) -> str:
    marker = re.compile(
        rf"server_name\s+[^;]*(?<![A-Za-z0-9.-]){re.escape(server_name)}"
        r"(?![A-Za-z0-9.-])[^;]*;"
    )
    blocks = []
    for match in marker.finditer(config):
        marker_index = match.start()
        start = config.rfind("\nserver {", 0, marker_index)
        start = 0 if start == -1 else start + 1
        end = config.find("\nserver {", marker_index)
        blocks.append(config[start:] if end == -1 else config[start:end])
    assert blocks, f"Missing Nginx server block for {server_name}"
    for block in blocks:
        if "listen 443 ssl http2;" in block:
            return block
    return blocks[0]


def _tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [Path(item.decode("utf-8")) for item in result.stdout.split(b"\0") if item]


def test_hybrid_cloudflare_staging_and_tailscale_admin_design_is_documented():
    docs = _docs_text()
    normalized_docs = " ".join(docs.split())

    for required in (
        "SITBank uses a hybrid zero-trust access model",
        "Staging uses a Cloudflare-managed public hostname with Cloudflare Access",
        "Admin access is private through Tailscale",
        "Implemented repository controls include",
        "Protected GitHub CI tailnet verification is implemented only by",
        "EC2 Host-Side Tailscale Preflight",
        "EC2 Tailscale Provisioning Automation",
        "verify-tailscale-admin-access --mode serve",
        "admin-tailscale",
        "TS_OAUTH_CLIENT_ID",
        "TS_OAUTH_SECRET",
        "This intentionally uses both products because the surfaces have different",
        "Production customer | `https://sitbank.duckdns.org`",
        "Staging customer | `https://staging-sitbank.pp.ua`",
        "Production admin app | `https://admin-sitbank.tailca101b.ts.net/` through Tailscale Serve",
        "The customer production site remains public.",
        "self-hosted Access application",
        "Cloudflare Authenticated Origin Pulls",
        "Do not enable Tailscale Funnel",
        "Flask admin login and TOTP remain mandatory",
        "onboarding, offboarding, emergency lockout, rollback",
        "local readiness succeeds through loopback",
        "direct Nginx origin access",
        "Cloudflare-managed zone/hostname or Cloudflare Tunnel",
        "Cloudflare Access and Tailscale decide whether a request may reach",
        "retired DuckDNS staging hostname is no longer",
        "Admins connect to the Tailscale VPN first, then open",
        "https://admin-sitbank.tailca101b.ts.net/",
        "old public admin verification",
        "page has been removed from the edge bootstrap",
        "No public admin hostname or Nginx admin upstream is configured",
        "Zero-trust and network-boundary work should use these repository labels",
    ):
        assert required in docs

    assert "temporarily join a GitHub-hosted runner to the tailnet" in normalized_docs
    assert "does not replace Flask admin login, TOTP, CSRF protection" in normalized_docs
    assert "staging is documented/configured as public-only" not in docs.lower()
    assert "admin is documented/configured as public-only" not in docs.lower()


def test_staging_nginx_blocks_direct_origin_bypass_but_keeps_local_health():
    default_nginx = Path("ops/nginx/sitbank-default.conf").read_text(encoding="utf-8")
    staging_nginx = Path("ops/nginx/sitbank-staging.conf").read_text(encoding="utf-8")
    access_headers = Path(
        "ops/nginx/sitbank-cloudflare-access-headers.conf"
    ).read_text(encoding="utf-8")
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(encoding="utf-8")

    assert "listen 80 default_server;" in default_nginx
    assert "listen 443 ssl http2 default_server;" in default_nginx
    assert "ssl_reject_handshake on;" in default_nginx
    assert "return 444;" in default_nginx

    assert "server_name staging-sitbank.pp.ua;" in staging_nginx
    assert "duckdns.org" not in staging_nginx
    assert "ssl_client_certificate /etc/nginx/cloudflare-authenticated-origin-pull-ca.pem;" in staging_nginx
    assert "ssl_verify_client optional;" in staging_nginx
    staging_https_prelocation = _nginx_server_block(
        staging_nginx,
        "staging-sitbank.pp.ua",
    ).split("\n    location ", 1)[0]
    assert "auth_basic \"SITBank staging\";" not in staging_https_prelocation
    assert "auth_basic_user_file /etc/nginx/.htpasswd-sitbank-staging;" not in staging_https_prelocation

    for selector in (
        "= /health/live",
        "= /login",
        "= /register",
        "= /mfa/verify",
        "^~ /auth/",
        "/",
    ):
        bodies = _nginx_location_bodies(staging_nginx, selector)
        assert bodies, f"Missing staging Nginx location {selector}"
        protected_bodies = [
            body for body in bodies if "$ssl_client_verify != SUCCESS" in body
        ]
        assert protected_bodies, f"Missing origin-pull gate for {selector}"
        assert any("return 403;" in body for body in protected_bodies)
        assert any("auth_basic \"SITBank staging\";" in body for body in protected_bodies)
        assert any(
            body.index("$ssl_client_verify != SUCCESS")
            < body.index("auth_basic \"SITBank staging\";")
            for body in protected_bodies
        )
        assert any(
            "include /etc/nginx/snippets/"
            "sitbank-cloudflare-access-headers.conf;" in body
            for body in protected_bodies
        )

    ready_bodies = _nginx_location_bodies(staging_nginx, "= /health/ready")
    assert len(ready_bodies) == 1
    ready = ready_bodies[0]
    assert "$ssl_client_verify" not in ready
    assert "allow 127.0.0.1;" in ready
    assert "allow ::1;" in ready
    assert "deny all;" in ready
    assert "proxy_pass http://127.0.0.1:5001;" in ready
    assert "sitbank-cloudflare-access-headers.conf" not in ready

    assert (
        "proxy_set_header Cf-Access-Jwt-Assertion "
        "$http_cf_access_jwt_assertion;" in access_headers
    )
    assert 'proxy_set_header Cf-Access-Authenticated-User-Email "";' in access_headers
    assert 'proxy_set_header Cf-Access-Client-Secret "";' in access_headers

    assert "STAGING_CLOUDFLARE_ORIGIN_PULL_CA_FILE" in bootstrap
    assert "STAGING_CLOUDFLARE_ORIGIN_PULL_CA_ALLOWLIST" in bootstrap
    assert "STAGING_ACCESS_HEADERS_FILE" in bootstrap
    assert "install_staging_access_headers" in bootstrap
    assert "/usr/local/sbin/verify-cloudflare-origin-pull-ca" in bootstrap
    assert "Cloudflare Authenticated Origin Pull CA validation failed." in bootstrap
    assert "nginx -t" in bootstrap


def test_admin_public_surface_is_absent_and_private_access_is_tailscale_only():
    production_nginx = Path("ops/nginx/sitbank-production.conf").read_text(
        encoding="utf-8"
    )
    docs = _docs_text()
    customer_server = _nginx_server_block(production_nginx, "sitbank.duckdns.org")

    assert "server_name sitbank.duckdns.org;" in customer_server
    assert "staging-sitbank.pp.ua" not in customer_server
    assert "location ^~ /admin" in customer_server
    assert "return 404;" in customer_server
    assert "server_name sitbank-" not in production_nginx
    assert "proxy_pass http://127.0.0.1:5002;" not in production_nginx

    assert "Tailscale/private operator access" in docs
    assert "https://admin-sitbank.tailca101b.ts.net/" in docs
    assert "Do not enable Tailscale Funnel" in docs
    assert "old public admin verification" in docs
    assert "page has been removed from the edge bootstrap" in docs
    assert "No public admin Nginx server block is configured." in docs


def test_admin_customer_session_and_runtime_isolation_remains_covered():
    admin_test = Path("tests/test_admin_isolation.py").read_text(encoding="utf-8")
    deployment_test = Path("tests/test_deployment.py").read_text(encoding="utf-8")
    deploy_script = Path("ops/deploy/sitbank-container-deploy").read_text(
        encoding="utf-8"
    )
    production_compose = Path("compose.prod.yml").read_text(encoding="utf-8")
    staging_compose = Path("compose.staging.yml").read_text(encoding="utf-8")

    for required in (
        "SESSION_COOKIE_NAME",
        "__Host-sitbank_session",
        "__Host-sitbank_admin_session",
        "SESSION_LOOKUP_HMAC_KEY",
        "SESSION_KEY_PREFIX",
        "RATELIMIT_KEY_PREFIX",
        "AUTH_FAILURE_KEY_PREFIX",
        "SQLALCHEMY_DATABASE_URI",
        "ADMIN_AUTH_ENABLED",
    ):
        assert required in admin_test

    for required in (
        "Admin runtime database role must be distinct from customer runtime role",
        "Admin session lookup HMAC key must be distinct from customer session lookup HMAC key",
    ):
        assert required in deploy_script

    for required in ("127.0.0.1:5002", "127.0.0.1:5003"):
        assert required in deployment_test

    assert "127.0.0.1:5002" in production_compose
    assert "127.0.0.1:5003" in staging_compose


def test_required_zero_trust_labels_and_labelers_are_configured():
    issue_labeler = Path(".github/workflows/issue-labeler.yml").read_text(
        encoding="utf-8"
    )
    pr_labeler = Path(".github/workflows/pr-labeler.yml").read_text(encoding="utf-8")
    retag = Path(".github/workflows/retag-labels.yml").read_text(encoding="utf-8")
    labeler = Path(".github/labeler.yml").read_text(encoding="utf-8")
    labeler_config = yaml.safe_load(labeler)

    for workflow in (issue_labeler, pr_labeler, retag):
        assert 'create_label zero-trust "Identity-aware or private-network access boundary changes."' in workflow
        assert 'create_label network-security "Firewall, VPN, origin access, private access, or network boundary changes."' in workflow
        assert 'create_label staging "Staging environment, staging deployment, or staging access changes."' in workflow
        for term in (
            "cloudflare access",
            "tailscale",
            "tailnet",
            "vpn",
            "private access",
            "origin bypass",
            "admin exposure",
            "staging exposure",
        ):
            assert term in workflow.lower()

    assert "gh pr diff \"${PR_NUMBER}\" --patch" in pr_labeler
    assert "gh pr diff \"${number}\" --patch" in retag
    assert "sync-labels: false" in pr_labeler
    assert "sync-labels: false" in retag

    for label in (
        "zero-trust",
        "network-security",
        "staging",
        "security",
        "deployment",
        "admin",
        "documentation",
    ):
        assert label in labeler_config

    assert "ops/nginx/**" in labeler_config["network-security"][0]["changed-files"][0][
        "any-glob-to-any-file"
    ]
    assert "ops/nginx/**" in labeler_config["security"][0]["changed-files"][0][
        "any-glob-to-any-file"
    ]
    assert "ops/cloudflare/**" in labeler_config["security"][0]["changed-files"][0][
        "any-glob-to-any-file"
    ]
    assert "ops/cloudflare/**" in labeler_config["network-security"][0][
        "changed-files"
    ][0]["any-glob-to-any-file"]
    assert "compose.staging.yml" in labeler_config["staging"][0]["changed-files"][0][
        "any-glob-to-any-file"
    ]
    assert "ops/cloudflare/**" in labeler_config["staging"][0]["changed-files"][0][
        "any-glob-to-any-file"
    ]
    assert "docs/security/admin-and-staging-zero-trust-access.md" in labeler
    assert "PROTECTED_LABELS" in retag
    for protected in ("dependencies", "docker", "github-actions", "python"):
        assert protected in retag
    assert "Dry-run mode is active" in retag
    assert "computed labels added" in retag


def test_provider_credentials_are_not_committed_or_required_by_ci():
    ci_workflow = Path(".github/workflows/ci-deploy.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(ci_workflow)
    private_gate = workflow["jobs"]["verify-private-admin-tailnet"]
    other_jobs = {
        name: job
        for name, job in workflow["jobs"].items()
        if name != "verify-private-admin-tailnet"
    }
    tracked_text = []
    for path in _tracked_files():
        if not path.is_file():
            continue
        try:
            tracked_text.append(path.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            continue
    combined = "\n".join(tracked_text)

    assert "CLOUDFLARE_API_TOKEN" not in ci_workflow
    assert "TAILSCALE_AUTH_KEY" not in ci_workflow
    assert "TS_AUTHKEY" not in ci_workflow
    assert "CF_API_TOKEN" not in ci_workflow
    assert private_gate["environment"] == {"name": "admin-tailscale"}
    assert "TS_OAUTH_CLIENT_ID" in str(private_gate)
    assert "TS_OAUTH_SECRET" in str(private_gate)
    assert "TS_OAUTH_CLIENT_ID" not in str(other_jobs)
    assert "TS_OAUTH_SECRET" not in str(other_jobs)

    forbidden_patterns = (
        r"tskey-(?:auth|api)-[A-Za-z0-9_-]{12,}",
        r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----",
        r"cloudflared/[A-Za-z0-9_-]+\.json",
        r"CLOUDFLARE_API_TOKEN=['\"][^'\"]+['\"]",
        r"TAILSCALE_AUTH_KEY=['\"][^'\"]+['\"]",
        r"TS_AUTHKEY=['\"][^'\"]+['\"]",
        r"TS_OAUTH_CLIENT_ID=['\"][^'\"]+['\"]",
        r"TS_OAUTH_SECRET=['\"][^'\"]+['\"]",
    )
    for pattern in forbidden_patterns:
        assert not re.search(pattern, combined)


def test_repository_identity_ghcr_cosign_and_bootstrap_references_are_consistent():
    docs = _docs_text()
    workflow = Path(".github/workflows/ci-deploy.yml").read_text(encoding="utf-8")
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(encoding="utf-8")
    deploy = Path("ops/deploy/sitbank-container-deploy").read_text(encoding="utf-8")
    old_owner = "wenjiang" + "ggg"
    old_repo = f"ghcr.io/{old_owner}/sitbank"

    for path in _tracked_files():
        if not path.is_file():
            continue
        try:
            contents = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        lowered = contents.casefold()
        assert old_owner not in lowered, path
        assert old_repo not in lowered, path

    assert "Repository identity: `WenJiangg/SITBank`" in docs
    assert "Production image form: `ghcr.io/wenjiangg/sitbank@sha256:<digest>`" in docs
    assert 'repository="ghcr.io/${GITHUB_REPOSITORY,,}"' in workflow
    assert "GITHUB_REPOSITORY=${github_repository}" in bootstrap
    assert "GHCR_REPOSITORY=ghcr.io/${repository_lower}" in bootstrap
    assert "COSIGN_CERTIFICATE_IDENTITY=https://github.com/${github_repository}/.github/workflows/ci-deploy.yml@refs/heads/main" in bootstrap
    assert "expected_identity=\"https://github.com/${GITHUB_REPOSITORY}/.github/workflows/ci-deploy.yml@refs/heads/main\"" in deploy
    assert "cosign verify" in deploy
    assert "--certificate-identity \"${COSIGN_CERTIFICATE_IDENTITY}\"" in deploy


def test_deployment_policy_and_wrapper_validation_are_not_weakened():
    workflow = yaml.safe_load(Path(".github/workflows/ci-deploy.yml").read_text(encoding="utf-8"))
    workflow_text = Path(".github/workflows/ci-deploy.yml").read_text(encoding="utf-8")
    deploy_script = Path("ops/deploy/sitbank-container-deploy").read_text(encoding="utf-8")

    assert workflow["jobs"]["deploy-production"]["needs"] == [
        "release-verify",
        "deploy-staging",
        "verify-staging-tls",
    ]
    assert "needs.deploy-staging.result == 'success'" in workflow_text
    assert "vars.PROD_DEPLOY_ENABLED == 'true'" in workflow_text
    assert "workflow_dispatch" in workflow_text
    assert "target_environment == 'staging'" in workflow_text
    assert "target_environment == 'production'" not in workflow_text
    assert "sha256sum /usr/local/sbin/sitbank-container-deploy" in workflow_text
    assert "/opt/sitbank-staging/compose.yml" in workflow_text
    assert "/opt/sitbank/compose.yml" in workflow_text
    assert "cosign verify-blob" in deploy_script
    assert "cosign verify \\" in deploy_script
    assert "production-check" in deploy_script
    assert "db upgrade" in deploy_script
