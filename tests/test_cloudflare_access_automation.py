from __future__ import annotations

import json
import os
import re
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


SCRIPT = Path("ops/cloudflare/provision-staging-access")
README = Path("ops/cloudflare/README.md")
WORKFLOW = Path(".github/workflows/cloudflare-access-verify.yml")
EXPECTED_HOST = "staging-sitbank.pp.ua"


def _base_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith(("CLOUDFLARE_", "STAGING_ACCESS_", "STAGING_DNS_", "STAGING_ORIGIN_")):
            environment.pop(name)
    environment.update(
        {
            "CLOUDFLARE_ACCOUNT_ID": "0123456789abcdef0123456789abcdef",
            "CLOUDFLARE_ZONE_ID": "abcdef0123456789abcdef0123456789",
            "STAGING_ACCESS_TEAM_DOMAIN": "sitbank.cloudflareaccess.com",
            "STAGING_ACCESS_ALLOWED_EMAILS": "operator@example.com",
            "STAGING_DNS_ORIGIN": "198.51.100.10",
        }
    )
    return environment


def _run_script(*arguments: str, environment: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=environment or _base_environment(),
        timeout=10,
    )


def _all_security_docs() -> str:
    paths = [
        Path("docs/DEPLOYMENT.md"),
        Path("docs/OPERATIONS.md"),
        Path("docs/security/access-control.md"),
        Path("docs/security/admin-and-staging-zero-trust-access.md"),
        Path("docs/security/framework-control-matrix.md"),
        Path("docs/security/security-gap-register.md"),
        README,
    ]
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def test_cloudflare_automation_files_and_modes_exist():
    assert SCRIPT.is_file()
    assert README.is_file()
    assert WORKFLOW.is_file()

    script = SCRIPT.read_text(encoding="utf-8")
    for mode in ("--plan", "--apply", "--verify"):
        assert mode in script
    assert "APPLY-STAGING-ACCESS" in script
    assert '"proxied": True' in script
    assert '"type": "self_hosted"' in script
    assert "Cf-Access-Jwt-Assertion" not in script


def test_plan_is_offline_redacted_and_does_not_require_token():
    result = _run_script("--plan")

    assert result.returncode == 0, result.stderr
    assert "offline; no API calls" in result.stdout
    assert EXPECTED_HOST in result.stdout
    assert "origin value redacted" in result.stdout
    assert "198.51.100.10" not in result.stdout
    assert "operator@example.com" not in result.stdout
    assert "CLOUDFLARE_API_TOKEN" not in result.stdout


def test_apply_requires_exact_confirmation_before_api_access():
    result = _run_script("--apply")

    assert result.returncode == 1
    assert "--apply requires --confirm APPLY-STAGING-ACCESS" in result.stderr
    assert "CLOUDFLARE_API_TOKEN" not in result.stderr


def test_configuration_forbids_allow_everyone_and_non_staging_hosts(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    config_type = module["Config"]
    configuration_error = module["ConfigurationError"]

    for name, value in _base_environment().items():
        if name.startswith(("CLOUDFLARE_", "STAGING_")):
            monkeypatch.setenv(name, value)
    monkeypatch.delenv("STAGING_ACCESS_ALLOWED_EMAILS")
    with pytest.raises(configuration_error, match="allow-everyone is forbidden"):
        config_type.from_environment(require_origin_ip=False)

    monkeypatch.setenv("STAGING_ACCESS_ALLOWED_EMAILS", "operator@example.com")
    monkeypatch.setenv("STAGING_ACCESS_HOSTNAME", "sitbank.duckdns.org")
    with pytest.raises(configuration_error, match="must be exactly"):
        config_type.from_environment(require_origin_ip=False)


def test_policy_payload_contains_only_explicit_operator_rules(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    config_type = module["Config"]
    for name, value in _base_environment().items():
        if name.startswith(("CLOUDFLARE_", "STAGING_")):
            monkeypatch.setenv(name, value)
    monkeypatch.setenv(
        "STAGING_ACCESS_ALLOWED_GROUP_IDS",
        "01234567-89ab-cdef-0123-456789abcdef",
    )

    payload = config_type.from_environment(
        require_origin_ip=False
    ).policy_payload

    assert payload["decision"] == "allow"
    assert payload["include"] == [
        {"email": {"email": "operator@example.com"}},
        {"group": {"id": "01234567-89ab-cdef-0123-456789abcdef"}},
    ]
    assert not any(
        "everyone" in rule or "any_valid_service_token" in rule
        for rule in payload["include"]
    )


def test_provider_verification_accepts_narrow_state_and_rejects_broad_state(
    monkeypatch,
):
    module = runpy.run_path(str(SCRIPT))
    config_type = module["Config"]
    provider_state_type = module["ProviderState"]
    verification_error = module["VerificationError"]
    verify_provider_state = module["verify_provider_state"]
    for name, value in _base_environment().items():
        if name.startswith(("CLOUDFLARE_", "STAGING_")):
            monkeypatch.setenv(name, value)
    config = config_type.from_environment(require_origin_ip=False)
    application = {
        **config.application_payload,
        "id": "00000000-0000-0000-0000-000000000001",
        "aud": "non-secret-application-audience",
    }
    policy = {
        **config.policy_payload,
        "id": "00000000-0000-0000-0000-000000000002",
    }
    dns_record = {
        **config.dns_payload,
        "id": "00000000000000000000000000000003",
    }

    state = provider_state_type(application, (policy,), dns_record)
    assert verify_provider_state(state, config) == "non-secret-application-audience"

    broad_policy = {
        **policy,
        "include": [{"everyone": {}}],
    }
    with pytest.raises(verification_error, match="drifted|Unsafe"):
        verify_provider_state(
            provider_state_type(application, (broad_policy,), dns_record),
            config,
        )

    broad_application = {
        **application,
        "destinations": [
            {"type": "public", "uri": EXPECTED_HOST},
            {"type": "public", "uri": "sitbank.duckdns.org"},
        ],
    }
    with pytest.raises(verification_error, match="application configuration"):
        verify_provider_state(
            provider_state_type(broad_application, (policy,), dns_record),
            config,
        )


def test_manual_verification_workflow_is_read_only_and_secret_safe():
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    triggers = workflow.get("on", workflow.get(True))

    assert set(triggers) == {"workflow_dispatch"}
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["verify"]["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["verify"]["environment"]["name"] == "staging"
    assert "--verify" in text
    assert "--apply" not in text
    assert "pull_request" not in text
    assert "${{ secrets.CLOUDFLARE_API_TOKEN }}" in text
    assert "actions/checkout@" in text
    assert "actions/upload-artifact@" in text
    assert not re.search(
        r"CLOUDFLARE_API_TOKEN:\s*(?!\$\{\{\s*secrets\.)\S+",
        text,
    )


def test_documentation_covers_provider_state_secrets_and_jwt_boundary():
    docs = _all_security_docs()

    for required in (
        "Cloudflare-managed hostname model",
        "ops/cloudflare/provision-staging-access",
        "Access: Apps and Policies Read",
        "Access: Apps and Policies Write",
        "DNS Read",
        "DNS Write",
        "CLOUDFLARE_ACCESS_AUD",
        "CLOUDFLARE_ACCESS_ISSUER",
        "CLOUDFLARE_ACCESS_JWKS_URL",
        "Cf-Access-Jwt-Assertion",
        "do not trust Cloudflare email/identity",
        "direct origin",
        "default deny",
        "service-token",
        "rotate",
        "revoke",
        "emergency staging lockout",
        "current runtime does not consume",
    ):
        assert required.casefold() in docs.casefold()

    assert "Cloudflare Tunnel" in docs
    assert "retired DuckDNS staging hostname" in docs
    assert "Cloudflare API tokens" in docs
    assert "Never use a Global API Key" in docs


def test_sanitized_evidence_contract_excludes_sensitive_values():
    script = SCRIPT.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    normalized_readme = " ".join(readme.split())
    ignored = Path(".gitignore").read_text(encoding="utf-8")

    assert "--evidence-file" in script
    assert "cloudflare-access-evidence*.json" in ignored
    for excluded in (
        "tokens",
        "account/zone IDs",
        "email/group allowlists",
        "origin addresses",
        "application IDs",
        "audience",
    ):
        assert excluded in normalized_readme


def test_existing_authenticated_origin_pull_gate_is_unchanged():
    nginx = Path("ops/nginx/sitbank-staging.conf").read_text(encoding="utf-8")

    assert (
        "ssl_client_certificate "
        "/etc/nginx/cloudflare-authenticated-origin-pull-ca.pem;" in nginx
    )
    assert "ssl_verify_client optional;" in nginx
    assert "if ($ssl_client_verify != SUCCESS) { return 403; }" in nginx
    assert 'auth_basic "SITBank staging";' in nginx
