from __future__ import annotations

import io
import json
import os
import re
import runpy
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml


SCRIPT = Path("ops/cloudflare/provision-staging-access")
README = Path("docs/security/architecture/cloudflare-staging-access.md")
LOCAL_README = Path("ops/cloudflare/README.md")
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
            "STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN": "sitbank.cloudflareaccess.com",
            "STAGING_CLOUDFLARE_ACCESS_AUD": "non-secret-application-audience",
            "STAGING_ACCESS_SESSION_DURATION": "6h",
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
        Path("docs/security/architecture/access-control.md"),
        Path("docs/security/architecture/admin-and-staging-zero-trust-access.md"),
        Path("docs/security/governance/framework-control-matrix.md"),
        Path("docs/security/governance/security-gap-register.md"),
        README,
    ]
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def test_cloudflare_automation_files_and_modes_exist():
    assert SCRIPT.is_file()
    assert README.is_file()
    assert LOCAL_README.is_file()
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
    assert "Access session duration of 6h" in result.stdout


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


def test_config_reads_six_hour_duration_and_expected_audience(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    for name, value in _base_environment().items():
        if name.startswith(("CLOUDFLARE_", "STAGING_")):
            monkeypatch.setenv(name, value)
    monkeypatch.setenv("STAGING_ACCESS_APP_NAME", "")
    monkeypatch.setenv("STAGING_ACCESS_POLICY_NAME", "")

    config = module["Config"].from_environment(require_origin_ip=False)

    assert config.session_duration == "6h"
    assert config.access_audience == "non-secret-application-audience"
    assert config.app_name == "SITBank staging"
    assert config.policy_name == "SITBank staging approved operators"
    assert config.application_payload["session_duration"] == "6h"


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


def test_provider_drift_diagnostics_name_safe_fields_without_secret_values(
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
        "aud": config.access_audience,
    }
    policy = {
        **config.policy_payload,
        "id": "00000000-0000-0000-0000-000000000002",
    }
    dns_record = {
        **config.dns_payload,
        "id": "00000000000000000000000000000003",
    }

    drifted_application = {
        **application,
        "session_duration": "24h",
        "app_launcher_visible": True,
    }
    with pytest.raises(verification_error) as application_error:
        verify_provider_state(
            provider_state_type(
                drifted_application,
                (policy,),
                dns_record,
            ),
            config,
        )
    message = str(application_error.value)
    assert "session_duration expected=6h actual=24h" in message
    assert "app_launcher_visible expected=false actual=true" in message

    unexpected_audience = "different-non-secret-audience"
    with pytest.raises(verification_error) as audience_error:
        verify_provider_state(
            provider_state_type(
                {**application, "aud": unexpected_audience},
                (policy,),
                dns_record,
            ),
            config,
        )
    message = str(audience_error.value)
    assert (
        "audience expected=non-secret-application-audience "
        f"actual={unexpected_audience}"
    ) in message

    drifted_policy = {
        **policy,
        "include": [{"email": {"email": "different-secret@example.com"}}],
    }
    with pytest.raises(verification_error) as policy_error:
        verify_provider_state(
            provider_state_type(
                application,
                (drifted_policy,),
                dns_record,
            ),
            config,
        )
    message = str(policy_error.value)
    assert "allowed_emails expected_count=1 actual_count=1 mismatch=true" in message
    assert "operator@example.com" not in message
    assert "different-secret@example.com" not in message


def test_cloudflare_http_error_does_not_print_raw_provider_response(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    cloudflare_api = module["CloudflareAPI"]
    cloudflare_api_error = module["CloudflareAPIError"]
    leaked_value = "provider-response-secret"

    def fail_request(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            url="https://api.cloudflare.com/client/v4/test",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=io.BytesIO(
                json.dumps(
                    {"errors": [{"message": leaked_value}]}
                ).encode("utf-8")
            ),
        )

    monkeypatch.setattr(urllib.request, "urlopen", fail_request)
    with pytest.raises(cloudflare_api_error) as error:
        cloudflare_api("token-that-must-not-appear").request("GET", "/test")

    assert "returned HTTP 403" in str(error.value)
    assert leaked_value not in str(error.value)
    assert "token-that-must-not-appear" not in str(error.value)


@pytest.mark.parametrize(
    "sensitive_value",
    [
        "CF-Access-Jwt-Assertion: eyJ.fake.jwt",
        "Authorization: Bearer fake-cloudflare-token",
        "CF_API_TOKEN=fake-token",
        "access_service_token=fake-service-token",
        "session=fake-session",
        "csrf_token=fake-csrf",
        "-----BEGIN " + "PRIVATE KEY-----\nfake\n-----END " + "PRIVATE KEY-----",
    ],
)
def test_provider_output_sanitizer_redacts_sensitive_diagnostics(sensitive_value):
    module = runpy.run_path(str(SCRIPT))

    sanitized = module["sanitize_provider_output"](
        f"provider failed: {sensitive_value}"
    )

    assert sensitive_value not in sanitized
    assert "fake-cloudflare-token" not in sanitized
    assert "fake-service-token" not in sanitized
    assert "fake-session" not in sanitized
    assert "fake-csrf" not in sanitized


def test_manual_verification_workflow_is_read_only_and_secret_safe():
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    triggers = workflow.get("on", workflow.get(True))

    assert set(triggers) == {"workflow_dispatch"}
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["verify"]["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["verify"]["environment"]["name"] == "staging"
    assert workflow["jobs"]["verify"]["if"] == "github.ref == 'refs/heads/main'"
    assert workflow["jobs"]["verify"]["env"] == {
        "CLOUDFLARE_API_TOKEN": "${{ secrets.CLOUDFLARE_API_TOKEN }}",
        "CLOUDFLARE_ACCOUNT_ID": "${{ vars.CLOUDFLARE_ACCOUNT_ID }}",
        "CLOUDFLARE_ZONE_ID": "${{ vars.CLOUDFLARE_ZONE_ID }}",
        "STAGING_ACCESS_HOSTNAME": "${{ vars.STAGING_PUBLIC_HOST }}",
        "STAGING_ACCESS_APP_NAME": "${{ vars.STAGING_ACCESS_APP_NAME }}",
        "STAGING_ACCESS_POLICY_NAME": "${{ vars.STAGING_ACCESS_POLICY_NAME }}",
        "STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN": (
            "${{ vars.STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN }}"
        ),
        "STAGING_CLOUDFLARE_ACCESS_AUD": (
            "${{ vars.STAGING_CLOUDFLARE_ACCESS_AUD }}"
        ),
        "STAGING_ACCESS_SESSION_DURATION": (
            "${{ vars.STAGING_ACCESS_SESSION_DURATION }}"
        ),
        "STAGING_ACCESS_ALLOWED_EMAILS": (
            "${{ secrets.STAGING_ACCESS_ALLOWED_EMAILS }}"
        ),
        "STAGING_ACCESS_ALLOWED_GROUP_IDS": (
            "${{ secrets.STAGING_ACCESS_ALLOWED_GROUP_IDS }}"
        ),
        "STAGING_ACCESS_ALLOWED_IDP_IDS": (
            "${{ vars.STAGING_ACCESS_ALLOWED_IDP_IDS }}"
        ),
        "STAGING_DNS_ORIGIN": "${{ secrets.STAGING_DNS_ORIGIN }}",
        "STAGING_ORIGIN_IP": "${{ secrets.STAGING_ORIGIN_IP }}",
    }
    assert "--verify" in text
    assert "--apply" not in text
    assert "pull_request" not in text
    assert "${{ secrets.CLOUDFLARE_API_TOKEN }}" in text
    assert "actions/checkout@" in text
    assert "actions/upload-artifact@" in text
    assert "retention-days: 30" in text
    assert not re.search(
        r"CLOUDFLARE_API_TOKEN:\s*(?!\$\{\{\s*secrets\.)\S+",
        text,
    )


def test_documentation_covers_provider_state_secrets_and_jwt_boundary():
    docs = _all_security_docs()
    normalized_docs = " ".join(docs.split())

    for required in (
        "Cloudflare-managed hostname model",
        "ops/cloudflare/provision-staging-access",
        "Access: Apps and Policies Read",
        "Access: Apps and Policies Write",
        "DNS Read",
        "DNS Write",
        "STAGING_CLOUDFLARE_ACCESS_AUD",
        "STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN",
        "STAGING_CLOUDFLARE_ACCESS_JWT_REQUIRED",
        "STAGING_ACCESS_SESSION_DURATION=6h",
        "SITBank staging",
        "wildcard domains",
        "broad allow-all",
        "Cf-Access-Jwt-Assertion",
        "email/service-token headers",
        "direct origin",
        "default deny",
        "service-token",
        "rotate",
        "revoke",
        "emergency staging lockout",
        "validates the",
    ):
        assert required.casefold() in normalized_docs.casefold()

    assert "Cloudflare Tunnel" in docs
    assert "retired DuckDNS staging hostname" in docs
    assert "Cloudflare API tokens" in docs
    assert "Never use a Global API Key" in docs


def test_documentation_records_complete_staging_environment_contract():
    docs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            Path("docs/GITHUB_ACTIONS.md"),
            Path("docs/DEPLOYMENT.md"),
            Path("docs/OPERATIONS.md"),
            Path("docs/security/architecture/admin-and-staging-zero-trust-access.md"),
            README,
        )
    )

    for required_secret in (
        "CLOUDFLARE_API_TOKEN",
        "STAGING_ACCESS_ALLOWED_EMAILS",
        "STAGING_DNS_ORIGIN",
        "STAGING_ORIGIN_IP",
        "STAGING_EC2_KNOWN_HOSTS",
        "STAGING_EC2_SSH_PRIVATE_KEY_B64",
    ):
        assert required_secret in docs
    for required_variable in (
        "CLOUDFLARE_ACCOUNT_ID",
        "CLOUDFLARE_ZONE_ID",
        "STAGING_ACCESS_SESSION_DURATION",
        "STAGING_CLOUDFLARE_ACCESS_AUD",
        "STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN",
        "STAGING_PUBLIC_HOST",
        "STAGING_EC2_HOST",
        "STAGING_EC2_DEPLOY_USER",
        "STAGING_EC2_PORT",
    ):
        assert required_variable in docs
    for expected_value in (
        "STAGING_ACCESS_SESSION_DURATION=6h",
        "SITBank staging",
        "staging-sitbank.pp.ua",
        "small-boat-a77f.cloudflareaccess.com",
        "847a9be3c396f4930a210e3106aa5d86945839ba9ad31be794e4378bf8a55663",
    ):
        assert expected_value in docs
    for safety_statement in (
        "exact explicit email",
        "Everyone",
        "wildcard domains",
        "broad allow-all",
        "reports counts only",
    ):
        assert safety_statement.casefold() in docs.casefold()
    assert "default `8h`" not in docs


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


def test_sanitized_evidence_records_only_non_secret_expected_duration(
    monkeypatch,
    tmp_path,
):
    module = runpy.run_path(str(SCRIPT))
    for name, value in _base_environment().items():
        if name.startswith(("CLOUDFLARE_", "STAGING_")):
            monkeypatch.setenv(name, value)
    config = module["Config"].from_environment(require_origin_ip=False)
    http = module["HTTPVerification"](True, True, "http_403")
    evidence_path = tmp_path / "cloudflare-access-evidence.json"

    module["_write_evidence"](evidence_path, config, http)

    evidence_text = evidence_path.read_text(encoding="utf-8")
    evidence = json.loads(evidence_text)
    assert evidence["schema"] == 2
    assert evidence["session_duration"] == "6h"
    assert evidence["result"] == "pass"
    assert evidence["github_environment"] == "staging"
    assert evidence["workflow_trigger"] == "manual_protected"
    assert evidence["checks"]["allow_everyone"] is False
    assert evidence["checks"]["approved_identities_configured"] is True
    assert evidence["checks"]["origin_protection_expected"] is True
    assert evidence["provider_owned_review"]["mfa_or_device_posture"] == (
        "external_review_required"
    )
    assert "operator@example.com" not in evidence_text
    assert config.access_audience not in evidence_text
    assert config.dns_origin not in evidence_text


@pytest.mark.parametrize("direct_status", ["400", "403"])
def test_live_verification_accepts_approved_http_origin_denials(
    monkeypatch,
    direct_status,
):
    module = runpy.run_path(str(SCRIPT))
    for name, value in _base_environment().items():
        if name.startswith(("CLOUDFLARE_", "STAGING_")):
            monkeypatch.setenv(name, value)
    monkeypatch.setenv("STAGING_ORIGIN_IP", "8.8.8.8")
    config = module["Config"].from_environment(require_origin_ip=True)
    responses = iter(
        (
            subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    "HTTP/2 302\r\n"
                    "server: cloudflare\r\n"
                    "cf-ray: fake-ray\r\n"
                    "location: https://sitbank.cloudflareaccess.com/"
                    "cdn-cgi/access/login\r\n\r\n"
                ),
                stderr="",
            ),
            subprocess.CompletedProcess(
                [],
                0,
                stdout=f"HTTP/1.1 {direct_status} Denied\r\nserver: nginx\r\n\r\n",
                stderr="",
            ),
        )
    )
    monkeypatch.setitem(
        module["verify_live_http"].__globals__,
        "_curl_headers",
        lambda _arguments: next(responses),
    )

    result = module["verify_live_http"](config)

    assert result.edge_challenge is True
    assert result.direct_origin_blocked is True
    assert result.direct_origin_result == f"http_{direct_status}"


def test_live_verification_rejects_direct_origin_app_response(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    for name, value in _base_environment().items():
        if name.startswith(("CLOUDFLARE_", "STAGING_")):
            monkeypatch.setenv(name, value)
    monkeypatch.setenv("STAGING_ORIGIN_IP", "8.8.8.8")
    config = module["Config"].from_environment(require_origin_ip=True)
    responses = iter(
        (
            subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    "HTTP/2 302\r\n"
                    "server: cloudflare\r\n"
                    "cf-ray: fake-ray\r\n"
                    "location: https://sitbank.cloudflareaccess.com/"
                    "cdn-cgi/access/login\r\n\r\n"
                ),
                stderr="",
            ),
            subprocess.CompletedProcess(
                [],
                0,
                stdout="HTTP/1.1 200 OK\r\nserver: nginx\r\n\r\n",
                stderr="",
            ),
        )
    )
    monkeypatch.setitem(
        module["verify_live_http"].__globals__,
        "_curl_headers",
        lambda _arguments: next(responses),
    )

    with pytest.raises(
        module["VerificationError"],
        match="approved fail-closed status",
    ):
        module["verify_live_http"](config)


def test_existing_authenticated_origin_pull_gate_is_unchanged():
    nginx = Path("ops/nginx/sitbank-staging.conf").read_text(encoding="utf-8")

    assert (
        "ssl_client_certificate "
        "/etc/nginx/cloudflare-authenticated-origin-pull-ca.pem;" in nginx
    )
    assert "ssl_verify_client on;" in nginx
    assert "$ssl_client_verify" not in nginx
    assert "auth_basic" not in nginx
