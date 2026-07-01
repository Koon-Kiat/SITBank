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
from types import SimpleNamespace

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


def _module_config(module, monkeypatch, *, require_origin_ip=False):
    for name, value in _base_environment().items():
        if name.startswith(("CLOUDFLARE_", "STAGING_")):
            monkeypatch.setenv(name, value)
    if require_origin_ip:
        monkeypatch.setenv("STAGING_ORIGIN_IP", "8.8.8.8")
    return module["Config"].from_environment(require_origin_ip=require_origin_ip)


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("CLOUDFLARE_ACCOUNT_ID", "", "Missing required"),
        ("CLOUDFLARE_ACCOUNT_ID", "bad!", "not a valid Cloudflare identifier"),
        ("STAGING_CLOUDFLARE_ACCESS_AUD", "bad!", "not a valid Cloudflare identifier"),
        ("STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN", "example.com", "cloudflareaccess.com"),
        ("STAGING_ACCESS_ALLOWED_EMAILS", "not-an-email", "invalid email"),
        ("STAGING_ACCESS_ALLOWED_GROUP_IDS", "bad!", "invalid identifier"),
        ("STAGING_ACCESS_SESSION_DURATION", "2d", "minutes or hours"),
        ("STAGING_ACCESS_SESSION_DURATION", "5m", "between 15m and 24h"),
        ("STAGING_DNS_ORIGIN", EXPECTED_HOST, "different hostname"),
        ("STAGING_ORIGIN_IP", "localhost", "literal public IP"),
        ("STAGING_ORIGIN_IP", "127.0.0.1", "public origin address"),
    ],
)
def test_configuration_helpers_fail_closed(monkeypatch, name, value, message):
    module = runpy.run_path(str(SCRIPT))
    for env_name, env_value in _base_environment().items():
        if env_name.startswith(("CLOUDFLARE_", "STAGING_")):
            monkeypatch.setenv(env_name, env_value)
    monkeypatch.setenv(name, value)
    require_origin_ip = name == "STAGING_ORIGIN_IP"

    with pytest.raises(module["ConfigurationError"], match=message):
        module["Config"].from_environment(require_origin_ip=require_origin_ip)


def test_config_payloads_support_cname_groups_idps_and_safe_urls(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    for name, value in _base_environment().items():
        if name.startswith(("CLOUDFLARE_", "STAGING_")):
            monkeypatch.setenv(name, value)
    monkeypatch.setenv("STAGING_DNS_ORIGIN", "origin.example.com.")
    group_a = "a" * 32
    group_b = "b" * 32
    idp_a = "c" * 32
    idp_b = "d" * 32
    monkeypatch.setenv("STAGING_ACCESS_ALLOWED_GROUP_IDS", f"{group_b},{group_a}")
    monkeypatch.setenv("STAGING_ACCESS_ALLOWED_IDP_IDS", f"{idp_b},{idp_a}")
    config = module["Config"].from_environment(require_origin_ip=False)

    assert config.dns_record_type == "CNAME"
    assert config.dns_origin == "origin.example.com"
    assert config.issuer == "https://sitbank.cloudflareaccess.com"
    assert config.jwks_url.endswith("/cdn-cgi/access/certs")
    assert config.application_payload["allowed_idps"] == [idp_a, idp_b]
    assert config.policy_payload["include"][-2:] == [
        {"group": {"id": group_a}},
        {"group": {"id": group_b}},
    ]


def test_read_provider_state_queries_exact_application_policy_and_dns(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    config = _module_config(module, monkeypatch)
    application = {"id": "app-id", "domain": EXPECTED_HOST}
    policy = {"id": "policy-id"}
    dns = {"id": "dns-id", "name": EXPECTED_HOST}

    class API:
        def __init__(self):
            self.calls = []

        def request(self, method, path, **kwargs):
            self.calls.append((method, path, kwargs))
            if path.endswith("/access/apps"):
                return [application]
            if path.endswith("/policies"):
                return [policy]
            return [dns]

    api = API()
    state = module["read_provider_state"](api, config)

    assert state.application == application
    assert state.policies == (policy,)
    assert state.dns_record == dns
    assert len(api.calls) == 3

    with pytest.raises(module["VerificationError"], match="Multiple Access application"):
        module["read_provider_state"](
            SimpleNamespace(
                request=lambda _method, path, **_kwargs: (
                    [application, application] if path.endswith("/access/apps") else []
                )
            ),
            config,
        )
    with pytest.raises(module["VerificationError"], match="has no ID"):
        module["read_provider_state"](
            SimpleNamespace(
                request=lambda _method, path, **_kwargs: (
                    [{"domain": EXPECTED_HOST}]
                    if path.endswith("/access/apps")
                    else []
                )
            ),
            config,
        )


def test_apply_provider_state_creates_missing_objects_and_reads_back(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    config = _module_config(module, monkeypatch)
    empty = module["ProviderState"](None, (), None)
    final = module["ProviderState"]({"id": "app-id"}, (), {"id": "dns-id"})
    states = iter([empty, final])
    monkeypatch.setitem(
        module["apply_provider_state"].__globals__,
        "read_provider_state",
        lambda _api, _config: next(states),
    )

    class API:
        def __init__(self):
            self.calls = []

        def request(self, method, path, **kwargs):
            self.calls.append((method, path, kwargs))
            if method == "POST" and path.endswith("/access/apps"):
                return {"id": "app-id"}
            if method == "GET" and path.endswith("/policies"):
                return []
            return {}

    api = API()
    assert module["apply_provider_state"](api, config) == final
    assert [(method, path.rsplit("/", 1)[-1]) for method, path, _ in api.calls] == [
        ("POST", "apps"),
        ("GET", "policies"),
        ("POST", "policies"),
        ("POST", "dns_records"),
    ]


def test_apply_provider_state_updates_drifted_objects(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    config = _module_config(module, monkeypatch)
    drifted_app = {"id": "app-id", "name": "wrong"}
    drifted_policy = {"id": "policy-id", "name": config.policy_name, "decision": "deny"}
    drifted_dns = {"id": "dns-id", "type": "A", "content": "203.0.113.1", "proxied": False}
    initial = module["ProviderState"](drifted_app, (drifted_policy,), drifted_dns)
    final = module["ProviderState"]({"id": "app-id"}, (drifted_policy,), drifted_dns)
    states = iter([initial, final])
    monkeypatch.setitem(
        module["apply_provider_state"].__globals__,
        "read_provider_state",
        lambda _api, _config: next(states),
    )

    class API:
        def __init__(self):
            self.calls = []

        def request(self, method, path, **kwargs):
            self.calls.append((method, path, kwargs))
            if method == "PUT" and path.endswith("/app-id"):
                return {"id": "app-id"}
            if method == "GET" and path.endswith("/policies"):
                return [drifted_policy]
            return {}

    api = API()
    assert module["apply_provider_state"](api, config) == final
    assert [method for method, _, _ in api.calls] == ["PUT", "GET", "PUT", "PATCH"]


def test_repository_origin_pull_verifier_and_curl_errors_are_actionable(monkeypatch, tmp_path):
    module = runpy.run_path(str(SCRIPT))
    verifier_globals = module["_verify_repository_origin_pull"].__globals__
    monkeypatch.chdir(tmp_path)
    with pytest.raises(module["VerificationError"], match="repository root"):
        module["_verify_repository_origin_pull"]()

    nginx = tmp_path / "ops" / "nginx"
    nginx.mkdir(parents=True)
    (nginx / "sitbank-staging.conf").write_text("ssl_verify_client on;", encoding="utf-8")
    with pytest.raises(module["VerificationError"], match="enforcement is missing"):
        module["_verify_repository_origin_pull"]()

    monkeypatch.setattr(
        module["subprocess"],
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError()),
    )
    with pytest.raises(module["VerificationError"], match="curl is required"):
        module["_curl_headers"]([])
    monkeypatch.setattr(
        module["subprocess"],
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired("curl", 25)
        ),
    )
    with pytest.raises(module["VerificationError"], match="timed out"):
        module["_curl_headers"]([])


def test_cloudflare_api_handles_success_rejection_and_transport_failures(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    with pytest.raises(module["ConfigurationError"], match="Missing required"):
        module["CloudflareAPI"]("")
    api = module["CloudflareAPI"]("clearly-fake-token")

    class Response(io.StringIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    monkeypatch.setattr(
        module["urllib"].request,
        "urlopen",
        lambda *_args, **_kwargs: Response(
            json.dumps({"success": True, "result": {"id": "result-id"}})
        ),
    )
    assert api.request("GET", "/example", query={"name": "value"}) == {
        "id": "result-id"
    }

    monkeypatch.setattr(
        module["urllib"].request,
        "urlopen",
        lambda *_args, **_kwargs: Response(
            json.dumps(
                {
                    "success": False,
                    "errors": [{"code": 1001, "message": "sensitive provider detail"}],
                }
            )
        ),
    )
    with pytest.raises(module["CloudflareAPIError"], match="error codes: 1001") as exc:
        api.request("POST", "/example", payload={"safe": True})
    assert "sensitive provider detail" not in str(exc.value)

    http_error = urllib.error.HTTPError(
        "https://api.cloudflare.com/client/v4/example",
        403,
        "forbidden",
        {},
        io.BytesIO(b'{"secret":"must-not-leak"}'),
    )
    monkeypatch.setattr(
        module["urllib"].request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(http_error),
    )
    with pytest.raises(module["CloudflareAPIError"], match="returned HTTP 403") as exc:
        api.request("GET", "/example")
    assert "must-not-leak" not in str(exc.value)

    monkeypatch.setattr(
        module["urllib"].request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            urllib.error.URLError("offline")
        ),
    )
    with pytest.raises(module["CloudflareAPIError"], match="failed"):
        api.request("GET", "/example")


def test_main_direct_modes_cover_plan_apply_and_sanitized_verify(monkeypatch, tmp_path, capsys):
    module = runpy.run_path(str(SCRIPT))
    config = _module_config(module, monkeypatch, require_origin_ip=True)
    main_globals = module["main"].__globals__
    monkeypatch.setattr(
        module["Config"],
        "from_environment",
        classmethod(lambda _cls, *, require_origin_ip: config),
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "clearly-fake-token")
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "clearly-fake-token")

    assert module["main"](["--plan"]) == 0
    plan_output = capsys.readouterr().out
    assert "offline; no API calls" in plan_output
    assert "origin value redacted" in plan_output

    state = module["ProviderState"]({}, (), {})
    monkeypatch.setitem(main_globals, "apply_provider_state", lambda _api, _config: state)
    monkeypatch.setitem(main_globals, "verify_provider_state", lambda _state, _config: "fake-audience")
    assert module["main"](
        ["--apply", "--confirm", module["APPLY_CONFIRMATION"]]
    ) == 0
    apply_output = capsys.readouterr().out
    assert "applied and read-back verification passed" in apply_output
    assert "STAGING_CLOUDFLARE_ACCESS_AUD=fake-audience" in apply_output

    http = module["HTTPVerification"](True, True, "http_403")
    monkeypatch.setitem(main_globals, "read_provider_state", lambda _api, _config: state)
    monkeypatch.setitem(main_globals, "_verify_repository_origin_pull", lambda: None)
    monkeypatch.setitem(main_globals, "verify_live_http", lambda _config: http)
    evidence = tmp_path / "evidence.json"
    assert module["main"](["--verify", "--evidence-file", str(evidence)]) == 0
    verify_output = capsys.readouterr().out
    assert "Sanitized evidence written" in verify_output
    assert json.loads(evidence.read_text(encoding="utf-8"))["checks"][
        "direct_origin_result"
    ] == "http_403"

    assert module["main"](["--plan", "--evidence-file", str(evidence)]) == 1
    assert "valid only with --verify" in capsys.readouterr().err


def test_provider_helpers_cover_optional_and_fail_closed_edges(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    for name, value in _base_environment().items():
        if name.startswith(("CLOUDFLARE_", "STAGING_")):
            monkeypatch.setenv(name, value)
    monkeypatch.delenv("STAGING_CLOUDFLARE_ACCESS_AUD")
    monkeypatch.setenv(
        "STAGING_CLOUDFLARE_ACCESS_TEAM_DOMAIN",
        "https://sitbank.cloudflareaccess.com/",
    )
    config = module["Config"].from_environment(require_origin_ip=False)
    assert config.access_audience is None
    assert config.team_domain == "sitbank.cloudflareaccess.com"
    with pytest.raises(module["ConfigurationError"], match="STAGING_ORIGIN_IP is required"):
        module["Config"].from_environment(require_origin_ip=True)

    assert module["_policy_is_unsafe"]({"decision": "bypass"})
    assert module["_policy_is_unsafe"](
        {"decision": "allow", "include": [{"everyone": {}}]}
    )
    assert module["_diagnostic_value"](None) == "<missing>"
    assert module["_diagnostic_value"]([]) == "<list>"
    assert module["_diagnostic_value"]("bad\nvalue") == "<invalid>"

    with pytest.raises(module["VerificationError"], match="unsafe everyone"):
        module["_assert_apply_safe"](({"decision": "bypass"},), config)
    with pytest.raises(module["VerificationError"], match="unmanaged Allow"):
        module["_assert_apply_safe"](
            ({"decision": "allow", "name": "unmanaged", "include": []},),
            config,
        )


def test_provider_verification_failure_reasons_are_specific_and_safe(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    config = _module_config(module, monkeypatch)
    provider_state = module["ProviderState"]

    cases = [
        (provider_state(None, (), None), "application is missing"),
        (
            provider_state(
                {**config.application_payload, "id": "app-id"},
                (),
                config.dns_payload,
            ),
            "audience is missing",
        ),
        (
                provider_state(
                {
                    **config.application_payload,
                    "id": "app-id",
                    "aud": config.access_audience,
                },
                (),
                config.dns_payload,
            ),
            "policy is missing",
        ),
    ]
    for state, message in cases:
        with pytest.raises(module["VerificationError"], match=message):
            module["verify_provider_state"](state, config)

    app_data = {**config.application_payload, "id": "app-id", "aud": config.access_audience}
    policy = {**config.policy_payload, "id": "policy-id"}
    with pytest.raises(module["VerificationError"], match="Unsafe Access policy"):
        module["verify_provider_state"](
            provider_state(
                app_data,
                (policy, {"name": "unsafe", "decision": "bypass"}),
                config.dns_payload,
            ),
            config,
        )
    with pytest.raises(module["VerificationError"], match="unmanaged Allow"):
        module["verify_provider_state"](
            provider_state(
                app_data,
                (policy, {"name": "other", "decision": "allow", "include": []}),
                config.dns_payload,
            ),
            config,
        )
    with pytest.raises(module["VerificationError"], match="DNS record is missing"):
        module["verify_provider_state"](
            provider_state(app_data, (policy,), None),
            config,
        )
    with pytest.raises(module["VerificationError"], match="not the expected proxied"):
        module["verify_provider_state"](
            provider_state(app_data, (policy,), {**config.dns_payload, "proxied": False}),
            config,
        )


def test_live_http_rejects_bad_edge_and_inconclusive_origin(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    config = _module_config(module, monkeypatch, require_origin_ip=True)
    verify_globals = module["verify_live_http"].__globals__

    monkeypatch.setitem(
        verify_globals,
        "_curl_headers",
        lambda _args: subprocess.CompletedProcess([], 7, stdout="", stderr=""),
    )
    with pytest.raises(module["VerificationError"], match="edge request failed"):
        module["verify_live_http"](config)

    responses = iter(
        [
            subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    "HTTP/2 200\r\nserver: cloudflare\r\ncf-ray: fake\r\n"
                    "location: https://sitbank.cloudflareaccess.com/cdn-cgi/access/login\r\n"
                ),
                stderr="",
            ),
        ]
    )
    monkeypatch.setitem(verify_globals, "_curl_headers", lambda _args: next(responses))
    with pytest.raises(module["VerificationError"], match="expected Cloudflare Access"):
        module["verify_live_http"](config)

    edge_ok = subprocess.CompletedProcess(
        [],
        0,
        stdout=(
            "HTTP/2 302\r\nserver: cloudflare\r\ncf-ray: fake\r\n"
            "location: https://sitbank.cloudflareaccess.com/cdn-cgi/access/login\r\n"
        ),
        stderr="",
    )
    for returncode, expected in ((35, "network_or_tls_block"), (2, "inconclusive")):
        sequence = iter(
            [
                edge_ok,
                subprocess.CompletedProcess([], returncode, stdout="", stderr=""),
            ]
        )
        monkeypatch.setitem(
            verify_globals,
            "_curl_headers",
            lambda _args, sequence=sequence: next(sequence),
        )
        if returncode == 35:
            assert expected in module["verify_live_http"](config).direct_origin_result
        else:
            with pytest.raises(module["VerificationError"], match=expected):
                module["verify_live_http"](config)


def test_remaining_provider_drift_and_apply_noop_branches(monkeypatch):
    module = runpy.run_path(str(SCRIPT))
    config = _module_config(module, monkeypatch)
    application = {
        **config.application_payload,
        "id": "app-id",
        "aud": config.access_audience,
        "self_hosted_domains": ["wrong.example.test"],
        "allowed_idps": "invalid",
    }
    drift = module["_application_drift"](application, config)
    assert any("self_hosted_domains" in item for item in drift)
    assert any("allowed_idps" in item for item in drift)
    application["self_hosted_domains"] = [config.hostname]
    application["allowed_idps"] = ["unexpected"]
    assert any(
        "allowed_idps" in item
        for item in module["_application_drift"](application, config)
    )
    policy = {**config.policy_payload, "exclude": [{"email": {"email": "x"}}]}
    assert any("exclude_rules" in item for item in module["_policy_drift"](policy, config))

    matching_app = {**config.application_payload, "id": "app-id"}
    matching_policy = {**config.policy_payload, "id": "policy-id"}
    matching_dns = {**config.dns_payload, "id": "dns-id"}
    initial = module["ProviderState"](
        matching_app,
        (matching_policy,),
        matching_dns,
    )
    final = module["ProviderState"](matching_app, (matching_policy,), matching_dns)
    states = iter([initial, final])
    monkeypatch.setitem(
        module["apply_provider_state"].__globals__,
        "read_provider_state",
        lambda _api, _config: next(states),
    )
    calls = []

    class API:
        def request(self, method, path, **kwargs):
            calls.append((method, path, kwargs))
            if method == "GET" and path.endswith("/policies"):
                return [matching_policy]
            return {}

    assert module["apply_provider_state"](API(), config) == final
    assert [method for method, _, _ in calls] == ["GET"]

    broken = module["ProviderState"]({}, (), None)
    states = iter([broken])
    monkeypatch.setitem(
        module["apply_provider_state"].__globals__,
        "read_provider_state",
        lambda _api, _config: next(states),
    )
    with pytest.raises(module["VerificationError"], match="application ID"):
        module["apply_provider_state"](API(), config)


def test_main_rejects_apply_evidence_and_wrong_confirmation(monkeypatch, tmp_path, capsys):
    module = runpy.run_path(str(SCRIPT))
    config = _module_config(module, monkeypatch)
    monkeypatch.setattr(
        module["Config"],
        "from_environment",
        classmethod(lambda _cls, *, require_origin_ip: config),
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "clearly-fake-token")
    evidence = tmp_path / "evidence.json"
    assert module["main"](["--apply", "--confirm", "wrong"]) == 1
    assert "requires --confirm" in capsys.readouterr().err
    assert module["main"](
        [
            "--apply",
            "--confirm",
            module["APPLY_CONFIRMATION"],
            "--evidence-file",
            str(evidence),
        ]
    ) == 1
    assert "valid only with --verify" in capsys.readouterr().err
