from __future__ import annotations

import json
import re
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


OBS_ROOT = Path("ops/observability")
VERIFIER_PATH = OBS_ROOT / "verify-private-observability"
PRIVATE_GRAFANA_URL = "https://grafana-sitbank.tailca101b.ts.net"
FAKE_GRAFANA_TOKEN = "fake-grafana-health-token"


def _read_observability_files() -> str:
    paths = sorted(OBS_ROOT.rglob("*"))
    paths.extend(
        [
            Path("ops/deploy/bootstrap-observability-ec2"),
            Path("docs/security/assurance/operational-observability.md"),
            Path("docs/runbooks/private-observability-grafana-loki.md"),
        ]
    )
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in paths
        if path.is_file()
    )


def _load_verifier_module():
    return runpy.run_path(str(VERIFIER_PATH))


def _status_headers(module, status: str, *headers: str):
    header_text = "\r\n".join([f"HTTP/2 {status}", *headers])
    return module["CommandResult"](
        0,
        f"{header_text}\r\n\r\nSITBANK_HTTP_CODE:{status}\n",
    )


def _make_grafana_runner(
    module,
    *,
    token: str = FAKE_GRAFANA_TOKEN,
    anonymous_status: str = "401",
    user=None,
    datasources=None,
    datasource_health_returncode: int = 0,
):
    user_payload = (
        {"login": "sitbank-verifier", "orgRole": "Viewer"}
        if user is None
        else user
    )
    datasource_payload = (
        [{"uid": "sitbank-loki", "type": "loki"}]
        if datasources is None
        else datasources
    )

    def fake_runner(arguments):
        command = tuple(arguments)
        url = command[-1]
        if url.endswith("/api/health"):
            return module["CommandResult"](0, '{"database":"ok"}')
        if url.endswith("/api/user") and f"Authorization: Bearer {token}" in command:
            return module["CommandResult"](0, json.dumps(user_payload))
        if url.endswith("/api/user"):
            return _status_headers(module, anonymous_status)
        if url.endswith("/api/datasources"):
            return module["CommandResult"](0, json.dumps(datasource_payload))
        if re.search(r"/api/datasources/uid/.+/health$", url):
            return module["CommandResult"](
                datasource_health_returncode,
                '{"status":"OK"}',
            )
        raise AssertionError(command)

    return fake_runner


def test_private_grafana_loki_alloy_deployment_files_exist_and_are_private():
    compose_path = OBS_ROOT / "compose.observability.yml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = compose["services"]

    assert set(services) == {"grafana", "loki", "alloy"}
    assert services["grafana"]["ports"] == ["127.0.0.1:3000:3000"]
    assert services["loki"]["ports"] == ["127.0.0.1:3100:3100"]
    assert "ports" not in services["alloy"]
    assert services["alloy"]["command"] == [
        "run",
        "--server.http.listen-addr=127.0.0.1:12345",
        "/etc/alloy/config.alloy",
    ]
    assert compose["networks"]["observability"]["internal"] is True

    for service_name, service in services.items():
        assert "0.0.0.0:" not in str(service.get("ports", []))
        assert service["restart"] == "unless-stopped"
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["cap_drop"] == ["ALL"]
        assert service["read_only"] is True
        assert service["image"].startswith("${")
        assert "digest reference" in service["image"]

    grafana = services["grafana"]
    assert grafana["environment"]["GF_AUTH_ANONYMOUS_ENABLED"] == "false"
    assert grafana["environment"]["GF_USERS_ALLOW_SIGN_UP"] == "false"
    assert grafana["environment"]["GF_SECURITY_ADMIN_USER__FILE"] == (
        "/run/secrets/grafana_admin_user"
    )
    assert grafana["environment"]["GF_SECURITY_ADMIN_PASSWORD__FILE"] == (
        "/run/secrets/grafana_admin_password"
    )
    assert compose["secrets"]["grafana_admin_user"]["file"] == (
        "/etc/sitbank-observability/secrets/grafana_admin_user"
    )
    assert compose["secrets"]["grafana_admin_password"]["file"] == (
        "/etc/sitbank-observability/secrets/grafana_admin_password"
    )


def test_loki_retention_and_grafana_datasource_are_configured_without_credentials():
    loki = yaml.safe_load((OBS_ROOT / "loki" / "loki.yml").read_text(encoding="utf-8"))
    datasource = yaml.safe_load(
        (
            OBS_ROOT
            / "grafana"
            / "provisioning"
            / "datasources"
            / "loki.yml"
        ).read_text(encoding="utf-8")
    )
    dashboard = json.loads(
        (
            OBS_ROOT
            / "grafana"
            / "dashboards"
            / "sitbank-operational-overview.json"
        ).read_text(encoding="utf-8")
    )

    assert loki["compactor"]["retention_enabled"] is True
    assert loki["limits_config"]["retention_period"] == "168h"
    assert loki["limits_config"]["max_query_length"] == "168h"
    assert loki["analytics"]["reporting_enabled"] is False

    loki_datasource = datasource["datasources"][0]
    assert loki_datasource["type"] == "loki"
    assert loki_datasource["url"] == "http://loki:3100"
    assert loki_datasource["access"] == "proxy"
    assert "password" not in str(loki_datasource).casefold()
    assert "token" not in str(loki_datasource).casefold()
    assert dashboard["uid"] == "sitbank-operational-overview"
    assert "SecurityAuditEvent" not in json.dumps(dashboard)


def test_alloy_collects_only_approved_sources_and_redacts_sensitive_patterns():
    alloy = (OBS_ROOT / "alloy" / "config.alloy").read_text(encoding="utf-8")

    for required in (
        '/var/log/nginx/sitbank.access.log',
        '/var/log/nginx/sitbank.error.log',
        '/var/log/nginx/sitbank-staging.access.log',
        '/var/log/nginx/sitbank-staging.error.log',
        'source_labels = ["__meta_docker_container_label_sitbank_log_collect"]',
        'regex = "true"',
        'action = "keep"',
        'target_label = "service"',
        'target_label = "environment"',
        'target_label = "host_role"',
        'replacement = "container"',
        "_SYSTEMD_UNIT=sitbank-security-alerts.service",
        "_SYSTEMD_UNIT=certbot.service",
        "_SYSTEMD_UNIT=docker.service",
        "loki.process \"redact_sensitive\"",
        "[REDACTED]",
        "loki.write \"local\"",
        "http://loki:3100/loki/api/v1/push",
    ):
        assert required in alloy

    forbidden_sources = (
        "/home",
        ".bash_history",
        "/root",
        "/etc/sitbank/secrets",
        "/etc/sitbank-staging/secrets",
        "/run/secrets",
        "raw command transcript",
        "authorization header",
        "csrf token",
        "session id",
        "cloudflare_api_token",
        "tailscale_auth",
    )
    for forbidden in forbidden_sources:
        assert forbidden not in alloy


def test_sitbank_containers_opt_in_to_observability_without_exposing_ports():
    production = yaml.safe_load(Path("compose.prod.yml").read_text(encoding="utf-8"))
    staging = yaml.safe_load(Path("compose.staging.yml").read_text(encoding="utf-8"))

    expected = {
        "sitbank.log_collect": "true",
        "sitbank.host_role": "app",
    }
    for compose, environment in ((production, "production"), (staging, "staging")):
        for service_name in ("app", "admin"):
            labels = compose["services"][service_name]["labels"]
            assert labels | expected == labels
            assert labels["sitbank.environment"] == environment
            assert labels["sitbank.service"] in {"sitbank-app", "sitbank-admin"}

    assert production["services"]["app"]["network_mode"] == "host"
    assert production["services"]["admin"]["network_mode"] == "host"
    assert staging["services"]["app"]["ports"] == ["127.0.0.1:5001:5000"]
    assert staging["services"]["admin"]["ports"] == ["127.0.0.1:5003:5000"]


def test_observability_bootstrap_and_docs_keep_credentials_out_of_repo():
    combined = _read_observability_files()
    bootstrap = Path("ops/deploy/bootstrap-observability-ec2").read_text(
        encoding="utf-8"
    )
    docs = Path("docs/runbooks/private-observability-grafana-loki.md").read_text(
        encoding="utf-8"
    )
    nginx_combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("ops/nginx").glob("*.conf")
    )
    app_combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [*Path("app").rglob("*.py"), *Path("app").rglob("*.html")]
        if path.is_file()
    )
    normalized_combined = " ".join(combined.split())

    for required in (
        "bootstrap-observability-ec2",
        "/etc/sitbank-observability/observability.env",
        "/etc/sitbank-observability/secrets/grafana_admin_user",
        "/etc/sitbank-observability/secrets/grafana_admin_password",
        "root:root mode 0600",
        "docker compose --env-file",
        "Grafana listens only on `127.0.0.1:3000`",
        "Loki listens only on `127.0.0.1:3100`",
        "The admin audit viewer remains backed by `SecurityAuditEvent`, not Loki",
    ):
        assert required in normalized_combined

    assert "cat \"${secret_file}\"" not in bootstrap
    assert "printenv" not in bootstrap
    assert "env |" not in bootstrap
    assert "GF_SECURITY_ADMIN_PASSWORD=" not in combined
    assert "loki_" + "token=" not in combined.casefold()
    assert "datasource_" + "password=" not in combined.casefold()
    assert not re.search(r"(?i)(token|password|secret)\s*=\s*['\"][^'\"]+['\"]", combined)

    for public_config in (nginx_combined, app_combined):
        lowered = public_config.casefold()
        assert "grafana" not in lowered
        assert "loki" not in lowered
        assert "<iframe" not in lowered
        assert "proxy_pass http://127.0.0.1:3000" not in public_config
        assert "proxy_pass http://127.0.0.1:3100" not in public_config

    assert "SSH local port forwarding is allowed only for bootstrap" in docs
    assert "No public Nginx production, staging, customer, or admin route" in docs


def test_private_observability_verifier_accepts_safe_mocked_live_state(tmp_path):
    module = runpy.run_path(str(VERIFIER_PATH))
    token = "fake-grafana-health-token"
    calls = []

    def fake_runner(arguments):
        command = tuple(arguments)
        calls.append(command)
        url = command[-1]
        if url.endswith("/api/health"):
            return module["CommandResult"](0, '{"database":"ok"}')
        if url.endswith("/api/user") and "Authorization: Bearer " + token in command:
            return module["CommandResult"](
                0,
                json.dumps({"login": "sitbank-verifier", "orgRole": "Viewer"}),
            )
        if url.endswith("/api/user"):
            return module["CommandResult"](
                0,
                "HTTP/2 401\r\n\nSITBANK_HTTP_CODE:401\n",
            )
        if url.endswith("/api/datasources"):
            return module["CommandResult"](
                0,
                json.dumps([{"uid": "sitbank-loki", "type": "loki"}]),
            )
        if url.endswith("/api/datasources/uid/sitbank-loki/health"):
            return module["CommandResult"](0, '{"status":"OK"}')
        if "/grafana" in url or "/loki" in url:
            return module["CommandResult"](
                0,
                "HTTP/2 404\r\n\nSITBANK_HTTP_CODE:404\n",
            )
        raise AssertionError(command)

    grafana_url = "https://grafana-sitbank.tailca101b.ts.net"
    checks = [
        *module["verify_private_grafana"](fake_runner, grafana_url, token),
        *module["verify_public_denials"](
            fake_runner,
            ("https://sitbank.pp.ua/grafana", "https://staging-sitbank.pp.ua/loki"),
        ),
    ]
    evidence = tmp_path / "private-observability.json"
    module["_write_evidence"](
        evidence,
        target_environment="staging",
        grafana_url=grafana_url,
        checks=checks,
        token=token,
    )

    evidence_text = evidence.read_text(encoding="utf-8")
    evidence_json = json.loads(evidence_text)
    assert evidence_json["result"] == "pass"
    assert evidence_json["workflow_trigger"] == "manual_protected"
    assert evidence_json["private_grafana_host"] == "grafana-sitbank.tailca101b.ts.net"
    assert {check["name"] for check in evidence_json["checks"]} >= {
        "grafana_api_health",
        "grafana_anonymous_disabled",
        "grafana_verifier_role_least_privilege",
        "loki_datasource_health",
        "public_observability_denial",
    }
    assert token not in evidence_text
    assert "Authorization" not in evidence_text
    assert "grafana_session" not in evidence_text
    assert any(
        "Authorization: Bearer " + token in command
        for command in calls
    )


def test_private_observability_verifier_fails_closed_on_public_exposure_and_admin_token():
    module = runpy.run_path(str(VERIFIER_PATH))

    with pytest.raises(module["VerificationError"], match="public SITBank"):
        module["_validate_private_grafana_url"]("https://sitbank.pp.ua")
    with pytest.raises(module["VerificationError"], match="Tailscale"):
        module["_validate_private_grafana_url"]("https://grafana.example.com")
    with pytest.raises(module["VerificationError"], match="without credentials"):
        module["_validate_private_grafana_url"](
            "https://user:pass@grafana-sitbank.tailca101b.ts.net"
        )
    with pytest.raises(module["VerificationError"], match="private Tailscale"):
        module["_validate_public_probe_url"](
            "https://grafana-sitbank.tailca101b.ts.net/grafana"
        )

    def admin_runner(arguments):
        url = tuple(arguments)[-1]
        if url.endswith("/api/health"):
            return module["CommandResult"](0, "{}")
        if url.endswith("/api/user") and "Authorization: Bearer token" in tuple(arguments):
            return module["CommandResult"](0, json.dumps({"orgRole": "Admin"}))
        if url.endswith("/api/user"):
            return module["CommandResult"](
                0,
                "HTTP/2 401\r\n\nSITBANK_HTTP_CODE:401\n",
            )
        raise AssertionError(arguments)

    with pytest.raises(module["VerificationError"], match="administrative privileges"):
        module["verify_private_grafana"](
            admin_runner,
            "https://grafana-sitbank.tailca101b.ts.net",
            "token",
        )

    def public_runner(arguments):
        return module["CommandResult"](
            0,
            "HTTP/2 200\r\nserver: grafana\r\n\nSITBANK_HTTP_CODE:200\n",
        )

    with pytest.raises(module["VerificationError"], match="public observability"):
        module["verify_public_denials"](
            public_runner,
            ("https://sitbank.pp.ua/grafana",),
        )


def test_private_grafana_url_validation_accepts_only_private_tailscale_https():
    module = _load_verifier_module()

    assert (
        module["_validate_private_grafana_url"](
            "https://grafana-sitbank.tailca101b.ts.net/"
        )
        == "https://grafana-sitbank.tailca101b.ts.net"
    )

    invalid_urls = (
        ("http://grafana-sitbank.tailca101b.ts.net", "https URL"),
        ("https:///grafana", "https URL"),
        (
            "https://user:pass@grafana-sitbank.tailca101b.ts.net",
            "without credentials",
        ),
        ("https://www.sitbank.pp.ua", "public SITBank"),
        ("https://staging-sitbank.pp.ua", "public SITBank"),
        ("https://grafana.example.com", "Tailscale"),
    )
    for url, message in invalid_urls:
        with pytest.raises(module["VerificationError"], match=message):
            module["_validate_private_grafana_url"](url)


def test_public_probe_url_validation_allows_only_public_observability_denials():
    module = _load_verifier_module()

    for path in ("/grafana", "/grafana/login", "/loki", "/logs", "/metrics"):
        url = f"https://sitbank.pp.ua{path}"
        assert module["_validate_public_probe_url"](url) == url

    invalid_urls = (
        ("http://sitbank.pp.ua/grafana", "https URLs"),
        ("https://user:pass@sitbank.pp.ua/grafana", "without credentials"),
        (
            "https://grafana-sitbank.tailca101b.ts.net/grafana",
            "private Tailscale",
        ),
        ("https://sitbank.pp.ua/health/ready", "observability-denial paths"),
        ("https://sitbank.pp.ua/grafana-public", "observability-denial paths"),
    )
    for url, message in invalid_urls:
        with pytest.raises(module["VerificationError"], match=message):
            module["_validate_public_probe_url"](url)


def test_public_probe_urls_use_defaults_and_validate_custom_input():
    module = _load_verifier_module()

    assert module["_public_probe_urls"](None) == list(module["DEFAULT_PUBLIC_PROBES"])
    assert module["_public_probe_urls"]("") == list(module["DEFAULT_PUBLIC_PROBES"])
    assert module["_public_probe_urls"](
        "https://sitbank.pp.ua/grafana\n\nhttps://staging-sitbank.pp.ua/loki\n"
    ) == ["https://sitbank.pp.ua/grafana", "https://staging-sitbank.pp.ua/loki"]

    with pytest.raises(module["VerificationError"], match="At least one"):
        module["_public_probe_urls"](" \n\t\n")
    with pytest.raises(module["VerificationError"], match="observability-denial"):
        module["_public_probe_urls"]("https://sitbank.pp.ua/health/ready")


def test_safe_json_load_and_url_label_handle_bad_inputs_safely():
    module = _load_verifier_module()

    assert module["_safe_json_load"]('{"ok": true}', "Grafana") == {"ok": True}
    with pytest.raises(module["VerificationError"], match="valid JSON"):
        module["_safe_json_load"]("{bad json", "Grafana")

    assert (
        module["_safe_url_label"]("https://sitbank.pp.ua/grafana?token=fake")
        == "sitbank.pp.ua/grafana"
    )
    assert module["_safe_url_label"]("not a url") == "<invalid>not a url"
    assert module["_safe_url_label"]("https:///grafana") == "<invalid>/grafana"


def test_run_command_fails_closed_and_returns_nonzero_results(monkeypatch):
    module = _load_verifier_module()

    monkeypatch.setattr(module["shutil"], "which", lambda _command: None)
    with pytest.raises(module["VerificationError"], match="not installed"):
        module["run_command"](("curl", "--version"))

    monkeypatch.setattr(module["shutil"], "which", lambda _command: "C:/fake/curl.exe")

    def fake_run(arguments, **kwargs):
        assert arguments == ["C:/fake/curl.exe", "--fail"]
        assert kwargs["check"] is False
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["timeout"] == 20
        return subprocess.CompletedProcess(arguments, 7, "stdout", "stderr")

    monkeypatch.setattr(module["subprocess"], "run", fake_run)
    result = module["run_command"](("curl", "--fail"))
    assert result == module["CommandResult"](7, "stdout", "stderr")

    for exception in (
        OSError("synthetic failure"),
        subprocess.TimeoutExpired("curl", 20),
    ):

        def failing_run(_arguments, **_kwargs):
            raise exception

        monkeypatch.setattr(module["subprocess"], "run", failing_run)
        with pytest.raises(module["VerificationError"], match="could not run"):
            module["run_command"](("curl", "--fail"))


def test_curl_builds_safe_headers_and_raises_on_request_failure():
    module = _load_verifier_module()
    calls = []

    def ok_runner(arguments):
        calls.append(tuple(arguments))
        return module["CommandResult"](0, '{"ok":true}')

    assert module["_curl"](ok_runner, f"{PRIVATE_GRAFANA_URL}/api/health") == (
        0,
        '{"ok":true}',
    )
    assert "Accept: application/json" in calls[-1]
    assert not any("Authorization:" in argument for argument in calls[-1])

    module["_curl"](
        ok_runner,
        f"{PRIVATE_GRAFANA_URL}/api/user",
        token=FAKE_GRAFANA_TOKEN,
    )
    assert "Accept: application/json" in calls[-1]
    assert f"Authorization: Bearer {FAKE_GRAFANA_TOKEN}" in calls[-1]

    def failing_runner(_arguments):
        return module["CommandResult"](28, "", "timeout")

    with pytest.raises(module["VerificationError"], match="request failed"):
        module["_curl"](failing_runner, f"{PRIVATE_GRAFANA_URL}/api/health")


def test_curl_status_headers_parses_statuses_and_handles_curl_failures():
    module = _load_verifier_module()

    for returncode in (0, 22, 47):

        def runner(_arguments, code=returncode):
            return module["CommandResult"](
                code,
                "HTTP/2 403\r\nx-safe: true\r\n\r\nSITBANK_HTTP_CODE:403\n",
            )

        status, headers = module["_curl_status_headers"](
            runner,
            "https://sitbank.pp.ua/grafana",
        )
        assert status == "403"
        assert "x-safe: true" in headers

    def unexpected_failure(_arguments):
        return module["CommandResult"](
            6,
            "HTTP/2 000\r\n\r\nSITBANK_HTTP_CODE:000\n",
        )

    assert module["_curl_status_headers"](
        unexpected_failure,
        "https://sitbank.pp.ua/grafana",
    ) == ("000", "")

    def redirect_denial(_arguments):
        return module["CommandResult"](
            47,
            (
                "HTTP/2 302\r\n"
                "location: https://sitbank.pp.ua/login\r\n\r\n"
                "SITBANK_HTTP_CODE:302\n"
            ),
        )

    status, headers = module["_curl_status_headers"](
        redirect_denial,
        "https://sitbank.pp.ua/grafana",
    )
    assert status == "302"
    assert "location: https://sitbank.pp.ua/login" in headers


def test_verify_private_grafana_fails_closed_for_unsafe_grafana_states():
    module = _load_verifier_module()

    with pytest.raises(module["VerificationError"], match="TOKEN is required"):
        module["verify_private_grafana"](
            _make_grafana_runner(module),
            PRIVATE_GRAFANA_URL,
            "",
        )

    unsafe_cases = (
        (
            _make_grafana_runner(module, anonymous_status="200"),
            "anonymous API access",
        ),
        (
            _make_grafana_runner(module, user={"isGrafanaAdmin": True}),
            "administrative privileges",
        ),
        (
            _make_grafana_runner(module, user={"orgRole": "Admin"}),
            "administrative privileges",
        ),
        (
            _make_grafana_runner(module, datasources={"unexpected": "schema"}),
            "unexpected schema",
        ),
        (
            _make_grafana_runner(
                module,
                datasources=[{"uid": "prometheus", "type": "prometheus"}],
            ),
            "no Loki datasource",
        ),
        (
            _make_grafana_runner(
                module,
                datasources=[{"uid": "../unsafe", "type": "loki"}],
            ),
            "UID is missing or unsafe",
        ),
        (
            _make_grafana_runner(module, datasource_health_returncode=28),
            "request failed",
        ),
    )
    for runner, message in unsafe_cases:
        with pytest.raises(module["VerificationError"], match=message):
            module["verify_private_grafana"](
                runner,
                PRIVATE_GRAFANA_URL,
                FAKE_GRAFANA_TOKEN,
            )


def test_verify_public_denials_accepts_closed_statuses_and_sanitizes_records():
    module = _load_verifier_module()
    statuses = {
        "https://sitbank.pp.ua/grafana": "404",
        "https://staging-sitbank.pp.ua/loki": "403",
    }

    def closed_runner(arguments):
        return _status_headers(module, statuses[tuple(arguments)[-1]])

    checks = module["verify_public_denials"](closed_runner, tuple(statuses))
    assert checks == [
        {
            "name": "public_observability_denial",
            "result": "pass",
            "target": "sitbank.pp.ua/grafana",
            "http_status": "404",
        },
        {
            "name": "public_observability_denial",
            "result": "pass",
            "target": "staging-sitbank.pp.ua/loki",
            "http_status": "403",
        },
    ]
    assert "HTTP/2" not in json.dumps(checks)
    assert "location:" not in json.dumps(checks).casefold()


@pytest.mark.parametrize(
    ("status", "header", "message"),
    (
        ("200", "server: nginx", "public observability"),
        ("302", "location: https://sitbank.pp.ua/grafana/login", "public observability"),
        ("302", "location: https://sitbank.pp.ua/loki/", "public observability"),
        ("404", "authorization: Bearer fake", "sensitive observability headers"),
        ("404", "cookie: grafana_session=fake", "sensitive observability headers"),
        ("404", "cf-access-jwt-assertion: fake", "sensitive observability headers"),
        ("404", "set-cookie: grafana_session=fake", "sensitive observability headers"),
        ("404", "x-grafana-org-id: 1", "sensitive observability headers"),
    ),
)
def test_verify_public_denials_fails_closed_on_exposure_or_sensitive_headers(
    status,
    header,
    message,
):
    module = _load_verifier_module()

    def public_runner(_arguments):
        return _status_headers(module, status, header)

    with pytest.raises(module["VerificationError"], match=message):
        module["verify_public_denials"](
            public_runner,
            ("https://sitbank.pp.ua/grafana",),
        )


def test_write_evidence_creates_parent_and_retains_only_sanitized_fields(tmp_path):
    module = _load_verifier_module()
    evidence_path = tmp_path / "nested" / "private-observability.json"
    checks = [
        {
            "name": "public_observability_denial",
            "result": "pass",
            "target": "sitbank.pp.ua/grafana",
            "http_status": "404",
        }
    ]

    module["_write_evidence"](
        evidence_path,
        target_environment="production",
        grafana_url=PRIVATE_GRAFANA_URL,
        checks=checks,
        token=FAKE_GRAFANA_TOKEN,
    )

    evidence_text = evidence_path.read_text(encoding="utf-8")
    evidence = json.loads(evidence_text)
    assert evidence["target_environment"] == "production"
    assert evidence["private_grafana_host"] == "grafana-sitbank.tailca101b.ts.net"
    assert evidence["checks"] == checks
    assert evidence["sanitization"] == {
        "access_assertions_retained": False,
        "cookies_retained": False,
        "credentials_retained": False,
        "raw_http_bodies_retained": False,
    }
    for forbidden in (
        FAKE_GRAFANA_TOKEN,
        "Authorization: Bearer",
        "grafana_session=fake",
        "cf-access-jwt-assertion: fake",
        "raw response body",
    ):
        assert forbidden not in evidence_text


def test_write_evidence_refuses_to_write_if_token_would_be_retained(tmp_path):
    module = _load_verifier_module()
    evidence_path = tmp_path / "nested" / "private-observability.json"

    with pytest.raises(module["VerificationError"], match="contains the Grafana token"):
        module["_write_evidence"](
            evidence_path,
            target_environment="staging",
            grafana_url=PRIVATE_GRAFANA_URL,
            checks=[{"name": "unsafe", "result": FAKE_GRAFANA_TOKEN}],
            token=FAKE_GRAFANA_TOKEN,
        )

    assert not evidence_path.exists()


def test_parse_args_restricts_target_environment_and_accepts_overrides(tmp_path):
    module = _load_verifier_module()
    evidence_path = tmp_path / "private-observability.json"

    args = module["parse_args"](
        [
            "--target-environment",
            "production",
            "--grafana-url",
            PRIVATE_GRAFANA_URL,
            "--public-probe-url",
            "https://sitbank.pp.ua/grafana",
            "--evidence-file",
            str(evidence_path),
        ]
    )
    assert args.target_environment == "production"
    assert args.grafana_url == PRIVATE_GRAFANA_URL
    assert args.public_probe_url == ["https://sitbank.pp.ua/grafana"]
    assert args.evidence_file == str(evidence_path)

    with pytest.raises(SystemExit):
        module["parse_args"](["--target-environment", "development"])


def test_main_success_uses_env_and_writes_evidence_override(
    monkeypatch,
    tmp_path,
    capsys,
):
    module = _load_verifier_module()
    grafana_runner = _make_grafana_runner(module)
    calls = []

    def fake_run_command(arguments):
        command = tuple(arguments)
        calls.append(command)
        url = command[-1]
        if url.startswith(PRIVATE_GRAFANA_URL):
            return grafana_runner(command)
        return _status_headers(module, "404")

    monkeypatch.setitem(module["main"].__globals__, "run_command", fake_run_command)
    monkeypatch.setenv("GRAFANA_PRIVATE_URL", f"{PRIVATE_GRAFANA_URL}/")
    monkeypatch.setenv("GRAFANA_HEALTH_TOKEN", FAKE_GRAFANA_TOKEN)
    monkeypatch.setenv(
        "OBSERVABILITY_PUBLIC_PROBE_URLS",
        "https://sitbank.pp.ua/grafana\nhttps://www.sitbank.pp.ua/loki\n",
    )
    evidence_path = tmp_path / "custom" / "private-observability.json"

    assert module["main"](
        [
            "--target-environment",
            "production",
            "--evidence-file",
            str(evidence_path),
        ]
    ) == 0

    captured = capsys.readouterr()
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert f"written to {evidence_path}" in captured.out
    assert captured.err == ""
    assert evidence["target_environment"] == "production"
    assert evidence["private_grafana_host"] == "grafana-sitbank.tailca101b.ts.net"
    assert FAKE_GRAFANA_TOKEN not in evidence_path.read_text(encoding="utf-8")
    assert any(f"Authorization: Bearer {FAKE_GRAFANA_TOKEN}" in call for call in calls)


def test_main_failure_returns_one_and_prints_sanitized_error(monkeypatch, capsys):
    module = _load_verifier_module()
    monkeypatch.setenv("GRAFANA_HEALTH_TOKEN", FAKE_GRAFANA_TOKEN)

    result = module["main"](
        [
            "--grafana-url",
            "https://sitbank.pp.ua",
            "--public-probe-url",
            "https://sitbank.pp.ua/grafana",
        ]
    )

    captured = capsys.readouterr()
    assert result == 1
    assert "ERROR: GRAFANA_PRIVATE_URL must not be a public SITBank hostname" in captured.err
    assert FAKE_GRAFANA_TOKEN not in captured.err


def test_script_entrypoint_exits_with_sanitized_failure(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [str(VERIFIER_PATH), "--grafana-url", "https://sitbank.pp.ua"],
    )
    monkeypatch.setenv("GRAFANA_HEALTH_TOKEN", FAKE_GRAFANA_TOKEN)

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(str(VERIFIER_PATH), run_name="__main__")

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert "ERROR: GRAFANA_PRIVATE_URL must not be a public SITBank hostname" in captured.err
    assert FAKE_GRAFANA_TOKEN not in captured.err
