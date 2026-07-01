from __future__ import annotations

import json
import re
from pathlib import Path

import yaml


OBS_ROOT = Path("ops/observability")


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
