from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


SCRIPT_PATH = Path("ops/deploy/verify-production-nginx-boundary")
PRODUCTION_NGINX = Path("ops/nginx/sitbank-production.conf")
DEFAULT_NGINX = Path("ops/nginx/sitbank-default.conf")


def _load_verifier():
    loader = importlib.machinery.SourceFileLoader(
        "production_nginx_boundary_verifier",
        str(SCRIPT_PATH),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


verifier = _load_verifier()


def _valid_configuration() -> str:
    return "\n".join(
        (
            DEFAULT_NGINX.read_text(encoding="utf-8"),
            PRODUCTION_NGINX.read_text(encoding="utf-8"),
        )
    )


def test_current_production_boundary_passes_active_config_validation():
    messages = verifier.verify_configuration(_valid_configuration())

    assert messages == [
        "OK: production raw-IP HTTP redirect is active",
        "OK: production HTTPS origin-pull verification is active",
        "OK: production six-month HSTS policy is active",
        "OK: default HTTPS rejects unknown hosts",
        "OK: public Nginx HTTPS listeners exclude Tailscale interfaces",
        "OK: public production admin access is denied",
    ]


def test_production_boundary_requires_configured_non_wildcard_bind_address():
    rendered = _valid_configuration().replace(
        "__SITBANK_PUBLIC_BIND_ADDRESS__",
        "10.0.1.25",
    )

    verifier.verify_configuration(
        rendered,
        public_bind_address="10.0.1.25",
    )
    with pytest.raises(verifier.VerificationError, match="wildcard HTTPS"):
        verifier.verify_configuration(
            rendered.replace("10.0.1.25:443", "0.0.0.0:443"),
            public_bind_address="10.0.1.25",
        )
    with pytest.raises(verifier.VerificationError, match="not bound"):
        verifier.verify_configuration(
            rendered,
            public_bind_address="10.0.1.26",
        )


def test_nginx_dump_runner_is_bounded_and_does_not_use_a_shell(monkeypatch):
    observed = {}
    monkeypatch.setattr(verifier.shutil, "which", lambda command: "/usr/sbin/nginx")

    def fake_run(arguments, **kwargs):
        observed["arguments"] = arguments
        observed["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="active", stderr="notice")

    monkeypatch.setattr(verifier.subprocess, "run", fake_run)

    assert verifier.run_nginx_dump() == verifier.CommandResult(
        0,
        "active",
        "notice",
    )
    assert observed["arguments"] == ["/usr/sbin/nginx", "-T"]
    assert "shell" not in observed["kwargs"]

    monkeypatch.setattr(
        verifier.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="x" * (verifier.MAX_NGINX_OUTPUT_BYTES + 1),
            stderr="",
        ),
    )
    with pytest.raises(verifier.VerificationError, match="unexpectedly large"):
        verifier.run_nginx_dump()


def test_nginx_dump_runner_reports_missing_and_timed_out_commands(monkeypatch):
    monkeypatch.setattr(verifier.shutil, "which", lambda command: None)
    with pytest.raises(verifier.VerificationError, match="not installed"):
        verifier.run_nginx_dump()

    monkeypatch.setattr(verifier.shutil, "which", lambda command: command)
    monkeypatch.setattr(
        verifier.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired("nginx", 20)
        ),
    )
    with pytest.raises(verifier.VerificationError, match="could not be inspected"):
        verifier.run_nginx_dump()


def test_malformed_or_missing_active_server_blocks_fail_closed():
    with pytest.raises(verifier.VerificationError, match="incomplete server"):
        verifier.verify_configuration("server { listen 80;")
    with pytest.raises(verifier.VerificationError, match="no server blocks"):
        verifier.verify_configuration("events {}")


@pytest.mark.parametrize(
    ("configuration", "message"),
    (
        (
            lambda value: value.replace(" 18.188.152.24", "", 1),
            "raw-IP name",
        ),
        (
            lambda value: value.replace(
                "return 301 https://sitbank.pp.ua$request_uri;",
                "return 301 https://www.sitbank.pp.ua$request_uri;",
                1,
            ),
            "canonical raw-origin redirect",
        ),
        (
            lambda value: value.replace(
                "ssl_client_certificate "
                "/etc/nginx/sitbank-production-cloudflare-origin-pull-ca.pem;",
                "",
                1,
            ),
            "origin-pull CA",
        ),
        (
            lambda value: value.replace("ssl_verify_client on;", "", 1),
            "ssl_verify_client on",
        ),
        (
            lambda value: value.replace(
                "max-age=15552000; includeSubDomains",
                "max-age=31536000; includeSubDomains; preload",
                1,
            ),
            "six-month production HSTS",
        ),
        (
            lambda value: value.replace(
                "server_name sitbank.pp.ua;",
                (
                    "server_name sitbank.pp.ua;\n"
                    "    add_header X-Test \"preload\" always;"
                ),
                1,
            ),
            "forbidden one-year or preload",
        ),
        (
            lambda value: value.replace("ssl_reject_handshake on;", "", 1),
            "ssl_reject_handshake on",
        ),
        (
            lambda value: value.replace(
                "location ^~ /admin {\n        return 404;\n    }",
                (
                    "location ^~ /admin {\n"
                    "        proxy_pass http://127.0.0.1:5002;\n"
                    "    }"
                ),
                1,
            ),
            "public production /admin",
        ),
        (
            lambda value: value.replace(
                "location ^~ /admin {",
                (
                    "location = /private-admin-proxy {\n"
                    "        proxy_pass http://127.0.0.1:5002;\n"
                    "    }\n\n"
                    "    location ^~ /admin {"
                ),
                1,
            ),
            "proxies to the private admin service",
        ),
    ),
)
def test_stale_production_boundary_states_fail_closed(configuration, message):
    with pytest.raises(verifier.VerificationError, match=message):
        verifier.verify_configuration(configuration(_valid_configuration()))


def test_verifier_failure_is_sanitized_and_actionable(monkeypatch, capsys):
    monkeypatch.setattr(
        verifier,
        "run_nginx_dump",
        lambda: verifier.CommandResult(1, "unrelated active config", "failure"),
    )

    assert verifier.main([]) == 1
    error = capsys.readouterr().err
    assert "nginx -T failed" in error
    assert "rerun the trusted production bootstrap" in error
    assert "unrelated active config" not in error


def test_production_bootstrap_installs_and_deploy_invokes_active_verifier():
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(
        encoding="utf-8"
    )
    deploy = Path("ops/deploy/sitbank-container-deploy").read_text(
        encoding="utf-8"
    )
    attributes = Path(".gitattributes").read_text(encoding="utf-8")

    assert SCRIPT_PATH.is_file()
    assert bootstrap.count(
        '"${repo_root}/ops/deploy/verify-production-nginx-boundary"'
    ) >= 2
    assert "/usr/local/sbin/verify-production-nginx-boundary" in bootstrap
    assert bootstrap.index("systemctl reload nginx") < bootstrap.index(
        "/usr/local/sbin/verify-production-nginx-boundary",
        bootstrap.index("systemctl reload nginx"),
    )
    deploy_call = deploy.index(
        "/usr/local/sbin/verify-production-nginx-boundary"
    )
    assert deploy_call < deploy.index('audit_log "environment=${target} result=started')
    assert "rerun the trusted production bootstrap" in SCRIPT_PATH.read_text(
        encoding="utf-8"
    )
    assert (
        "ops/deploy/verify-production-nginx-boundary text eol=lf"
        in attributes
    )
    assert b"\r\n" not in SCRIPT_PATH.read_bytes()


def test_verifier_rejects_unknown_arguments_without_inspecting_host():
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--unexpected"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "unrecognized arguments" in result.stderr


def test_main_success_uses_process_arguments_when_not_supplied(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(verifier.sys, "argv", [str(SCRIPT_PATH)])
    monkeypatch.setattr(
        verifier,
        "verify_active_configuration",
        lambda: ["OK: active production boundary"],
    )

    assert verifier.main() == 0
    assert capsys.readouterr().out == "OK: active production boundary\n"
