from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


SCRIPT_PATH = Path("ops/deploy/verify-tailscale-admin-access")
PRIVATE_HOST = "admin-sitbank.tailca101b.ts.net"
TAILSCALE_FIXTURE_DIR = Path("tests/fixtures/tailscale")


def _load_verifier():
    loader = importlib.machinery.SourceFileLoader(
        "tailscale_admin_access_verifier",
        str(SCRIPT_PATH),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


verifier = _load_verifier()


def _serve_status(
    *,
    proxy: str = "http://127.0.0.1:5002",
    endpoint: str = f"{PRIVATE_HOST}:443",
    funnel: bool = False,
) -> str:
    return json.dumps(
        {
            "TCP": {"443": {"HTTPS": True}},
            "Web": {
                endpoint: {
                    "Handlers": {
                        "/": {
                            "Proxy": proxy,
                        }
                    }
                }
            },
            "AllowFunnel": {endpoint: funnel},
        }
    )


class FakeRunner:
    def __init__(
        self,
        *,
        listener_output: str = (
            "LISTEN 0 4096 127.0.0.1:5002 0.0.0.0:*\n"
        ),
        serve_status: str | None = None,
        funnel_status: str = "{}",
        nginx_output: str = (
            "server { listen 443 ssl; server_name sitbank.pp.ua; }\n"
        ),
    ) -> None:
        self.listener_output = listener_output
        self.serve_status = serve_status or _serve_status()
        self.funnel_status = funnel_status
        self.nginx_output = nginx_output
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, arguments):
        command = tuple(arguments)
        self.calls.append(command)
        if command == ("tailscale", "status", "--json"):
            return verifier.CommandResult(
                0,
                json.dumps(
                    {
                        "BackendState": "Running",
                        "Self": {"DNSName": f"{PRIVATE_HOST}."},
                    }
                ),
            )
        if command == ("tailscale", "debug", "prefs"):
            return verifier.CommandResult(0, json.dumps({"RunSSH": False}))
        if command == ("tailscale", "funnel", "status", "--json"):
            return verifier.CommandResult(0, self.funnel_status)
        if command == ("tailscale", "serve", "status", "--json"):
            return verifier.CommandResult(0, self.serve_status)
        if command == ("ss", "-H", "-ltn"):
            return verifier.CommandResult(0, self.listener_output)
        if command == ("nginx", "-T"):
            return verifier.CommandResult(0, self.nginx_output)
        if command[0] == "curl":
            return verifier.CommandResult(0, "200")
        raise AssertionError(f"Unexpected command: {command}")


def test_script_exists_has_safe_contract_and_is_installed_by_production_bootstrap():
    script = SCRIPT_PATH.read_text(encoding="utf-8")
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(
        encoding="utf-8"
    )
    attributes = Path(".gitattributes").read_text(encoding="utf-8")

    assert script.startswith("#!/usr/bin/env python3\n")
    assert 'choices=("serve", "ssh", "documentation-only")' in script
    assert '("tailscale", "serve", "status", "--json")' in script
    assert '("tailscale", "funnel", "status", "--json")' in script
    assert '("ss", "-H", "-ltn")' in script
    assert "127.0.0.1" in script
    assert "0.0.0.0" not in script
    assert "[::]" not in script
    assert "TAILSCALE_AUTH_KEY" not in script
    assert "TS_AUTHKEY" not in script
    assert "TS_OAUTH_SECRET" not in script
    assert "tailscale up" not in script
    assert "tailscale serve reset" not in script
    assert "tailscale funnel reset" not in script
    assert "set-config" not in script
    assert "shell=True" not in script
    assert (
        '"${repo_root}/ops/deploy/verify-tailscale-admin-access"'
        in bootstrap
    )
    assert "/usr/local/sbin/verify-tailscale-admin-access" in bootstrap
    assert "install -o root -g root -m 0755" in bootstrap
    assert (
        "ops/deploy/verify-tailscale-admin-access text eol=lf"
        in attributes
    )
    assert b"\r\n" not in SCRIPT_PATH.read_bytes()


def test_help_and_documentation_only_mode_do_not_require_live_tailscale():
    help_result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    documentation_result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--mode",
            "documentation-only",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert help_result.returncode == 0
    assert "--mode {serve,ssh,documentation-only}" in help_result.stdout
    assert documentation_result.returncode == 0
    assert "performs no live Tailscale" in documentation_result.stderr


def test_command_runner_bounds_output_and_never_uses_a_shell(monkeypatch):
    monkeypatch.setattr(verifier.shutil, "which", lambda command: f"/usr/bin/{command}")
    observed = {}

    def fake_run(arguments, **kwargs):
        observed["arguments"] = arguments
        observed["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="safe", stderr="")

    monkeypatch.setattr(verifier.subprocess, "run", fake_run)

    result = verifier.run_command(("tailscale", "status", "--json"))

    assert result == verifier.CommandResult(0, "safe", "")
    assert observed["arguments"] == [
        "/usr/bin/tailscale",
        "status",
        "--json",
    ]
    assert "shell" not in observed["kwargs"]
    with pytest.raises(verifier.VerificationError, match="large output"):
        verifier._bounded_text(
            "x" * (verifier.MAX_COMMAND_OUTPUT_BYTES + 1),
            "test",
        )


def test_command_runner_reports_missing_and_failed_commands(monkeypatch):
    monkeypatch.setattr(verifier.shutil, "which", lambda command: None)
    with pytest.raises(verifier.VerificationError, match="not installed"):
        verifier.run_command(("missing",))

    monkeypatch.setattr(verifier.shutil, "which", lambda command: command)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("tailscale", 15)

    monkeypatch.setattr(verifier.subprocess, "run", timeout)
    with pytest.raises(verifier.VerificationError, match="could not run"):
        verifier.run_command(("tailscale", "status", "--json"))


def test_json_helpers_reject_invalid_data_and_walk_nested_lists():
    with pytest.raises(verifier.VerificationError, match="valid JSON"):
        verifier._load_json("{", "test status")

    value = {"outer": [{"AllowFunnel": True}, "value"]}
    assert "value" in list(verifier._walk_json(value))
    assert verifier._values_for_key(value, "allowfunnel") == [True]
    assert verifier._contains_truthy_funnel(value)


def test_serve_mode_verifies_all_private_host_controls():
    runner = FakeRunner()

    messages = verifier.verify_host(
        "serve",
        "127.0.0.1",
        5002,
        PRIVATE_HOST,
        runner,
    )

    assert len(messages) == 8
    assert ("tailscale", "status", "--json") in runner.calls
    assert ("tailscale", "debug", "prefs") in runner.calls
    assert ("tailscale", "funnel", "status", "--json") in runner.calls
    assert ("tailscale", "serve", "status", "--json") in runner.calls
    assert ("ss", "-H", "-ltn") in runner.calls
    assert ("nginx", "-T") in runner.calls
    assert any(
        command[-1] == f"https://{PRIVATE_HOST}/login"
        for command in runner.calls
        if command[0] == "curl"
    )
    login_call = next(
        command
        for command in runner.calls
        if command[0] == "curl"
        and command[-1] == f"https://{PRIVATE_HOST}/login"
    )
    assert "--head" not in login_call
    assert ("--request", "GET") == (
        login_call[login_call.index("--request")],
        login_call[login_call.index("--request") + 1],
    )


def test_ssh_mode_verifies_safe_fallback_prerequisites_without_requiring_serve():
    runner = FakeRunner()

    messages = verifier.verify_host(
        "ssh",
        "127.0.0.1",
        5002,
        PRIVATE_HOST,
        runner,
    )

    assert len(messages) == 6
    assert ("tailscale", "serve", "status", "--json") not in runner.calls
    assert not any(
        command[-1] == f"https://{PRIVATE_HOST}/login"
        for command in runner.calls
        if command[0] == "curl"
    )


@pytest.mark.parametrize(
    "unexpected_listener",
    (
        "0.0.0.0:5002",
        "[::]:5002",
        "*:5002",
    ),
)
def test_listener_check_fails_closed_on_non_loopback_binding(
    unexpected_listener: str,
):
    runner = FakeRunner(
        listener_output=(
            "LISTEN 0 4096 127.0.0.1:5002 0.0.0.0:*\n"
            f"LISTEN 0 4096 {unexpected_listener} 0.0.0.0:*\n"
        )
    )

    with pytest.raises(
        verifier.VerificationError,
        match="non-approved listener",
    ):
        verifier.verify_admin_listener(runner, "127.0.0.1", 5002)


def test_funnel_check_fails_closed_when_any_endpoint_is_enabled():
    runner = FakeRunner(funnel_status=(
        TAILSCALE_FIXTURE_DIR / "funnel-status-enabled-1.98.json"
    ).read_text(encoding="utf-8"))

    with pytest.raises(verifier.VerificationError, match="Funnel is enabled"):
        verifier.verify_funnel_disabled(runner)


@pytest.mark.parametrize(
    "preferences",
    (
        {"RunSSH": True},
        {},
        {"RunSSH": "unknown"},
    ),
)
def test_tailscale_ssh_check_fails_closed_unless_explicitly_disabled(
    preferences,
):
    with pytest.raises(
        verifier.VerificationError,
        match="Tailscale SSH is enabled or its disabled state cannot be proved",
    ):
        verifier.verify_tailscale_ssh_disabled(
            lambda arguments: verifier.CommandResult(
                0,
                json.dumps(preferences),
            )
        )


def test_tailscale_1_98_serve_and_disabled_funnel_status_are_accepted():
    serve_status = (
        TAILSCALE_FIXTURE_DIR / "serve-status-1.98.json"
    ).read_text(encoding="utf-8")
    funnel_status = (
        TAILSCALE_FIXTURE_DIR / "funnel-status-disabled-1.98.json"
    ).read_text(encoding="utf-8")
    runner = FakeRunner(
        serve_status=serve_status,
        funnel_status=funnel_status,
    )

    verifier.verify_funnel_disabled(runner)
    verifier.verify_serve_mapping(
        runner,
        "127.0.0.1",
        5002,
        PRIVATE_HOST,
    )


def test_funnel_check_fails_closed_on_unknown_nonempty_status_schema():
    runner = FakeRunner(funnel_status=json.dumps({"Funnel": "unknown"}))

    with pytest.raises(
        verifier.VerificationError,
        match="cannot prove Funnel is disabled",
    ):
        verifier.verify_funnel_disabled(runner)


@pytest.mark.parametrize(
    ("serve_status", "message"),
    (
        (
            _serve_status(proxy="http://127.0.0.1:5000"),
            "proxy only to",
        ),
        (
            _serve_status(endpoint="other.tailnet.ts.net:443"),
            "must expose only",
        ),
        (
            json.dumps(
                {
                    "TCP": {
                        "443": {"HTTPS": True},
                        "8443": {"HTTPS": True},
                    },
                    "Web": {
                        f"{PRIVATE_HOST}:443": {
                            "Handlers": {
                                "/": {
                                    "Proxy": "http://127.0.0.1:5002"
                                }
                            }
                        }
                    },
                }
            ),
            "only on HTTPS port 443",
        ),
        (
            json.dumps(
                {
                    "Web": {
                        f"{PRIVATE_HOST}:443": {
                            "Handlers": {"/": {"Text": "unexpected"}}
                        }
                    }
                }
            ),
            "no reverse-proxy target",
        ),
    ),
)
def test_serve_check_rejects_unapproved_targets_and_handlers(
    serve_status: str,
    message: str,
):
    runner = FakeRunner(serve_status=serve_status)

    with pytest.raises(verifier.VerificationError, match=message):
        verifier.verify_serve_mapping(
            runner,
            "127.0.0.1",
            5002,
            PRIVATE_HOST,
        )


@pytest.mark.parametrize(
    "nginx_output",
    (
        "location /admin { proxy_pass http://127.0.0.1:5002; }",
        f"server_name {PRIVATE_HOST};",
    ),
)
def test_nginx_check_rejects_admin_upstream_or_private_hostname(
    nginx_output: str,
):
    runner = FakeRunner(nginx_output=nginx_output)

    with pytest.raises(verifier.VerificationError):
        verifier.verify_nginx_has_no_admin_upstream(
            runner,
            5002,
            PRIVATE_HOST,
        )


def test_settings_reject_non_loopback_and_command_fragment_inputs():
    with pytest.raises(verifier.VerificationError, match="127.0.0.0/8"):
        verifier.validate_settings("0.0.0.0", 5002, PRIVATE_HOST)
    with pytest.raises(verifier.VerificationError, match="bare hostname"):
        verifier.validate_settings(
            "127.0.0.1",
            5002,
            "https://admin.invalid/; echo unsafe",
        )
    with pytest.raises(verifier.VerificationError, match="invalid octet"):
        verifier.validate_settings("127.0.0.999", 5002, PRIVATE_HOST)
    with pytest.raises(verifier.VerificationError, match="1 through 65535"):
        verifier.validate_settings("127.0.0.1", 0, PRIVATE_HOST)
    with pytest.raises(verifier.VerificationError, match="IP literal"):
        verifier.validate_settings("127.0.0.1", 5002, "127.0.0.1")
    with pytest.raises(verifier.VerificationError, match="Tailscale DNS"):
        verifier.validate_settings("127.0.0.1", 5002, "sitbank.pp.ua")


def test_individual_checks_fail_closed_when_evidence_is_missing():
    runner = FakeRunner()

    with pytest.raises(verifier.VerificationError, match="Running state"):
        verifier.verify_tailscale_running(
            lambda arguments: verifier.CommandResult(
                0,
                json.dumps({"BackendState": "Stopped"}),
            )
        )
    with pytest.raises(verifier.VerificationError, match="Tailscale SSH"):
        verifier.verify_tailscale_ssh_disabled(
            lambda arguments: verifier.CommandResult(0, "{}")
        )
    with pytest.raises(verifier.VerificationError, match="no active admin mapping"):
        verifier.verify_serve_mapping(
            FakeRunner(serve_status="{}"),
            "127.0.0.1",
            5002,
            PRIVATE_HOST,
        )
    with pytest.raises(verifier.VerificationError, match="reports Funnel enabled"):
        verifier.verify_serve_mapping(
            FakeRunner(serve_status=_serve_status(funnel=True)),
            "127.0.0.1",
            5002,
            PRIVATE_HOST,
        )
    with pytest.raises(verifier.VerificationError, match="not listening"):
        verifier.verify_admin_listener(
            FakeRunner(listener_output=""),
            "127.0.0.1",
            5002,
        )
    with pytest.raises(verifier.VerificationError, match="readiness"):
        verifier.verify_local_admin_readiness(
            lambda arguments: verifier.CommandResult(0, "503"),
            "127.0.0.1",
            5002,
        )
    with pytest.raises(verifier.VerificationError, match="could not be inspected"):
        verifier.verify_nginx_has_no_admin_upstream(
            lambda arguments: verifier.CommandResult(1),
            5002,
            PRIVATE_HOST,
        )
    with pytest.raises(verifier.VerificationError, match="login"):
        verifier.verify_private_admin_url(
            lambda arguments: verifier.CommandResult(0, "404"),
            PRIVATE_HOST,
        )
    with pytest.raises(verifier.VerificationError, match="unsupported"):
        verifier.verify_host(
            "invalid",
            "127.0.0.1",
            5002,
            PRIVATE_HOST,
            runner,
        )


def test_argument_parsing_and_main_paths_are_covered(monkeypatch, capsys):
    monkeypatch.setenv("PRIVATE_ADMIN_HOST", PRIVATE_HOST)
    arguments = verifier.parse_args(["--mode", "serve"])
    assert arguments.mode == "serve"
    assert arguments.admin_loopback_host == "127.0.0.1"
    assert arguments.admin_loopback_port == 5002
    assert arguments.private_admin_host == PRIVATE_HOST

    assert verifier.main(["--mode", "documentation-only"]) == 0
    assert "performs no live Tailscale" in capsys.readouterr().err

    def fail_verification(*args, **kwargs):
        raise verifier.VerificationError("first failure\nsecond failure")

    monkeypatch.setattr(verifier, "verify_host", fail_verification)
    assert verifier.main(["--mode", "ssh"]) == 1
    error_output = capsys.readouterr().err
    assert "ERROR: first failure" in error_output
    assert "ERROR: second failure" in error_output


def test_private_hostname_is_discovered_from_local_tailscale_state(monkeypatch):
    monkeypatch.delenv("PRIVATE_ADMIN_HOST", raising=False)
    arguments = verifier.parse_args(["--mode", "serve"])

    assert arguments.private_admin_host is None
    assert verifier.discover_private_admin_host(FakeRunner()) == PRIVATE_HOST

    with pytest.raises(
        verifier.VerificationError,
        match="cannot provide the private admin hostname",
    ):
        verifier.discover_private_admin_host(
            lambda arguments: verifier.CommandResult(
                0,
                json.dumps({"BackendState": "Running"}),
            )
        )


def test_host_verification_reports_every_failed_required_check():
    class FailingRunner:
        def __call__(self, arguments):
            return verifier.CommandResult(1)

    with pytest.raises(verifier.VerificationError) as error:
        verifier.verify_host(
            "ssh",
            "127.0.0.1",
            5002,
            PRIVATE_HOST,
            FailingRunner(),
        )

    message = str(error.value)
    assert "Tailscale node is running" in message
    assert "Tailscale Funnel is disabled" in message
    assert "admin listener is loopback-only" in message
    assert "admin loopback readiness" in message
    assert "Nginx has no admin upstream" in message


def test_documentation_distinguishes_host_preflight_from_protected_workflow():
    documentation_paths = (
        Path("README.md"),
        Path("SECURITY.md"),
        Path("docs/DEPLOYMENT.md"),
        Path("docs/OPERATIONS.md"),
        Path("docs/GITHUB_ACTIONS.md"),
        Path("docs/security/architecture/admin-and-staging-zero-trust-access.md"),
        Path("docs/security/architecture/access-control.md"),
        Path("docs/security/governance/framework-control-matrix.md"),
        Path("docs/security/governance/security-gap-register.md"),
        Path("docs/security/governance/design-risk-register.md"),
        Path("docs/security/architecture/threat-model.md"),
        Path("docs/security/assurance/test-automation-and-dependencies.md"),
    )
    docs = "\n".join(
        path.read_text(encoding="utf-8") for path in documentation_paths
    )
    normalized = " ".join(docs.split())

    for required in (
        "ops/deploy/verify-tailscale-admin-access",
        "/usr/local/sbin/verify-tailscale-admin-access",
        "--mode serve",
        "--mode ssh",
        "--mode documentation-only",
        "127.0.0.1:5002",
        "Tailscale Funnel",
        "protected GitHub workflow",
        "operator-owned evidence",
        "Flask admin login",
        "TOTP",
        "offboarding",
        "Emergency Lockout",
    ):
        assert required in docs
    assert (
        "The two controls answer different questions."
        in normalized
    )
    assert "there is intentionally no public-admin-host setting" in docs
    assert "PUBLIC_ADMIN_HOST" not in docs
    assert "documentation-only mode performs live" not in docs
    assert "host-side Tailscale preflight is missing" not in docs.casefold()
