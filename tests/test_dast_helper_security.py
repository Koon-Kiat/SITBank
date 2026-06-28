from __future__ import annotations

import importlib.util
import os
import stat
import sys
from pathlib import Path

import yaml


def _load_create_dast_session_module():
    module_path = Path("ops/container/create_dast_session.py")
    spec = importlib.util.spec_from_file_location("_create_dast_session_security", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def test_smoke_test_keeps_dast_cookie_out_of_host_command_arguments():
    smoke_test = Path("ops/container/smoke-test.sh").read_text(encoding="utf-8")

    assert "dast_cookie=" not in smoke_test
    assert "replacement=${" not in smoke_test
    assert "replacer.full_list(0).replacement=${" not in smoke_test
    assert "cat \"${work_dir}/dast/auth-cookie\"" not in smoke_test
    assert "-configfile /run/dast/zap-replacer.properties" in smoke_test
    assert "-dir /zap/wrk/.ZAP -configfile /run/dast/zap-replacer.properties" in smoke_test
    assert "--volume \"${dast_mount_source}:/run/dast:ro\"" in smoke_test
    assert "--user 10001:10001" in smoke_test
    assert "--env HOME=/zap/wrk" in smoke_test
    assert "--workdir /zap/wrk" in smoke_test
    assert "Keep the UID aligned with the 0600 DAST config owner" in smoke_test
    assert "export MSYS_NO_PATHCONV=1" in smoke_test
    assert "converted explicitly by docker_bind_source" in smoke_test


def test_dast_secret_files_are_restricted_and_cleaned_up_by_contract():
    smoke_test = Path("ops/container/smoke-test.sh").read_text(encoding="utf-8")
    creator = Path("ops/container/create_dast_session.py").read_text(encoding="utf-8")

    assert "work_dir=\"$(mktemp -d)\"" in smoke_test
    assert "trap cleanup EXIT" in smoke_test
    assert "trap on_error ERR" in smoke_test
    assert "rm -rf -- \"${work_dir}\"" in smoke_test
    assert "umask 077" in smoke_test
    assert "install_host_dir 0700 \"${work_dir}/dast\"" in smoke_test
    assert "chmod_host_path 0777 \"${work_dir}/dast\"" in smoke_test
    assert "install -d -m \"${mode}\" \"$@\"" in smoke_test
    assert "chmod \"${mode}\" \"$@\" 2>/dev/null || true" in smoke_test
    assert "the cookie and ZAP config files inside remain 0600" in smoke_test
    assert "--output /run/dast/auth-cookie" in smoke_test
    assert "--zap-replacer-config-output /run/dast/zap-replacer.properties" in smoke_test
    assert "os.umask(0o077)" in creator
    assert "os.open(path, flags, 0o600)" in creator
    assert "path.chmod(0o600)" in creator


def test_dast_session_helper_writes_restricted_cookie_and_zap_config(tmp_path):
    create_dast_session = _load_create_dast_session_module()
    cookie = "__Host-sitbank_session=Abc123._~-"
    cookie_path = tmp_path / "auth-cookie"
    config_path = tmp_path / "zap-replacer.properties"

    create_dast_session.write_cookie_output(cookie_path, cookie)
    create_dast_session.write_zap_replacer_config(config_path, cookie)

    assert cookie_path.read_text(encoding="utf-8") == cookie
    zap_config = config_path.read_text(encoding="utf-8")
    assert f"replacer.full_list(0).replacement={cookie}" in zap_config
    assert "replacer.full_list(1).replacement=https" in zap_config
    if os.name != "nt":
        assert stat.S_IMODE(cookie_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


def test_dast_session_helper_rejects_malformed_cookie_outputs(tmp_path):
    create_dast_session = _load_create_dast_session_module()

    for bad_cookie in (
        "session=abc",
        "__Host-sitbank_session=abc def",
        "__Host-sitbank_session=abc\nX-Injected: value",
    ):
        try:
            create_dast_session.write_zap_replacer_config(
                tmp_path / "zap-replacer.properties",
                bad_cookie,
            )
        except RuntimeError as exc:
            assert "malformed" in str(exc)
        else:
            raise AssertionError(f"Accepted malformed DAST cookie: {bad_cookie!r}")


def test_github_workflow_does_not_upload_dast_secret_material():
    workflow = yaml.safe_load(Path(".github/workflows/ci-deploy.yml").read_text(encoding="utf-8"))
    forbidden = ("auth-cookie", "zap-replacer.properties", "/run/dast", "${work_dir}/dast")

    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if "actions/upload-artifact@" not in str(step.get("uses", "")):
                continue
            path = str(step.get("with", {}).get("path", ""))
            assert not any(item in path for item in forbidden)

    workflow_text = Path(".github/workflows/ci-deploy.yml").read_text(encoding="utf-8")
    assert "printenv" not in workflow_text
    assert "env |" not in workflow_text


def test_dast_docs_describe_secret_file_cookie_model():
    docs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            Path("docs/GITHUB_ACTIONS.md"),
            Path("docs/security/test-automation-and-dependencies.md"),
            Path("docs/security/security-gap-register.md"),
            Path("docs/security/framework-control-matrix.md"),
            Path("docs/security/threat-model.md"),
        )
    )

    for required in (
        "DAST cookie is not passed as a raw process argument",
        "ZAP loads the authenticated-cookie replacer from a restricted",
        "Synthetic DAST users remain the only authenticated scan identities",
        "auth-cookie` or `zap-replacer.properties",
        "tests/test_dast_helper_security.py",
    ):
        assert required in docs

    assert "DAST cookies are still passed through process arguments" not in docs
