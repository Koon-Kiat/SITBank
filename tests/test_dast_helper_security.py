from __future__ import annotations

import importlib.util
import builtins
import json
import os
import stat
import sys
from pathlib import Path

import pytest
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


def test_static_dast_helpers_import_without_pyotp(monkeypatch):
    real_import = builtins.__import__

    def import_without_pyotp(name, *args, **kwargs):
        if name == "pyotp":
            raise ModuleNotFoundError("No module named 'pyotp'")
        return real_import(name, *args, **kwargs)

    monkeypatch.delitem(sys.modules, "pyotp", raising=False)
    monkeypatch.setattr(builtins, "__import__", import_without_pyotp)

    module = _load_create_dast_session_module()

    account_number = module._generate_synthetic_account_number()
    assert len(account_number) == 12
    assert account_number.isdigit()
    assert "pyotp" not in Path("ops/container/create_dast_session.py").read_text(
        encoding="utf-8"
    )


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
    assert "--tmpfs \"/zap/wrk:rw,nosuid,nodev,size=1g,uid=10001,gid=10001,mode=1770\"" in smoke_test
    assert 'zap_mount_source="$(docker_bind_source "${work_dir}/zap")"' not in smoke_test
    assert '"${zap_mount_source}:/zap/wrk:rw"' not in smoke_test
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
    assert "Keeping ZAP caches and reports off the host" in smoke_test
    assert "install -d -m \"${mode}\" \"$@\"" in smoke_test
    assert "chmod \"${mode}\" \"$@\" 2>/dev/null || true" in smoke_test
    assert "the cookie and ZAP config files inside remain 0600" in smoke_test
    assert "--output /run/dast/auth-cookie" in smoke_test
    assert "--zap-replacer-config-output /run/dast/zap-replacer.properties" in smoke_test
    assert "os.umask(0o077)" in creator
    assert "os.open(path, flags, 0o600)" in creator
    assert "path.chmod(0o600)" in creator


def test_container_smoke_databases_use_per_run_test_credentials():
    for script_path in (
        Path("ops/container/dast-smoke.sh"),
        Path("ops/container/smoke-test.sh"),
    ):
        script = script_path.read_text(encoding="utf-8")
        assert "random_test_secret" in script
        assert "/dev/urandom" in script
        assert "ci-password" not in script


def test_dast_session_helper_writes_restricted_cookie_and_zap_config(tmp_path):
    create_dast_session = _load_create_dast_session_module()
    cookie = "__Host-sitbank_session=Abc123._~-"
    cookie_path = tmp_path / "auth-cookie"
    config_path = tmp_path / "zap-replacer.properties"

    create_dast_session.write_cookie_output(cookie_path, cookie, allowed_root=tmp_path)
    create_dast_session.write_zap_replacer_config(
        config_path,
        cookie,
        allowed_root=tmp_path,
    )

    assert cookie_path.read_text(encoding="utf-8") == cookie
    zap_config = config_path.read_text(encoding="utf-8")
    assert f"replacer.full_list(0).replacement={cookie}" in zap_config
    assert "replacer.full_list(1).replacement=https" in zap_config
    assert (
        f"replacer.full_list(2).replacement={create_dast_session.DAST_FORWARDED_FOR}"
        in zap_config
    )
    assert (
        f"replacer.full_list(3).replacement={create_dast_session.DAST_USER_AGENT}"
        in zap_config
    )
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
                allowed_root=tmp_path,
            )
        except RuntimeError as exc:
            assert "malformed" in str(exc)
        else:
            raise AssertionError(f"Accepted malformed DAST cookie: {bad_cookie!r}")


def test_dast_session_helper_rejects_output_outside_allowed_root(tmp_path):
    create_dast_session = _load_create_dast_session_module()
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside = tmp_path / "escaped-cookie"

    try:
        create_dast_session.write_cookie_output(
            outside,
            "__Host-sitbank_session=Abc123._~-",
            allowed_root=allowed_root,
        )
    except ValueError as exc:
        assert "escapes" in str(exc)
    else:
        raise AssertionError("Accepted DAST output outside the allowed root")

    assert not outside.exists()


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
            Path("docs/security/assurance/test-automation-and-dependencies.md"),
            Path("docs/security/governance/security-gap-register.md"),
            Path("docs/security/governance/framework-control-matrix.md"),
            Path("docs/security/architecture/threat-model.md"),
        )
    )

    for required in (
        "DAST cookie is not passed as a raw process argument",
        "ZAP loads the authenticated-cookie replacer from a restricted",
        "Synthetic DAST users remain the only authenticated scan identities",
        "auth-cookie` or `zap-replacer.properties",
        "X-Forwarded-For: 127.0.0.1",
        "sitbank-dast-session",
        "tests/test_dast_helper_security.py",
    ):
        assert required in docs

    assert "DAST cookies are still passed through process arguments" not in docs


class _Headers:
    def __init__(self, cookies=()):
        self.cookies = list(cookies)

    def get_all(self, name):
        assert name == "Set-Cookie"
        return self.cookies


class _Response:
    def __init__(self, body, *, status=200, cookies=()):
        self.status = status
        self.headers = _Headers(cookies)
        self._body = body

    def read(self):
        return self._body


def test_dast_client_request_builds_safe_json_request_and_captures_cookies(monkeypatch):
    module = _load_create_dast_session_module()
    seen = []

    def fake_urlopen(request, timeout):
        seen.append((request, timeout))
        return _Response(
            json.dumps({"csrf_token": "fake-csrf"}).encode(),
            cookies=["__Host-sitbank_session=fake-session; Secure; HttpOnly"],
        )

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    client = module.DastClient("http://127.0.0.1:5000/")
    result = client.request(
        "POST",
        "/auth/example",
        payload={"value": "fake"},
        csrf_token="fake-csrf",
        expected_status=200,
    )

    request, timeout = seen[0]
    assert result == {"csrf_token": "fake-csrf"}
    assert timeout == 15
    assert request.full_url == "http://127.0.0.1:5000/auth/example"
    assert json.loads(request.data) == {"value": "fake"}
    assert request.headers["X-csrftoken"] == "fake-csrf"
    assert request.headers["User-agent"] == module.DAST_USER_AGENT
    assert request.headers["X-forwarded-for"] == module.DAST_FORWARDED_FOR
    assert request.headers["X-forwarded-proto"] == "https"
    assert request.headers["Referer"] == "https://127.0.0.1:5000/"
    assert client.cookies == {"__Host-sitbank_session": "fake-session"}

    monkeypatch.setattr(
        module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b""),
    )
    assert client.request("GET", "/empty", expected_status=200) == {}


def test_dast_client_rejects_bad_status_and_non_object_json(monkeypatch):
    module = _load_create_dast_session_module()
    client = module.DastClient("http://localhost:5000")
    responses = iter(
        [
            _Response(b'{"error":"no"}', status=403),
            _Response(b"[]", status=200),
        ]
    )
    monkeypatch.setattr(
        module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: next(responses),
    )

    with pytest.raises(RuntimeError, match="returned 403"):
        client.request("GET", "/denied", expected_status=200)
    with pytest.raises(RuntimeError, match="non-object"):
        client.request("GET", "/list", expected_status=200)


def test_create_authenticated_cookie_mints_session_without_public_login(monkeypatch):
    module = _load_create_dast_session_module()
    created_users = []
    calls = []

    class FakeClient:
        def __init__(self, base_url, *, allowed_hosts):
            assert base_url == "http://smoke:5000"
            assert allowed_hosts == {"smoke"}
            self.csrf_referrer = "https://smoke:5000/"
            self.cookies = {}

        def request(self, method, path, **kwargs):
            calls.append((method, path, kwargs))
            assert self.cookies == {"__Host-sitbank_session": "fake-session"}
            return {}

    monkeypatch.setattr(module, "DastClient", FakeClient)
    monkeypatch.setattr(
        module,
        "create_dast_user",
        lambda **kwargs: created_users.append(kwargs) or 42,
    )
    monkeypatch.setattr(
        module,
        "issue_dast_session_cookie",
        lambda *, user_id, session_base_url: (
            calls.append(("ISSUE", session_base_url, {"user_id": user_id}))
            or "fake-session"
        ),
    )
    monkeypatch.setattr(module.secrets, "token_hex", lambda _size: "abc123")
    monkeypatch.setattr(module.secrets, "token_urlsafe", lambda _size: "fake-random")
    monkeypatch.setattr(module, "_generate_synthetic_phone_number", lambda: "91234567")

    cookie = module.create_authenticated_cookie(
        "http://smoke:5000",
        allowed_hosts={"smoke"},
    )

    assert cookie == "__Host-sitbank_session=fake-session"
    assert created_users[0]["username"] == "zapabc123"
    assert created_users[0]["email"].endswith("@sit.singaporetech.edu.sg")
    assert created_users[0]["phone_number"] == "91234567"
    assert calls == [
        ("ISSUE", "https://smoke:5000/", {"user_id": 42}),
        ("GET", "/auth/sessions", {"expected_status": 200}),
    ]


def test_create_authenticated_cookie_requires_issued_session_cookie(monkeypatch):
    module = _load_create_dast_session_module()

    monkeypatch.setattr(module, "create_dast_user", lambda **_kwargs: 42)
    monkeypatch.setattr(module, "issue_dast_session_cookie", lambda **_kwargs: "")
    with pytest.raises(RuntimeError, match="malformed"):
        module.create_authenticated_cookie("http://localhost:5000")


def test_create_dast_user_persists_mfa_user_and_reuses_username(app, monkeypatch):
    module = _load_create_dast_session_module()
    import app as app_module

    from app.extensions import db
    from app.models import User
    from app.security.passwords import verify_password

    monkeypatch.setattr(app_module, "create_app", lambda: app)
    monkeypatch.setattr(module, "_generate_synthetic_account_number", lambda: "123456789012")

    user_id = module.create_dast_user(
        username="zapreal",
        email="zapreal@sit.singaporetech.edu.sg",
        password="DAST-Correct-Horse-Battery-Staple-2026-A9!",
        full_name="DAST Real User",
        phone_number="91234567",
    )

    user = db.session.get(User, user_id)
    assert user is not None
    assert user.username == "zapreal"
    assert user.email == "zapreal@sit.singaporetech.edu.sg"
    assert user.full_name == "DAST Real User"
    assert user.phone_number == "91234567"
    assert user.account_number == "123456789012"
    assert user.mfa_enabled is True
    assert verify_password(
        "DAST-Correct-Horse-Battery-Staple-2026-A9!",
        user.password_hash,
    )

    reused_id = module.create_dast_user(
        username="zapreal",
        email="other@sit.singaporetech.edu.sg",
        password="DAST-Other-Correct-Horse-Battery-Staple-2026-A9!",
        full_name="Other DAST User",
        phone_number="91234568",
    )

    assert reused_id == user_id
    assert db.session.query(User).filter_by(username="zapreal").count() == 1


def test_create_dast_user_avoids_colliding_phone_numbers(app, monkeypatch):
    module = _load_create_dast_session_module()
    import app as app_module

    from app.extensions import db
    from app.models import User

    monkeypatch.setattr(app_module, "create_app", lambda: app)
    monkeypatch.setattr(module, "_generate_synthetic_phone_number", lambda: "91234568")
    monkeypatch.setattr(module, "_generate_synthetic_account_number", lambda: "123456789013")
    db.session.add(
        User(
            username="existingphone",
            email="existingphone@sit.singaporetech.edu.sg",
            password_hash="not-used",
            full_name="Existing Phone",
            phone_number="91234567",
            account_number="123456789012",
            mfa_enabled=True,
        )
    )
    db.session.commit()

    user_id = module.create_dast_user(
        username="zapcollision",
        email="zapcollision@sit.singaporetech.edu.sg",
        password="DAST-Correct-Horse-Battery-Staple-2026-A9!",
        full_name="DAST Collision User",
        phone_number="91234567",
    )

    user = db.session.get(User, user_id)
    assert user is not None
    assert user.phone_number == "91234568"
    assert user.account_number == "123456789013"


def test_issue_dast_session_cookie_persists_mfa_session(app, monkeypatch):
    module = _load_create_dast_session_module()
    import app as app_module

    from flask import request

    from app.extensions import db
    from app.models import ServerSideSession, User
    from app.security.sessions import session_lookup_hash

    monkeypatch.setattr(app_module, "create_app", lambda: app)
    user = User(
        username="dastuser",
        email="dastuser@sit.singaporetech.edu.sg",
        password_hash="not-used-by-dast-session-test",
        full_name="DAST User",
        phone_number="91234567",
        account_number="123456789012",
        mfa_enabled=False,
    )
    db.session.add(user)
    db.session.commit()

    cookie_value = module.issue_dast_session_cookie(
        user_id=user.id,
        session_base_url="https://smoke:5000/",
    )

    assert module.DAST_COOKIE_RE.fullmatch(
        f"__Host-sitbank_session={cookie_value}"
    )
    db.session.remove()
    user = db.session.get(User, user.id)
    assert user is not None
    assert user.mfa_enabled is True
    record = db.session.execute(
        db.select(ServerSideSession).where(
            ServerSideSession.session_lookup_hash == session_lookup_hash(cookie_value)
        )
    ).scalar_one()
    assert record.component == "customer"
    assert record.user_id == user.id
    assert record.payload_format == "session-hmac-v2"
    assert record.ip_address == "127.0.0.1"
    assert record.user_agent == "sitbank-dast-session"

    with app.test_request_context(
        "/auth/sessions",
        base_url="https://smoke:5000/",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
        headers={
            "Cookie": f"{app.config['SESSION_COOKIE_NAME']}={cookie_value}",
            "User-Agent": "sitbank-dast-session",
        },
    ):
        loaded_session = app.session_interface.open_session(app, request)

    assert loaded_session["user_id"] == user.id
    assert loaded_session["auth_context"] == "dast_smoke"
    assert loaded_session["mfa_verified_at"]
    assert loaded_session["fresh_mfa_verified_at"]


def test_issue_dast_session_cookie_rejects_missing_synthetic_user(app, monkeypatch):
    module = _load_create_dast_session_module()
    import app as app_module

    monkeypatch.setattr(app_module, "create_app", lambda: app)

    with pytest.raises(RuntimeError, match="Synthetic DAST user was not found"):
        module.issue_dast_session_cookie(
            user_id=999,
            session_base_url="https://smoke:5000/",
        )


def test_synthetic_identifiers_have_expected_shape(monkeypatch):
    module = _load_create_dast_session_module()
    monkeypatch.setattr(module.secrets, "randbelow", lambda _limit: 42)

    assert module._generate_synthetic_phone_number() == "91000042"
    assert module._generate_synthetic_account_number() == "000000000042"


def test_main_writes_both_restricted_outputs(monkeypatch, tmp_path):
    module = _load_create_dast_session_module()
    cookie_path = tmp_path / "cookie"
    zap_path = tmp_path / "zap.properties"
    writes = []
    monkeypatch.setattr(
        module,
        "create_authenticated_cookie",
        lambda base_url, *, allowed_hosts: "__Host-sitbank_session=fake",
    )
    monkeypatch.setattr(
        module,
        "write_cookie_output",
        lambda path, cookie, *, allowed_root: writes.append(
            ("cookie", path, cookie, allowed_root)
        ),
    )
    monkeypatch.setattr(
        module,
        "write_zap_replacer_config",
        lambda path, cookie, *, allowed_root: writes.append(
            ("zap", path, cookie, allowed_root)
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "create_dast_session.py",
            "--base-url",
            "http://smoke:5000",
            "--allow-host",
            "smoke",
            "--output",
            str(cookie_path),
            "--zap-replacer-config-output",
            str(zap_path),
            "--output-root",
            str(tmp_path),
        ],
    )

    module.main()

    assert [write[0] for write in writes] == ["cookie", "zap"]
    assert all(write[2] == "__Host-sitbank_session=fake" for write in writes)
    assert all(write[3] == tmp_path for write in writes)
