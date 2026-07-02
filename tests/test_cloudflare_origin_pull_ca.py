from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest


HELPER_PATH = Path("ops/deploy/verify-cloudflare-origin-pull-ca")
ALLOWLIST_PATH = Path(
    "ops/security/cloudflare-origin-pull-ca-allowlist.json"
)
FIXTURE_PATH = Path("tests/fixtures/cloudflare_origin_pull_test_ca.crt")
FIXTURE_FINGERPRINT = (
    "0FBAD7C5DF786982B2C20D391633A3A4D60CF59CDDE237AB77450F63EB38B52C"
)
FIXTURE_SUBJECT = (
    "CN=SITBank Test Origin Pull CA,OU=Origin Pull Test,"
    "O=SITBank Tests,C=SG"
)


def _load_verifier():
    module_name = "sitbank_origin_pull_ca_verifier"
    loader = importlib.machinery.SourceFileLoader(
        module_name,
        str(HELPER_PATH),
    )
    spec = importlib.util.spec_from_loader(module_name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    loader.exec_module(module)
    return module


@pytest.fixture
def verifier():
    return _load_verifier()


def _safe_metadata(verifier, *, group: str = "root", mode: int = 0o644):
    return verifier.FileMetadata(
        is_regular=True,
        is_symlink=False,
        owner="root",
        group=group,
        mode=mode,
    )


def _use_available_openssl(verifier, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = shutil.which("openssl")
    if executable is None:
        git_openssl = Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
        if git_openssl.is_file():
            executable = str(git_openssl)
    if executable is None:
        pytest.skip("OpenSSL is not available")
    monkeypatch.setattr(verifier.shutil, "which", lambda _name: executable)


def _write_allowlist(
    path: Path,
    *,
    fingerprint: str = FIXTURE_FINGERPRINT,
    subject: str = FIXTURE_SUBJECT,
    issuer: str = FIXTURE_SUBJECT,
) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "certificates": [
                    {
                        "description": "Repository test CA",
                        "issuer": issuer,
                        "sha256_fingerprint": fingerprint,
                        "subject": subject,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        ((True, True, "root", "root", 0o644), "must not be a symlink"),
        ((False, False, "root", "root", 0o644), "regular file"),
        ((True, False, "ubuntu", "root", 0o644), "owned by root"),
        ((True, False, "root", "staff", 0o640), "root or www-data"),
        ((True, False, "root", "root", 0o664), "mode must be"),
        ((True, False, "root", "www-data", 0o644), "mode must be"),
    ],
)
def test_certificate_metadata_failures_are_rejected(
    verifier,
    metadata,
    expected,
):
    with pytest.raises(verifier.OriginPullCAVerificationError, match=expected):
        verifier._validate_certificate_metadata(
            verifier.FileMetadata(*metadata)
        )


@pytest.mark.parametrize(
    ("group", "mode"),
    [
        ("root", 0o600),
        ("root", 0o640),
        ("root", 0o644),
        ("www-data", 0o600),
        ("www-data", 0o640),
    ],
)
def test_approved_certificate_metadata_is_accepted(
    verifier,
    group,
    mode,
):
    verifier._validate_certificate_metadata(
        _safe_metadata(verifier, group=group, mode=mode)
    )


@pytest.mark.parametrize(
    "metadata",
    [
        (True, True, "root", "root", 0o644),
        (False, False, "root", "root", 0o644),
        (True, False, "ubuntu", "root", 0o644),
        (True, False, "root", "www-data", 0o640),
        (True, False, "root", "root", 0o664),
    ],
)
def test_unsafe_allowlist_metadata_is_rejected(verifier, metadata):
    with pytest.raises(verifier.OriginPullCAVerificationError):
        verifier._validate_allowlist_metadata(
            verifier.FileMetadata(*metadata)
        )


def test_missing_certificate_fails_closed(verifier, tmp_path):
    with pytest.raises(
        verifier.OriginPullCAVerificationError,
        match="Required file is missing",
    ):
        verifier.verify_origin_pull_ca(
            tmp_path / "missing.pem",
            ALLOWLIST_PATH,
        )


@pytest.mark.parametrize(
    "contents",
    [
        b"not a certificate\n",
        FIXTURE_PATH.read_bytes() + FIXTURE_PATH.read_bytes(),
    ],
)
def test_unparsable_or_multiple_pem_certificates_are_rejected(
    verifier,
    monkeypatch,
    tmp_path,
    contents,
):
    certificate = tmp_path / "candidate.pem"
    certificate.write_bytes(contents)
    monkeypatch.setattr(
        verifier,
        "_read_metadata",
        lambda _path: _safe_metadata(verifier),
    )

    with pytest.raises(
        verifier.OriginPullCAVerificationError,
        match="exactly one PEM certificate",
    ):
        verifier.verify_origin_pull_ca(certificate, ALLOWLIST_PATH)


def test_unknown_fingerprint_is_rejected(
    verifier,
    monkeypatch,
    tmp_path,
):
    allowlist = tmp_path / "allowlist.json"
    _write_allowlist(allowlist, fingerprint="A" * 64)
    monkeypatch.setattr(
        verifier,
        "_read_metadata",
        lambda _path: _safe_metadata(verifier),
    )
    _use_available_openssl(verifier, monkeypatch)

    with pytest.raises(
        verifier.OriginPullCAVerificationError,
        match="not in the reviewed allowlist",
    ):
        verifier.verify_origin_pull_ca(FIXTURE_PATH, allowlist)


def test_subject_or_issuer_mismatch_is_rejected(
    verifier,
    monkeypatch,
    tmp_path,
):
    allowlist = tmp_path / "allowlist.json"
    _write_allowlist(allowlist, subject="CN=Unexpected")
    monkeypatch.setattr(
        verifier,
        "_read_metadata",
        lambda _path: _safe_metadata(verifier),
    )
    _use_available_openssl(verifier, monkeypatch)

    with pytest.raises(
        verifier.OriginPullCAVerificationError,
        match="subject or issuer",
    ):
        verifier.verify_origin_pull_ca(FIXTURE_PATH, allowlist)


def test_reviewed_test_ca_is_accepted(
    verifier,
    monkeypatch,
    tmp_path,
):
    allowlist = tmp_path / "allowlist.json"
    _write_allowlist(allowlist)
    monkeypatch.setattr(
        verifier,
        "_read_metadata",
        lambda _path: _safe_metadata(verifier),
    )
    _use_available_openssl(verifier, monkeypatch)

    details, entry = verifier.verify_origin_pull_ca(FIXTURE_PATH, allowlist)

    assert details.fingerprint == FIXTURE_FINGERPRINT
    assert details.subject == FIXTURE_SUBJECT
    assert details.issuer == FIXTURE_SUBJECT
    assert entry.description == "Repository test CA"


def test_cli_error_does_not_echo_certificate_contents(
    verifier,
    monkeypatch,
    tmp_path,
    capsys,
):
    marker = "DO-NOT-ECHO-CERTIFICATE-CONTENTS"
    certificate = tmp_path / "candidate.pem"
    certificate.write_text(marker, encoding="utf-8")
    monkeypatch.setattr(
        verifier,
        "_read_metadata",
        lambda _path: _safe_metadata(verifier),
    )

    assert (
        verifier.main(
            [
                "--certificate",
                str(certificate),
                "--allowlist",
                str(ALLOWLIST_PATH),
            ]
        )
        == 1
    )
    output = capsys.readouterr()
    assert marker not in output.out
    assert marker not in output.err


def test_allowlist_pins_reviewed_cloudflare_global_ca():
    allowlist = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    entry = allowlist["certificates"][0]

    assert allowlist["schema"] == 1
    assert (
        entry["sha256_fingerprint"]
        == "9A1AC2B4BE15F9F27EEE20A734CBA4E9898F61001B3BD7C84B69B56A3E25A2B9"
    )
    assert entry["subject"] == entry["issuer"]
    assert entry["source"].startswith("https://developers.cloudflare.com/")


def test_verifier_and_fixture_contain_no_secrets_or_runtime_fetches():
    helper = HELPER_PATH.read_text(encoding="utf-8")
    fixture = FIXTURE_PATH.read_text(encoding="utf-8")

    assert "PRIVATE KEY" not in fixture
    assert "CLOUDFLARE_API_TOKEN" not in helper
    assert "urllib" not in helper
    assert "requests" not in helper
    assert "curl" not in helper
    assert "https://" not in helper


def test_bootstrap_installs_and_runs_verifier_before_each_nginx_boundary():
    bootstrap = Path("ops/deploy/bootstrap-container-ec2").read_text(
        encoding="utf-8"
    )
    invocation = bootstrap.index(
        "if ! /usr/local/sbin/verify-cloudflare-origin-pull-ca"
    )
    staging_config = bootstrap.index(
        '"${repo_root}/ops/nginx/sitbank-staging.conf"',
        invocation,
    )
    production_invocation = bootstrap.index(
        "Production Cloudflare Authenticated Origin Pull CA validation failed."
    )
    production_config = bootstrap.index(
        '"${repo_root}/ops/nginx/sitbank-production.conf"',
        production_invocation,
    )

    assert "ops/security/cloudflare-origin-pull-ca-allowlist.json" in bootstrap
    assert (
        'STAGING_CLOUDFLARE_ORIGIN_PULL_CA_ALLOWLIST="/etc/'
        'sitbank-staging/cloudflare-origin-pull-ca-allowlist.json"'
    ) in bootstrap
    assert "apt-get install -y age ca-certificates curl gnupg openssl" in bootstrap
    assert "developers.cloudflare.com/ssl/static" not in bootstrap
    assert "authenticated_origin_pull_ca.pem" not in bootstrap
    assert invocation < staging_config
    assert invocation < bootstrap.index("nginx -t", invocation)
    assert production_invocation < production_config
    assert production_invocation < bootstrap.index(
        "nginx -t",
        production_invocation,
    )
