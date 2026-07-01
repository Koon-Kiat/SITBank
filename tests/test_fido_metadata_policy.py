from __future__ import annotations

import base64
import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from app.security import fido_mds


AAGUID = "12345678-1234-5678-1234-567812345678"
OTHER_AAGUID = "87654321-4321-8765-4321-876543218765"
ROOT_DER = b"clearly-fake-der-certificate"
ROOT_B64 = base64.b64encode(ROOT_DER).decode("ascii")


def _entry(
    *,
    aaguid: str = AAGUID,
    status: str = "FIDO_CERTIFIED_L2",
    roots: list[str] | None = None,
) -> dict:
    return {
        "aaguid": aaguid,
        "statusReports": [{"status": status}],
        "metadataStatement": {
            "attestationRootCertificates": [ROOT_B64] if roots is None else roots,
        },
    }


def _cache(*entries: dict, next_update: date | str | None = None) -> dict:
    return {
        "entries": list(entries),
        "nextUpdate": str(next_update or (date.today() + timedelta(days=1))),
    }


def test_normalize_aaguid_accepts_uuid_forms_and_rejects_invalid_value():
    assert fido_mds.normalize_aaguid(AAGUID.upper()) == AAGUID
    with pytest.raises(fido_mds.FidoMetadataError, match="Invalid authenticator AAGUID"):
        fido_mds.normalize_aaguid("not-an-aaguid")


def test_read_json_maps_file_and_json_failures_to_safe_errors(tmp_path, monkeypatch):
    valid = tmp_path / "metadata.json"
    valid.write_text(json.dumps({"entries": []}), encoding="utf-8")
    assert fido_mds._read_json(valid) == {"entries": []}

    missing = tmp_path / "missing.json"
    with pytest.raises(fido_mds.FidoMetadataError, match="not found"):
        fido_mds._read_json(missing)

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(fido_mds.FidoMetadataError, match="invalid JSON"):
        fido_mds._read_json(invalid)

    def raise_permission(_self, **_kwargs):
        raise PermissionError

    monkeypatch.setattr(Path, "read_text", raise_permission)
    with pytest.raises(fido_mds.FidoMetadataError, match="not readable"):
        fido_mds._read_json(valid)

    def raise_os_error(_self, **_kwargs):
        raise OSError

    monkeypatch.setattr(Path, "read_text", raise_os_error)
    with pytest.raises(fido_mds.FidoMetadataError, match="could not be read"):
        fido_mds._read_json(valid)


@pytest.mark.parametrize(
    ("cache", "expected"),
    [
        ({}, True),
        ({"nextUpdate": "invalid"}, True),
        ({"next_update": str(date.today() - timedelta(days=1))}, True),
        ({"nextUpdate": str(date.today())}, False),
        ({"nextUpdate": str(date.today() + timedelta(days=1))}, False),
    ],
)
def test_cache_staleness_is_fail_closed(cache, expected):
    assert fido_mds._cache_is_stale(cache) is expected


def test_entry_helpers_accept_metadata_variants_and_ignore_invalid_aaguid():
    nested = {
        "metadataStatement": {
            "aaguid": AAGUID,
            "attestationRootCertificates": [ROOT_B64],
        },
        "status_reports": [{"status": " FIDO_CERTIFIED_L2 "}, {}, {"status": ""}],
    }

    assert fido_mds._entry_aaguid(nested) == AAGUID
    assert fido_mds._entry_aaguid({"aaguid": "bad"}) is None
    assert fido_mds._entry_aaguid({}) is None
    assert fido_mds._entry_statuses(nested) == {"FIDO_CERTIFIED_L2"}
    assert fido_mds._entry_root_certificates(nested)[0].startswith(
        b"-----BEGIN CERTIFICATE-----\n"
    )
    assert fido_mds._entry_root_certificates(
        {"metadata_statement": {"attestation_root_certificates": [ROOT_B64]}}
    )
    assert fido_mds._entry_for_aaguid(_cache(nested), AAGUID) == nested
    assert fido_mds._entry_for_aaguid(_cache(nested), OTHER_AAGUID) is None


def test_certificate_conversion_wraps_base64_and_rejects_invalid_input():
    pem = fido_mds._base64_der_to_pem(base64.b64encode(b"x" * 80).decode("ascii"))

    assert pem.startswith(b"-----BEGIN CERTIFICATE-----\n")
    assert pem.endswith(b"\n-----END CERTIFICATE-----\n")
    encoded_lines = pem.decode("ascii").splitlines()[1:-1]
    assert [len(line) for line in encoded_lines] == [64, 44]
    with pytest.raises(fido_mds.FidoMetadataError, match="invalid attestation root"):
        fido_mds._base64_der_to_pem("%%%")


def test_pem_roots_include_only_approved_authenticators(monkeypatch):
    monkeypatch.setattr(fido_mds, "_approved_aaguid_policy", lambda: ({AAGUID}, set()))
    monkeypatch.setattr(
        fido_mds,
        "_mds_cache",
        lambda: _cache(_entry(), _entry(aaguid=OTHER_AAGUID)),
    )

    roots_by_format = fido_mds.pem_root_certs_by_fmt()

    assert set(roots_by_format) == fido_mds.ATTESTATION_FORMATS_REQUIRING_ROOTS
    assert all(len(roots) == 1 for roots in roots_by_format.values())
    assert all(roots[0].startswith(b"-----BEGIN CERTIFICATE-----") for roots in roots_by_format.values())
    assert fido_mds._approved_aaguids() == {AAGUID}
    assert fido_mds.validate_fido_metadata_config() == 0


def test_aaguid_policy_rejects_unapproved_stale_missing_and_dangerous_metadata(monkeypatch):
    monkeypatch.setattr(fido_mds, "_approved_aaguid_policy", lambda: ({AAGUID}, set()))
    monkeypatch.setattr(fido_mds, "_mds_cache", lambda: _cache())
    with pytest.raises(fido_mds.FidoMetadataError, match="not approved"):
        fido_mds.validate_aaguid_policy(OTHER_AAGUID, "none")
    with pytest.raises(fido_mds.FidoMetadataError, match="not present"):
        fido_mds.validate_aaguid_policy(AAGUID, "none")

    monkeypatch.setattr(
        fido_mds,
        "_mds_cache",
        lambda: _cache(_entry(), next_update=date.today() - timedelta(days=1)),
    )
    with pytest.raises(fido_mds.FidoMetadataError, match="cache is stale"):
        fido_mds.validate_aaguid_policy(AAGUID, "none")

    monkeypatch.setattr(
        fido_mds,
        "_mds_cache",
        lambda: _cache(_entry(status="REVOKED")),
    )
    with pytest.raises(fido_mds.FidoMetadataError, match="compromised or revoked"):
        fido_mds.validate_aaguid_policy(AAGUID, "none")


def test_aaguid_policy_enforces_certification_and_required_roots(monkeypatch):
    monkeypatch.setattr(fido_mds, "_approved_aaguid_policy", lambda: ({AAGUID}, set()))
    monkeypatch.setattr(
        fido_mds,
        "_mds_cache",
        lambda: _cache(_entry(status="FIDO_CERTIFIED", roots=[])),
    )
    with pytest.raises(fido_mds.FidoMetadataError, match="certification level"):
        fido_mds.validate_aaguid_policy(AAGUID, "none")

    monkeypatch.setattr(
        fido_mds,
        "_mds_cache",
        lambda: _cache(_entry(status="FIDO_CERTIFIED_L2", roots=[])),
    )
    with pytest.raises(fido_mds.FidoMetadataError, match="lacks attestation trust roots"):
        fido_mds.validate_aaguid_policy(AAGUID, "PACKED")

    fido_mds.validate_aaguid_policy(AAGUID, "none")


def test_legacy_level_one_policy_allows_missing_entry_and_matching_certification(monkeypatch):
    monkeypatch.setattr(fido_mds, "_approved_aaguid_policy", lambda: (set(), {AAGUID}))
    monkeypatch.setattr(fido_mds, "_mds_cache", lambda: _cache())
    fido_mds.validate_aaguid_policy(AAGUID, "none")

    monkeypatch.setattr(
        fido_mds,
        "_mds_cache",
        lambda: _cache(_entry(status="FIDO_CERTIFIED", roots=[])),
    )
    fido_mds.validate_aaguid_policy(AAGUID, "none")
