from __future__ import annotations

from pathlib import Path

import pytest

from ops.security import discover_lint_targets


def _write(root: Path, relative: str, content: bytes = b"") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return Path(relative)


@pytest.mark.parametrize(
    "shebang",
    (
        b"#!/bin/sh\n",
        b"#!/usr/bin/env sh\n",
        b"#!/bin/bash\n",
        b"#!/usr/bin/bash\n",
        b"#!/usr/bin/env bash\n",
        b"#!/usr/bin/env -S bash -e\n",
    ),
)
def test_shell_discovery_recognizes_supported_shebangs(tmp_path, shebang):
    candidate = _write(tmp_path, "ops/tool", shebang + b"echo safe\n")

    assert discover_lint_targets.discover_targets(
        tmp_path,
        "shell",
        [candidate],
    ) == [candidate]


def test_shell_discovery_includes_sh_files_and_ignores_non_shell_files(tmp_path):
    shell_by_extension = _write(tmp_path, "scripts/check.sh", b"echo safe\n")
    shell_by_shebang = _write(
        tmp_path,
        "ops/backups/run-backup",
        b"#!/usr/bin/env bash\nset -euo pipefail\n",
    )
    python_script = _write(
        tmp_path,
        "ops/security/check.py",
        b"#!/usr/bin/env python3\n",
    )

    assert discover_lint_targets.discover_targets(
        tmp_path,
        "shell",
        [python_script, shell_by_shebang, shell_by_extension],
    ) == [shell_by_shebang, shell_by_extension]


def test_dockerfile_discovery_is_recursive_and_name_based(tmp_path):
    root_dockerfile = _write(tmp_path, "Dockerfile", b"FROM scratch\n")
    ops_dockerfile = _write(
        tmp_path,
        "ops/container/Dockerfile.scan",
        b"FROM scratch\n",
    )
    compose = _write(tmp_path, "compose.prod.yml", b"services: {}\n")

    assert discover_lint_targets.discover_targets(
        tmp_path,
        "dockerfile",
        [compose, ops_dockerfile, root_dockerfile],
    ) == [root_dockerfile, ops_dockerfile]


def test_discovery_ignores_missing_candidates_and_rejects_unknown_kind(tmp_path):
    assert discover_lint_targets.discover_targets(
        tmp_path,
        "shell",
        [Path("missing.sh")],
    ) == []
    with pytest.raises(ValueError, match="Unsupported lint target kind"):
        discover_lint_targets.discover_targets(tmp_path, "unknown", [])


def test_cli_fails_closed_when_discovery_is_empty(monkeypatch, capsys):
    monkeypatch.setattr(discover_lint_targets, "tracked_paths", lambda _root: [])

    assert discover_lint_targets.main(["shell"]) == 1
    assert "refusing a silent pass" in capsys.readouterr().err


def test_cli_supports_line_and_nul_output(monkeypatch, capsys):
    targets = [Path("Dockerfile"), Path("ops/container/Dockerfile.scan")]
    monkeypatch.setattr(
        discover_lint_targets,
        "tracked_paths",
        lambda _root: targets,
    )
    monkeypatch.setattr(
        discover_lint_targets,
        "discover_targets",
        lambda _root, _kind, _candidates: targets,
    )

    assert discover_lint_targets.main(["dockerfile"]) == 0
    assert capsys.readouterr().out == "Dockerfile\nops/container/Dockerfile.scan\n"

    assert discover_lint_targets.main(["dockerfile", "--format", "nul"]) == 0
    assert capsys.readouterr().out == "Dockerfile\0ops/container/Dockerfile.scan\0"
