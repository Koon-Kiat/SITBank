#!/usr/bin/env python3
"""Render a bounded, Markdown-safe CycloneDX component summary."""

from __future__ import annotations

import argparse
import html
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any


PYTHON_COMPONENT_LIMIT = 10
PYPI_PURL_PREFIX = "pkg:pypi/"
SYSTEM_PURL_PREFIXES = (
    "pkg:alpm/",
    "pkg:apk/",
    "pkg:deb/",
    "pkg:rpm/",
)
PINNED_REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[[^\]]+\])?==([^\s\\;]+)"
)


def _safe_cell(value: object, *, limit: int = 160) -> str:
    text = " ".join(str(value or "unknown").split())
    escaped = html.escape(text[:limit], quote=False)
    for character, entity in (
        ("|", "&#124;"),
        ("`", "&#96;"),
        ("[", "&#91;"),
        ("]", "&#93;"),
        ("(", "&#40;"),
        (")", "&#41;"),
        ("!", "&#33;"),
    ):
        escaped = escaped.replace(character, entity)
    return escaped or "unknown"


def _component_purl(component: dict[str, Any]) -> str:
    return str(component.get("purl") or "").strip().casefold()


def _normalized_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _python_purl_identity(component: dict[str, Any]) -> tuple[str, str] | None:
    purl = _component_purl(component)
    if not purl.startswith(PYPI_PURL_PREFIX):
        return None
    package = (
        purl.removeprefix(PYPI_PURL_PREFIX)
        .split("?", 1)[0]
        .split("#", 1)[0]
    )
    if "@" not in package:
        return None
    name, version = package.rsplit("@", 1)
    if not name or not version:
        return None
    return (
        _normalized_python_name(urllib.parse.unquote(name)),
        urllib.parse.unquote(version).casefold(),
    )


def _read_pinned_python_dependencies(
    manifest_paths: list[Path],
) -> set[tuple[str, str]]:
    dependencies: set[tuple[str, str]] = set()
    for manifest_path in manifest_paths:
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            match = PINNED_REQUIREMENT_RE.match(line)
            if match:
                dependencies.add(
                    (
                        _normalized_python_name(match.group(1)),
                        match.group(2).casefold(),
                    )
                )
    if not dependencies:
        raise ValueError("Reviewed Python manifests contain no pinned dependencies")
    return dependencies


def _ecosystem(component: dict[str, Any]) -> str:
    purl = _component_purl(component)
    if purl.startswith(PYPI_PURL_PREFIX):
        return "PyPI"
    if purl.startswith("pkg:github/"):
        return "GitHub actions/workflows"
    if purl.startswith("pkg:npm/"):
        return "npm"
    if purl.startswith(SYSTEM_PURL_PREFIXES):
        return "OS/system"
    if not purl:
        return "Unknown/no PURL"
    return "Other PURL"


def render_summary(
    document: dict[str, Any],
    *,
    declared_python_dependencies: set[tuple[str, str]] | None = None,
    python_manifest_count: int = 0,
) -> str:
    raw_components = document.get("components") or []
    if not isinstance(raw_components, list):
        raise ValueError("CycloneDX components must be a list")
    components = [
        component for component in raw_components if isinstance(component, dict)
    ]
    ecosystem_order = (
        "PyPI",
        "GitHub actions/workflows",
        "npm",
        "OS/system",
        "Unknown/no PURL",
        "Other PURL",
    )
    counts = {
        ecosystem: sum(
            1 for component in components if _ecosystem(component) == ecosystem
        )
        for ecosystem in ecosystem_order
    }
    python_by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for component in components:
        identity = _python_purl_identity(component)
        if identity is not None:
            python_by_identity.setdefault(identity, component)
    all_python_components = list(python_by_identity.values())
    if declared_python_dependencies is None:
        python_components = all_python_components
    else:
        python_components = [
            component
            for identity, component in python_by_identity.items()
            if identity in declared_python_dependencies
        ]
    unmatched_python_count = len(all_python_components) - len(python_components)

    lines = [
        "### Python components",
        "",
        (
            "- Reviewed source-controlled Python manifests: "
            f"`{python_manifest_count}`"
        ),
        (
            "- Declared pinned Python packages: "
            f"`{len(declared_python_dependencies or set())}`"
        ),
        (
            "- Python components detected from reviewed manifests: "
            f"`{len(python_components)}`"
        ),
    ]
    if unmatched_python_count:
        lines.append(
            "- PyPI components excluded because they were not matched to reviewed "
            f"manifests: `{unmatched_python_count}`"
        )
    if python_components:
        lines.extend(
            (
                f"- Preview limit: `{PYTHON_COMPONENT_LIMIT}` components",
                "",
                "| Component | Version | Package URL |",
                "| --- | --- | --- |",
            )
        )
        for component in python_components[:PYTHON_COMPONENT_LIMIT]:
            lines.append(
                "| "
                f"{_safe_cell(component.get('name'))} | "
                f"{_safe_cell(component.get('version'))} | "
                f"{_safe_cell(component.get('purl'))} |"
            )
    else:
        lines.append(
            "- No matching `pkg:pypi/` package URLs were emitted. This is a "
            "generator/PURL detection limitation, not evidence that the source "
            "has no Python dependencies."
        )
    lines.extend(
        (
            "",
            "### Ecosystem breakdown",
            "",
            "| Ecosystem | Components |",
            "| --- | ---: |",
            *(
                f"| {ecosystem} | {counts[ecosystem]} |"
                for ecosystem in ecosystem_order
            ),
        )
    )
    return "\n".join(lines)


def _validated_input_path(
    input_path: Path, *, input_root: Path | None = None
) -> Path:
    root = (input_root if input_root is not None else Path.cwd()).resolve(
        strict=True
    )
    if input_path.is_absolute() or ".." in input_path.parts:
        raise ValueError(
            "CycloneDX input must be a relative path within the working directory"
        )

    candidate = root / input_path
    resolved_candidate = candidate.resolve(strict=True)
    try:
        resolved_candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(
            "CycloneDX input must be within the working directory"
        ) from error
    if not resolved_candidate.is_file():
        raise ValueError("CycloneDX input must be a regular file")
    return resolved_candidate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cyclonedx_json", type=Path)
    parser.add_argument(
        "--python-manifest",
        action="append",
        required=True,
        type=Path,
        help="reviewed source-controlled pinned Python dependency manifest",
    )
    args = parser.parse_args()
    input_path = _validated_input_path(args.cyclonedx_json)
    manifest_paths = [
        _validated_input_path(manifest_path)
        for manifest_path in args.python_manifest
    ]
    document = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("CycloneDX root must be an object")
    print(
        render_summary(
            document,
            declared_python_dependencies=_read_pinned_python_dependencies(
                manifest_paths
            ),
            python_manifest_count=len(manifest_paths),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
