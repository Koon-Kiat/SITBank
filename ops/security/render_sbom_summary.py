#!/usr/bin/env python3
"""Render a bounded, Markdown-safe CycloneDX component summary."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any


PYTHON_COMPONENT_LIMIT = 10
SYSTEM_PURL_PREFIXES = (
    "pkg:alpm/",
    "pkg:apk/",
    "pkg:deb/",
    "pkg:rpm/",
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


def _ecosystem(component: dict[str, Any]) -> str:
    purl = _component_purl(component)
    if purl.startswith("pkg:pypi/"):
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


def render_summary(document: dict[str, Any]) -> str:
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
    python_components = [
        component
        for component in components
        if _component_purl(component).startswith("pkg:pypi/")
    ]

    lines = [
        "### Ecosystem breakdown",
        "",
        "| Ecosystem | Components |",
        "| --- | ---: |",
        *(
            f"| {ecosystem} | {counts[ecosystem]} |"
            for ecosystem in ecosystem_order
        ),
        "",
        "### Python components",
        "",
        f"- Python components detected: `{len(python_components)}`",
    ]
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
            "- No PyPI package URLs were detected; inspect the full artifact "
            "before concluding that the source has no Python dependencies."
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
    args = parser.parse_args()
    input_path = _validated_input_path(args.cyclonedx_json)
    document = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("CycloneDX root must be an object")
    print(render_summary(document))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
