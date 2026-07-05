#!/usr/bin/env python3
"""Render the non-secret Prometheus environment label for host deployment."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ENVIRONMENT_PLACEHOLDER = "${OBSERVABILITY_ENVIRONMENT}"
UNRESOLVED_PLACEHOLDER_RE = re.compile(r"\$\{[^}]+\}")
VALID_ENVIRONMENTS = frozenset({"production", "staging"})
PROMETHEUS_TEMPLATE_ROOT = Path(__file__).resolve().parent / "prometheus"
TEMPLATE_PATH_ERROR = "Prometheus template must be a regular file inside the approved template directory"


def render_prometheus_config(template: str, environment: str) -> str:
    normalized_environment = environment.strip().casefold()
    if environment != normalized_environment or normalized_environment not in VALID_ENVIRONMENTS:
        raise ValueError("Prometheus environment must be staging or production")
    if ENVIRONMENT_PLACEHOLDER not in template:
        raise ValueError("Prometheus template is missing its environment placeholder")

    rendered = template.replace(ENVIRONMENT_PLACEHOLDER, normalized_environment)
    if UNRESOLVED_PLACEHOLDER_RE.search(rendered):
        raise ValueError("Prometheus template contains an unresolved placeholder")
    return rendered


def validate_prometheus_template_path(
    candidate: Path,
    *,
    allowed_root: Path = PROMETHEUS_TEMPLATE_ROOT,
) -> Path:
    if ".." in candidate.parts:
        raise ValueError(TEMPLATE_PATH_ERROR)
    try:
        root = allowed_root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(TEMPLATE_PATH_ERROR) from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(TEMPLATE_PATH_ERROR) from exc
    if candidate.is_symlink() or resolved.is_symlink() or not resolved.is_file():
        raise ValueError(TEMPLATE_PATH_ERROR)
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("template", type=Path)
    parser.add_argument("environment")
    args = parser.parse_args()

    try:
        validated_template = validate_prometheus_template_path(args.template)
    except ValueError as exc:
        parser.error(str(exc))
    print(
        render_prometheus_config(
            validated_template.read_text(encoding="utf-8"),
            args.environment,
        ),
        end="",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
