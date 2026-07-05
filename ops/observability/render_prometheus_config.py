#!/usr/bin/env python3
"""Render the non-secret Prometheus environment label for host deployment."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ENVIRONMENT_PLACEHOLDER = "${OBSERVABILITY_ENVIRONMENT}"
UNRESOLVED_PLACEHOLDER_RE = re.compile(r"\$\{[^}]+\}")
VALID_ENVIRONMENTS = frozenset({"production", "staging"})


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("template", type=Path)
    parser.add_argument("environment")
    args = parser.parse_args()

    if args.template.is_symlink() or not args.template.is_file():
        raise ValueError("Prometheus template must be a regular non-symlink file")
    print(
        render_prometheus_config(
            args.template.read_text(encoding="utf-8"),
            args.environment,
        ),
        end="",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
