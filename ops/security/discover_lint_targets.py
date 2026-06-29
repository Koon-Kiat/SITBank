#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path


SHELL_SHEBANG = re.compile(
    rb"^#![ \t]*(?:(?:/usr)?/bin/(?:ba)?sh|/usr/bin/env[ \t]+"
    rb"(?:-S[ \t]+)?(?:ba)?sh)(?:[ \t]|$)"
)


def tracked_paths(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [
        Path(raw.decode("utf-8"))
        for raw in result.stdout.split(b"\0")
        if raw
    ]


def has_shell_shebang(path: Path) -> bool:
    try:
        with path.open("rb") as source:
            first_line = source.readline(512)
    except OSError:
        return False
    return SHELL_SHEBANG.match(first_line) is not None


def is_shell_script(root: Path, relative: Path) -> bool:
    return relative.suffix.casefold() == ".sh" or has_shell_shebang(root / relative)


def is_dockerfile(relative: Path) -> bool:
    return relative.name == "Dockerfile" or relative.name.startswith("Dockerfile.")


def discover_targets(
    root: Path,
    kind: str,
    candidates: Iterable[Path],
) -> list[Path]:
    if kind == "shell":
        predicate = lambda path: is_shell_script(root, path)
    elif kind == "dockerfile":
        predicate = is_dockerfile
    else:
        raise ValueError(f"Unsupported lint target kind: {kind}")

    return sorted(
        (
            path
            for path in candidates
            if (root / path).is_file() and predicate(path)
        ),
        key=lambda path: path.as_posix(),
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Discover tracked repository files for static-analysis tools.",
    )
    parser.add_argument("kind", choices=("shell", "dockerfile"))
    parser.add_argument(
        "--format",
        choices=("lines", "nul"),
        default="lines",
        dest="output_format",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    targets = discover_targets(root, args.kind, tracked_paths(root))
    if not targets:
        print(
            f"No tracked {args.kind} lint targets were found; refusing a silent pass.",
            file=sys.stderr,
        )
        return 1

    separator = "\0" if args.output_format == "nul" else "\n"
    sys.stdout.write(separator.join(path.as_posix() for path in targets))
    sys.stdout.write(separator)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
