from __future__ import annotations

import re
import sys
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)")


def manifest_requirements(path: Path) -> dict[str, str]:
    requirements: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-r ")):
            continue
        requirement = Requirement(line)
        specifiers = list(requirement.specifier)
        if len(specifiers) != 1 or specifiers[0].operator != "==":
            raise RuntimeError(f"{path.name} must use one exact pin per dependency")
        requirements[canonicalize_name(requirement.name)] = specifiers[0].version
    return requirements


def lock_requirements(path: Path) -> dict[str, str]:
    requirements: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        match = LOCK_PATTERN.match(raw_line)
        if match:
            requirements[canonicalize_name(match.group(1))] = match.group(2)
    return requirements


def verify_pair(manifest_name: str, lock_name: str) -> list[str]:
    manifest = manifest_requirements(ROOT / manifest_name)
    lock = lock_requirements(ROOT / lock_name)
    failures = []
    for name, expected_version in sorted(manifest.items()):
        actual_version = lock.get(name)
        if actual_version != expected_version:
            failures.append(
                f"{manifest_name}: {name}=={expected_version} is not pinned "
                f"identically in {lock_name}"
            )
    return failures


def main() -> int:
    failures = [
        *verify_pair("requirements.in", "requirements.lock"),
        *verify_pair("requirements.in", "requirements-dev.lock"),
        *verify_pair("requirements-dev.in", "requirements-dev.lock"),
    ]
    if (ROOT / "requirements.txt").exists() or (ROOT / "requirements-dev.txt").exists():
        failures.append(
            "Use only requirements.in, requirements-dev.in, and their hashed lockfiles"
        )
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Dependency manifests match hashed lockfiles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
