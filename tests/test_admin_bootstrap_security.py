from __future__ import annotations

from pathlib import Path


WORKFLOW_DIR = Path(".github/workflows")
DEPLOYMENT_DIRS = (Path("ops/deploy"), Path("ops/container"), Path("ops/tailscale"))
BOOTSTRAP_COMMAND_PATTERNS = (
    "flask admin bootstrap-root",
    "admin bootstrap-root",
    "bootstrap-root-admin",
)
ROOT_BOOTSTRAP_SECRET_PATTERNS = (
    "ROOT_ADMIN_PASSWORD",
    "ROOT_ADMIN_TOTP",
    "TOTP_SEED",
    "TOTP_SECRET",
    "PROVISIONING_URI",
    "OTPAUTH",
    "RECOVERY_CODE",
)


def _read_text_files(paths: list[Path]) -> dict[Path, str]:
    contents: dict[Path, str] = {}
    for path in paths:
        if path.is_file():
            try:
                contents[path] = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
    return contents


def _workflow_texts() -> dict[Path, str]:
    return _read_text_files(sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml")))


def _deployment_texts() -> dict[Path, str]:
    files: list[Path] = []
    for directory in DEPLOYMENT_DIRS:
        files.extend(path for path in directory.rglob("*") if path.is_file())
    return _read_text_files(sorted(files))


def test_github_actions_do_not_invoke_root_admin_bootstrap():
    combined = "\n".join(_workflow_texts().values()).casefold()

    for pattern in BOOTSTRAP_COMMAND_PATTERNS:
        assert pattern.casefold() not in combined


def test_deployment_scripts_do_not_invoke_root_admin_bootstrap():
    combined = "\n".join(_deployment_texts().values()).casefold()

    for pattern in BOOTSTRAP_COMMAND_PATTERNS:
        assert pattern.casefold() not in combined


def test_workflows_do_not_define_root_bootstrap_secret_channels_or_artifacts():
    workflows = _workflow_texts()
    combined = "\n".join(workflows.values())
    upper_combined = combined.upper()

    for pattern in ROOT_BOOTSTRAP_SECRET_PATTERNS:
        assert pattern not in upper_combined
    assert "bootstrap-root" not in combined.casefold()


def test_docs_preserve_manual_only_root_bootstrap_boundary():
    docs = " ".join(
        path.read_text(encoding="utf-8")
        for path in (
            Path("docs/OPERATIONS.md"),
            Path("docs/GITHUB_ACTIONS.md"),
            Path("docs/DEPLOYMENT.md"),
        )
    )
    docs = " ".join(docs.split()).casefold()

    for required in (
        "root-admin bootstrap remains a manual",
        "must not run from github actions",
        "do not paste, screenshot, commit, upload, or store the root-admin password",
        "totp secret",
        "provisioning uri",
        "separate reviewed design",
    ):
        assert required in docs
