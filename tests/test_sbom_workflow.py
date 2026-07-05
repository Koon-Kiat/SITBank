from __future__ import annotations

import re
import runpy
from pathlib import Path

import yaml


WORKFLOW_PATH = Path(".github/workflows/sbom.yml")
CI_WORKFLOW_PATH = Path(".github/workflows/ci-deploy.yml")


def _workflow() -> tuple[str, dict]:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    return text, yaml.load(text, Loader=yaml.BaseLoader)


def test_source_sbom_workflow_is_safe_pinned_and_automatic():
    text, workflow = _workflow()

    assert workflow["name"] == "Generate source SBOM"
    assert workflow["on"]["pull_request"]["branches"] == ["main"]
    assert workflow["on"]["push"]["branches"] == ["main"]
    assert workflow["on"]["workflow_dispatch"] == ""
    assert "pull_request_target" not in text
    assert workflow["permissions"] == {"contents": "read"}

    steps = workflow["jobs"]["source-sbom"]["steps"]
    uses = [step["uses"] for step in steps if "uses" in step]
    assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", use) for use in uses)
    checkout = steps[0]
    assert checkout["with"]["persist-credentials"] == "false"
    assert "anchore/sbom-action/download-syft@" in uses[1]
    assert steps[1]["with"]["syft-version"] == "v1.46.0"


def test_source_sbom_is_cyclonedx_json_with_predictable_retention():
    _, workflow = _workflow()
    steps = workflow["jobs"]["source-sbom"]["steps"]
    generate = next(step for step in steps if step["name"].startswith("Generate"))
    upload = next(step for step in steps if step["name"] == "Upload source SBOM")

    assert "dir:." in generate["run"]
    assert "--output cyclonedx-json=sitbank-source-sbom-cyclonedx.json" in (
        generate["run"]
    )
    assert "jq empty sitbank-source-sbom-cyclonedx.json" in generate["run"]
    assert upload["with"] == {
        "name": "sitbank-source-sbom",
        "path": "sitbank-source-sbom-cyclonedx.json",
        "if-no-files-found": "error",
        "retention-days": "30",
    }
    summary = next(step for step in steps if step["name"] == "Summarize source SBOM")
    assert "python ops/security/render_sbom_summary.py" in summary["run"]
    assert "sitbank-source-sbom-cyclonedx.json" in summary["run"]


def test_sbom_workflow_does_not_cross_deployment_or_secret_boundaries():
    text = WORKFLOW_PATH.read_text(encoding="utf-8").casefold()

    for forbidden in (
        "${{ secrets.",
        "pull_request_target",
        "packages: write",
        "id-token: write",
        "docker push",
        "tailscale",
        "cloudflare",
        "database-cutover",
        "bootstrap-container",
        "deploy-production",
        "deploy-staging",
    ):
        assert forbidden not in text
    assert "sbom: true" in CI_WORKFLOW_PATH.read_text(encoding="utf-8")


def test_sbom_documentation_distinguishes_artifact_attestation_and_scanning():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "docs/GITHUB_ACTIONS.md",
            "docs/security/assurance/test-automation-and-dependencies.md",
        )
    )

    for required in (
        ".github/workflows/sbom.yml",
        "sitbank-source-sbom",
        "sitbank-source-sbom-cyclonedx.json",
        "CycloneDX JSON",
        "30 days",
        "Buildx",
        "attestation",
        "explicit image SBOM artifact remains deferred",
        "not vulnerability scanning",
        "bounded preview",
        "pkg:pypi/",
    ):
        assert required in docs


def _summary_renderer():
    return runpy.run_path("ops/security/render_sbom_summary.py")


def test_sbom_summary_reports_ecosystems_and_bounds_python_preview():
    render_summary = _summary_renderer()["render_summary"]
    components = [
        {
            "name": f"python-package-{index}",
            "version": str(index),
            "purl": f"pkg:pypi/python-package-{index}@{index}",
        }
        for index in range(12)
    ]
    components.extend(
        [
            {
                "name": "checkout",
                "version": "v6",
                "purl": "pkg:github/actions/checkout@v6",
            },
            {"name": "web", "version": "1", "purl": "pkg:npm/web@1"},
            {"name": "libc", "version": "1", "purl": "pkg:deb/libc@1"},
            {"name": "no-purl", "version": "1"},
            {"name": "crate", "version": "1", "purl": "pkg:cargo/crate@1"},
        ]
    )

    summary = render_summary({"components": components})

    assert "### Ecosystem breakdown" in summary
    assert "| PyPI | 12 |" in summary
    assert "| GitHub actions/workflows | 1 |" in summary
    assert "| npm | 1 |" in summary
    assert "| OS/system | 1 |" in summary
    assert "| Unknown/no PURL | 1 |" in summary
    assert "| Other PURL | 1 |" in summary
    assert "Python components detected: `12`" in summary
    assert "Preview limit: `10` components" in summary
    assert summary.count("| python-package-") == 10
    assert "python-package-10" not in summary


def test_sbom_summary_explicitly_reports_no_python_and_sanitizes_markdown():
    render_summary = _summary_renderer()["render_summary"]

    summary = render_summary(
        {
            "components": [
                {
                    "name": "<unsafe>|`name`",
                    "version": "1\ninjected",
                    "purl": "pkg:npm/unsafe@1",
                }
            ]
        }
    )

    assert "Python components detected: `0`" in summary
    assert "No PyPI package URLs were detected" in summary
    assert "<unsafe>" not in summary
    assert "|`name`" not in summary
