from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tests.e2e.support import _assert_local_base_url


CI_WORKFLOW_PATH = Path(".github/workflows/ci-deploy.yml")
E2E_SUPPORT_PATH = Path("tests/e2e/support.py")
E2E_TEST_PATHS = tuple(sorted(Path("tests/e2e").glob("test_*.py")))


def _combined_e2e_tests() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in E2E_TEST_PATHS)


def test_playwright_dependency_is_locked_for_browser_e2e():
    requirements = Path("requirements-dev.in").read_text(encoding="utf-8")
    lockfile = Path("requirements-dev.lock").read_text(encoding="utf-8")

    assert "playwright==1.61.0" in requirements
    assert "playwright==1.61.0" in lockfile
    assert "pyee==13.0.1" in lockfile


def test_playwright_e2e_defaults_to_opt_in_local_loopback():
    support = E2E_SUPPORT_PATH.read_text(encoding="utf-8")
    tests = _combined_e2e_tests()
    combined = f"{support}\n{tests}"

    assert not Path("tests/e2e/conftest.py").exists()
    assert "SITBANK_RUN_E2E" in combined
    assert "from tests.e2e.support import" in tests
    assert "record_console_errors" in tests
    assert "login_customer_with_mfa" in tests
    assert "from support import" not in tests
    assert "pytest.mark.skip" in tests
    assert 'make_server("127.0.0.1", 0, app, threaded=False)' in support
    assert "Playwright E2E tests may only use a loopback live server" in support
    assert "pytest.mark.e2e" in tests
    assert "https://sitbank.pp.ua" not in combined
    assert "https://staging-sitbank.pp.ua" not in combined


@pytest.mark.parametrize(
    "base_url",
    [
        "https://sitbank.pp.ua",
        "https://staging-sitbank.pp.ua",
        "https://admin-sitbank.tailca101b.ts.net",
        "http://203.0.113.10:5000",
    ],
)
def test_playwright_e2e_rejects_non_loopback_targets(base_url):
    with pytest.raises(RuntimeError, match="loopback live server"):
        _assert_local_base_url(base_url)


def test_ci_has_dedicated_playwright_browser_e2e_job():
    workflow = yaml.safe_load(CI_WORKFLOW_PATH.read_text(encoding="utf-8"))
    job = workflow["jobs"]["playwright-e2e"]
    steps = {step["name"]: step for step in job["steps"]}

    assert job["name"] == "Playwright E2E browser tests"
    assert job["needs"] == ["workflow-security", "resolve-source"]
    assert job["permissions"] == {"contents": "read"}
    assert job["env"]["SITBANK_RUN_E2E"] == "1"
    assert job["env"]["SITBANK_E2E_HEADLESS"] == "1"
    assert job["env"]["PLAYWRIGHT_BROWSERS_PATH"] == ".playwright-browsers"
    assert steps["Check out repository"]["with"] == {
        "fetch-depth": 0,
        "persist-credentials": False,
        "ref": "${{ needs.resolve-source.outputs.source_sha }}",
    }
    assert (
        steps["Set up Python"]["uses"]
        == "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
    )
    assert (
        steps["Install locked dependencies"]["run"]
        == "python -m pip install --require-hashes -r requirements-dev.lock"
    )
    assert (
        steps["Install Playwright Chromium"]["run"]
        == "python -m playwright install --with-deps chromium"
    )
    assert steps["Run Playwright E2E tests"]["run"] == (
        "python -m pytest -q tests/e2e"
    )
    assert not any("upload-artifact" in str(step) for step in job["steps"])


def test_playwright_browser_artifacts_are_ignored_and_not_committed():
    gitignore = Path(".gitignore").read_text(encoding="utf-8")

    for required in (
        ".playwright-browsers/",
        "playwright-report/",
        "test-results/",
        "tests/e2e/artifacts/",
    ):
        assert required in gitignore
    assert not any(Path("tests/e2e").glob("**/*.webm"))
    assert not any(Path("tests/e2e").glob("**/*.zip"))
    assert not any(Path("tests/e2e").glob("**/trace*"))


def test_playwright_e2e_docs_are_current():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "README.md",
            "docs/GITHUB_ACTIONS.md",
            "docs/security/assurance/test-automation-and-dependencies.md",
        )
    )

    for required in (
        "Playwright E2E browser tests",
        "SITBANK_RUN_E2E",
        "PLAYWRIGHT_BROWSERS_PATH",
        ".playwright-browsers",
        "python -m playwright install chromium",
        "python -m pytest -q tests/e2e",
        "loopback Flask server",
        "authentication, MFA, session, banking, and boundary regressions",
        "do not prove live staging or production provider state",
    ):
        assert required in docs
