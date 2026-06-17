from __future__ import annotations

import re
from pathlib import Path

import conftest
import yaml


def test_required_pytest_markers_are_registered(pytestconfig):
    registered = {
        marker.split(":", 1)[0].strip()
        for marker in pytestconfig.getini("markers")
    }

    assert {"security", "deployment", "slow", "serial"} <= registered


def test_security_test_marker_inventory_covers_required_files():
    expected_security_files = {
        "tests/test_config.py",
        "tests/test_deployment.py",
        "tests/test_group_a_security.py",
        "tests/test_mfa_envelope_crypto.py",
        "tests/test_owasp_regressions.py",
        "tests/test_passwords.py",
        "tests/test_pentest_auth_bypass.py",
        "tests/test_redis_session_integrity.py",
        "tests/test_route_inventory_security.py",
        "tests/test_secret_scanner.py",
        "tests/test_webauthn_lifecycle.py",
    }

    assert expected_security_files <= conftest.SECURITY_TEST_FILES
    assert conftest.DEPLOYMENT_TEST_FILES <= conftest.SECURITY_TEST_FILES
    assert conftest.SLOW_TEST_FILES <= conftest.SECURITY_TEST_FILES


def test_ci_keeps_full_parallel_pytest_and_locked_dependency_checks():
    workflow_text = Path(".github/workflows/ci-deploy.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)
    test_steps = workflow["jobs"]["test"]["steps"]

    setup_python = next(step for step in test_steps if step["name"] == "Set up Python")
    cache_dependencies = set(setup_python["with"]["cache-dependency-path"].split())
    assert setup_python["with"]["cache"] == "pip"
    assert setup_python["with"]["python-version"] == "${{ env.PYTHON_VERSION }}"
    assert cache_dependencies == {"requirements.lock", "requirements-dev.lock"}

    install_step = next(step for step in test_steps if step["name"] == "Install locked dependencies")
    assert install_step["run"] == "python -m pip install --require-hashes -r requirements-dev.lock"

    checks_step = next(step for step in test_steps if step["name"] == "Run tests and security checks")
    pytest_lines = [
        line.strip()
        for line in checks_step["run"].splitlines()
        if line.strip().startswith("python -m pytest")
    ]

    assert pytest_lines == [
        "python -m pytest -q -n auto --durations=30 --durations-min=0.5"
    ]
    pytest_args = pytest_lines[0].split("pytest", 1)[1]
    assert re.search(r"\s-m\s", pytest_args) is None
    assert "tests/" not in pytest_lines[0]
    for required in (
        "python -m pip check",
        "python -m bandit -q -ll -r app ops config.py wsgi.py",
        "python -m pip_audit --disable-pip --require-hashes -r requirements.lock",
        "python -m pip_audit --disable-pip --require-hashes -r requirements-dev.lock",
        "python ops/security/check_dependency_locks.py",
        "python ops/security/scan_repository_secrets.py --history",
    ):
        assert required in checks_step["run"]


def test_all_tracked_test_files_are_collected_by_unscoped_ci_pytest():
    tracked_test_files = {
        path.as_posix()
        for path in Path("tests").glob("test_*.py")
    }

    assert "tests/test_pytest_optimization.py" in tracked_test_files
    assert conftest.SECURITY_TEST_FILES <= tracked_test_files
    assert "tests/test_pytest_optimization.py" not in conftest.SECURITY_TEST_FILES
