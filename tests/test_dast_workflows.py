from pathlib import Path

import yaml


def test_pr_dast_smoke_is_local_automatic_and_time_bounded():
    path = Path(".github/workflows/dast-pr-smoke.yml")
    text = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)

    triggers = workflow[True]
    assert triggers["pull_request"]["branches"] == ["main"]
    assert "workflow_dispatch" in triggers
    assert "pull_request_target" not in text
    assert workflow["permissions"] == {"contents": "read"}

    job = workflow["jobs"]["smoke"]
    assert job["name"] == "Local ephemeral application"
    assert job["timeout-minutes"] == 15
    checkout = next(step for step in job["steps"] if step["name"] == "Check out repository")
    assert checkout["with"]["persist-credentials"] is False
    smoke = next(step for step in job["steps"] if step.get("id") == "smoke")
    assert "timeout --signal=TERM 12m" in smoke["run"]
    assert "ops/container/smoke-test.sh" in smoke["run"]
    assert smoke["env"]["RUN_ZAP_BASELINE"] == "true"
    helper = Path("ops/container/smoke-test.sh").read_text(encoding="utf-8")
    assert "zap-baseline.py" in helper
    assert "-m 2" in helper and "-T 5" in helper
    assert "10020\\tFAIL\\tAnti-clickjacking header" in helper
    assert "10021\\tFAIL\\tX-Content-Type-Options header" in helper
    assert "10038\\tFAIL\\tContent Security Policy header" in helper
    assert 'zap_baseline_target="http://${app_container}:5000/"' in helper
    assert '-t "${zap_baseline_target}" # NOSONAR' in helper
    for required_runtime_setting in (
        "--env PASSWORD_RESET_ENABLED=true",
        "--env PASSWORD_RESET_EMAIL_BACKEND=smtp",
        "--env SMTP_HOST=smtp.example.test",
        "--env SMTP_USERNAME_FILE=/run/secrets/smtp_username",
        "--env SMTP_PASSWORD_FILE=/run/secrets/smtp_password",
        "--env SECURITY_ALERT_WEBHOOK_URL_FILE=/run/secrets/security_alert_webhook_url",
    ):
        assert required_runtime_setting in helper
    assert "apply-runtime-db-privileges" in helper
    assert "verify-runtime-db-privileges" in helper
    assert "dump_container_diagnostics" in helper
    assert "target=isolated-docker-network" in text
    assert "staging-sitbank.pp.ua" not in text
    assert "sitbank.pp.ua" not in text
    assert "admin-sitbank" not in text
    assert "auth-cookie" not in text
    assert "zap-replacer.properties" not in text
    assert "pr-dast-report/summary.txt" in text


def test_pr_dast_does_not_replace_release_dast():
    release_workflow = Path(".github/workflows/ci-deploy.yml").read_text(encoding="utf-8")
    smoke_helper = Path("ops/container/smoke-test.sh").read_text(encoding="utf-8")

    assert "RUN_ZAP_DAST" in release_workflow
    assert 'if [[ "${RUN_ZAP_DAST:-false}" == "true" ]]' in smoke_helper
