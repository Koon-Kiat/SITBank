# SonarQube Cloud Analysis

SITBank uses SonarQube Cloud as an additional code-quality and security
analysis layer. It reports maintainability issues, duplication, coverage,
reliability findings, and security-sensitive patterns through the SonarQube
Cloud project dashboard. It does not replace pytest, CodeQL, Semgrep, Bandit,
Gitleaks, the custom repository secret scanner, dependency auditing, Trivy, ShellCheck,
Hadolint, Syft, deployment tests, or production guard tests.

Category: [Security assurance](../README.md#assurance).

## Mode And Repository Decision

Cloud analysis was selected instead of a self-hosted SonarQube server because
SITBank does not need another internet-facing service or an operator-maintained
analysis host. SonarQube must not be installed on the public production EC2
server.

`Koon-Kiat/SITBank` is public. The repository uses the current SonarQube Cloud
public-project plan selected in the provider UI. Plan limits and provider state
must still be confirmed by an operator; repository files cannot prove the live
subscription or organization configuration.

SonarQube Cloud is a third-party SaaS: configured source code is sent to
SonarQube Cloud for analysis, together with configured test code. The
repository contains demonstration code, not real banking data, and the scan
scope explicitly excludes local
environments, dumps, databases, keys, certificates, build output, caches, and
test fixtures. Enabling the project and token confirms the repository owner's
acceptance of this processing. Do not enable Cloud analysis if that acceptance
changes; choose a separately operated non-production SonarQube server through
a reviewed follow-up instead.

## One-Time Setup And Secrets

1. Import or rebind the public `Koon-Kiat/SITBank` GitHub repository into the
   `koon-kiat` SonarQube Cloud organization and confirm the project key is
   `Koon-Kiat_SITBank`.
2. Confirm current plan terms, repository binding, and access permissions in
   SonarQube Cloud.
3. Generate a narrowly scoped project analysis token.
4. Store it as the GitHub Actions repository or organization secret
   `SONAR_TOKEN`. Never place it in a repository variable, environment file,
   workflow input, log, issue, or committed file.
5. Run `.github/workflows/ci-deploy.yml` from a pull request, a push to `main`,
   or a manual CI run, then retain the successful workflow URL and SonarQube
   Cloud dashboard link as review evidence.

Cloud mode does not use `SONAR_HOST_URL`. That setting is needed only for a
future self-hosted deployment, where a GitHub-hosted runner would also need
network reachability to the separate SonarQube host. No application,
production, deployment, AWS, SSH, database, or EC2 secret is exposed to this
workflow.

Rotate `SONAR_TOKEN` by creating a replacement in SonarQube Cloud, replacing
the GitHub secret, manually verifying a scan, and then revoking the old token.
For suspected disclosure, revoke first, replace the GitHub secret, inspect
workflow and SonarQube audit history, and treat any logged value as
compromised. Disable analysis safely by revoking/deleting the token and
disabling the workflow; a missing token intentionally fails trusted runs with
a clear error. Fork and Dependabot pull requests cannot receive ordinary
repository secrets, so they run the coverage step and emit an explicit notice
that both the cloud scan and PR comment were skipped.

## Coverage, Scope, And Evidence

The visible `Test and security checks` job (internal ID `test`) in
`.github/workflows/ci-deploy.yml` installs `requirements-dev.lock` with hashes
and runs the full suite once:

```text
python -m pytest -q -n auto --cov=. --cov-config=.coveragerc --cov-report=xml:coverage.xml --cov-report=term --durations=30 --durations-min=0.5
node tests/js/collect-browser-coverage.mjs
```

After all test and security checks pass, that job uploads `coverage.xml` and
`coverage/lcov.info` as a one-day artifact. Its downstream visible
`SonarQube analysis` job (internal ID `sonarqube`) calls the reusable
`.github/workflows/sonarqube.yml`, checks out the same resolved source commit,
downloads the coverage artifact, and runs the scanner without rerunning pytest.
This keeps the authoritative test result and SonarQube coverage input in the
same workflow run. The test and reusable scanner jobs remain read-only; a
separate trusted-PR-only `SonarQube PR comment` job (internal ID
`sonarqube-comment`) holds the narrowly scoped `pull-requests: write`
permission.

`sonar-project.properties` sends `app`, deployment/security material under
`ops`, and `config.py`, `wsgi.py`, and `admin_wsgi.py` as sources.
`tests` is test code, `coverage.xml` supplies Python coverage, and
`coverage/lcov.info` supplies browser JavaScript coverage. Test
fixtures and generated, local, secret-bearing, database, dump, key, and
certificate patterns are excluded. Security-sensitive Flask, admin, auth,
banking, session, audit, production guard, and deployment-adjacent Python code
remain in scope.

Reviewers may use the workflow run and project dashboard as evidence for
coverage, duplication, maintainability, reliability, and security review.
SonarQube Cloud findings complement the more specialized tools: CodeQL and
Semgrep inspect security patterns, dependency tools inspect known component
risk, secret scanners look for credentials, and deployment checks validate
runtime and infrastructure contracts.

The active binding is the `koon-kiat` organization and
`Koon-Kiat_SITBank` project key. Workflow dashboard links are constructed from
the validated values in `sonar-project.properties`; they must not hard-code or
fall back to a legacy owner or project. Scanner evidence is valid only when the
same run imports both `coverage.xml` and `coverage/lcov.info` for the resolved
source commit.

The reviewed main-branch cleartext-protocol finding in
`ops/container/smoke-test.sh` is an intentional private-only exception: the
URL and its ZAP baseline sink address only a named container on the isolated
ephemeral Docker smoke network and carry narrow line-scoped dispositions.
Public, staging, production, admin, deployment, and observability traffic
remain HTTPS/TLS or private OpenSSH-over-Tailscale as applicable. CodeQL
findings for the mandated
HIBP SHA-1 range lookup, keyed HMAC/PBKDF2 constructions, a non-verifier
configuration fingerprint, and exact trusted static-document assertions are
also alert-specific false positives. Each provider disposition carries its
own rationale; these decisions do not allow broad exclusions or suppression
of future findings.

Gitleaks 8.30.1 is a separate full Git history control in
`.github/workflows/gitleaks.yml`; it uses redacted output, no production
secrets, and no SARIF upload. The custom repository secret scanner also
remains in main/local CI. Neither scanner is replaced by SonarQube coverage or
security findings; triage is documented in
`docs/security/assurance/secret-scanning.md`.

## Pull-Request Summary Comment

After a successful analysis for a trusted internal pull request, the workflow
creates one informational `SonarQube Cloud Analysis` issue comment. It includes
the workflow run, a dashboard link constructed from the validated
`sonar.organization` and `sonar.projectKey` properties, the reporting-only
status, and a reminder that the quality gate is not blocking. Full findings
remain in the SonarQube Cloud dashboard.

The comment contains the hidden marker
`<!-- sitbank-sonarqube-summary -->`. Reruns paginate existing comments and
update the marker-bearing `github-actions[bot]` comment instead of creating
duplicates. Fork pull requests and Dependabot pull requests do not receive
secret-backed analysis or this write-permission comment; they receive a
workflow notice explaining the security skip. The workflow does not use
`pull_request_target`.

Commenting is isolated from scanning: the reusable scanner job has only
`contents: read`, while the caller workflow's trusted-PR-only comment job uses
SHA-pinned, Node.js 24 `actions/github-script` with `contents: read` and
`pull-requests: write`. No scanner or test step receives PR write access.

Inline review comments are intentionally not implemented. Mapping findings to
changed diff lines, controlling false-positive noise, and granting review
comment permissions require a separate reviewed design. The single sticky
summary does not replace pytest, CodeQL, Semgrep, Bandit, secret scanning,
dependency auditing, Trivy, ShellCheck, Hadolint, Syft, deployment tests, or
production guard tests.

## Reviewed Finding Dispositions

The baseline remediation treats credential-like configuration names and
generated synthetic DAST credentials as false positives only after confirming
that no reusable credential value is committed. HTTP used solely between
ephemeral containers on an isolated smoke-test network is also a reviewed
false positive; production and external traffic remain HTTPS-only.

The Python base image intentionally retains both its specific version tag and
its immutable digest. Docker resolves the image by digest, while the tag keeps
the intended `3.12.13-slim-trixie` release line visible to Dependabot. A
maintainability finding that asks for only one of those identifiers should be
accepted with this rationale rather than removing reproducible pinning or
automated version tracking.

The database-backed session hook, production-readiness mode validation, and
transactional admin database-privilege applicator use focused tested helpers so
their security decisions and rollback boundaries remain explicit. Flask CLI
registration retains one line-scoped `NOSONAR` disposition because Sonar counts
the colocated Click decorator declarations as one function even though each
command has an independent callback. Credential-like configuration names,
standardized HMAC-SHA1 TOTP use, HIBP range lookup, keyed HMAC references, and
isolated-container HTTP carry only line-scoped dispositions with an adjacent
rationale; there are no file-wide exclusions.

## Initial Quality-Gate And Triage Policy

The rollout is reporting-only. `sonar.qualitygate.wait=false` means the
workflow uploads analysis but does not wait for or enforce the Sonar quality
gate, and SonarQube is not part of the production deployment job. Scanner,
test, credential, or upload failures still fail the workflow; only the remote
quality-gate result is non-blocking. The PR summary comment is informational
and does not change that policy.

Maintainers should triage critical/high-confidence security and reliability
findings promptly, assign maintainability and duplication work by impact, and
record accepted findings in the pull request or issue. Mark a false positive
in SonarQube only with a concise rationale and reviewer agreement; do not
exclude security-sensitive code merely to improve metrics. A separate issue
may enable blocking after the baseline is reviewed, false positives are
handled, ownership and override rules are approved, and the interaction with
CodeQL, Semgrep, dependency scanning, and deployment gates is documented.

Current limitations are the external plan/organization prerequisite, the
manual `SONAR_TOKEN` setup, absent secret-backed analysis on fork pull
requests and Dependabot pull requests, no summary comments for those untrusted
events, intentionally absent inline comments, and the deliberately non-blocking
quality gate. Existing CodeQL behavior is unchanged.
