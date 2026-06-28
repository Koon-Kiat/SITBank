# SonarQube Cloud Analysis

SITBank uses SonarQube Cloud as an additional code-quality and security
analysis layer. It reports maintainability issues, duplication, coverage,
reliability findings, and security-sensitive patterns through the SonarQube
Cloud project dashboard. It does not replace pytest, CodeQL, Semgrep, Bandit,
Gitleaks/repository secret scanning, dependency auditing, Trivy, ShellCheck,
Hadolint, Syft, deployment tests, or production guard tests.

## Mode And Private-Repository Decision

Cloud analysis was selected instead of a self-hosted SonarQube server because
SITBank does not need another internet-facing service or an operator-maintained
analysis host. SonarQube must not be installed on the public production EC2
server.

As checked on 28 June 2026, the official
[SonarQube Cloud subscription documentation](https://docs.sonarsource.com/sonarqube-cloud/administering-sonarcloud/managing-subscription/subscription-plans)
allows Free-plan analysis of private projects up to 50,000 private lines of
code across the organization. Tests, comments, blank lines, excluded files,
and unsupported languages do not count toward that limit. A repository-side
count found about 11,600 nonblank/noncomment Python lines under `app`, so this
project is within the per-organization ceiling if the `wenjiangg` SonarQube
Cloud organization has enough unused private LOC and no more than five
members. The plan and usage must be confirmed in the SonarQube Cloud
organization during project import because limits and organization-wide usage
can change. Upgrade to Team or stop analysis rather than silently exceeding
the plan.

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

1. Import the private `WenJiangg/SITBank` GitHub repository into the
   `wenjiangg` SonarQube Cloud organization and confirm the generated project
   key is `WenJiangg_SITBank`.
2. Confirm current private LOC usage, member limits, plan terms, repository
   binding, and access permissions in SonarQube Cloud.
3. Generate a narrowly scoped project analysis token.
4. Store it as the GitHub Actions repository or organization secret
   `SONAR_TOKEN`. Never place it in a repository variable, environment file,
   workflow input, log, issue, or committed file.
5. Run `.github/workflows/sonarqube.yml` manually from `main`, then retain the
   successful workflow URL and SonarQube Cloud dashboard link as review
   evidence.

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
that the cloud scan was skipped.

## Coverage, Scope, And Evidence

The workflow installs `requirements-dev.lock` with hashes and runs the full
suite:

```text
python -m pytest -q -n auto --cov=app --cov-report=xml:coverage.xml --cov-report=term --durations=30 --durations-min=0.5
```

`sonar-project.properties` sends `app`, deployment/security material under
`ops`, and `config.py`, `wsgi.py`, and `admin_wsgi.py` as sources.
`tests` is test code, and `coverage.xml` supplies application coverage. Test
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

## Initial Quality-Gate And Triage Policy

The rollout is reporting-only. `sonar.qualitygate.wait=false` means the
workflow uploads analysis but does not wait for or enforce the Sonar quality
gate, and SonarQube is not part of the production deployment job. Scanner,
test, credential, or upload failures still fail the workflow; only the remote
quality-gate result is non-blocking.

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
requests, and the deliberately non-blocking quality gate. Existing CodeQL
private-repository behavior is unchanged.
