# GitHub Branch Protection Evidence

Category: [Security governance](../README.md#governance).

Repository policy uses sentence-style workflow and job display names. Job IDs
remain stable, lower-case, and machine-friendly. A required check is identified
by its exact `Workflow / Job` display name; event suffixes are avoided unless
two checks would otherwise collide.

## Expected `main` ruleset

- Require a pull request before merging, at least one approval, dismissal of
  stale approvals, conversation resolution, and Code Owner review.
- Require the branch to be up to date and require these stable PR checks:
  - `CI, publish, and deploy / Workflow security`
  - `CI, publish, and deploy / Test and security checks`
  - `CI, publish, and deploy / Dependency review`
  - `CI, publish, and deploy / Playwright E2E browser tests`
  - `CI, publish, and deploy / SonarQube analysis`
  - `ShellCheck / Repository shell scripts`
  - `Hadolint / Repository Dockerfiles`
  - `Semgrep / High-severity SAST`
  - `Gitleaks / Full-history secret scan`
  - `CodeQL / Python analysis`
  - `Commit message policy / Commit message`
  - `PR title policy / Pull request title`
- Keep SBOM/provenance publishing, OpenSSF Scorecard, PR DAST smoke,
  label/comment automation, scheduled scans, manual workflows, and post-merge
  deployment jobs reporting-only until separately reviewed and approved as
  stable blocking checks.
- Keep `Non-deploy security summary / Consolidated non-deploy security`
  reporting-only unless a separate ruleset review promotes it. The rollup is
  read-only convenience evidence; individual required security checks remain
  the authoritative branch-protection contexts.
- Do not require staging deployment, production deployment, live TLS evidence,
  or the private-admin tailnet gate before a pull request can merge. Those
  controls run after merge to `main`.
- Prevent force pushes and branch deletion; do not allow bypass except through
  an explicitly reviewed emergency process.

`.github/CODEOWNERS` covers the repository by default and calls out workflows,
operations/deployment code, security and admin code, migrations, entry-point
configuration, and security documentation. Repository files describe the
expected configuration, but they cannot prove GitHub-hosted settings. A
maintainer must compare this document with the active GitHub ruleset UI or
sanitized approved CLI/API evidence after check-name or ruleset changes and at
least quarterly.

Roll out a renamed required check by first allowing the new workflow to complete
successfully, updating the GitHub ruleset to the exact new check name, and only
then removing the old name. This avoids an unmergeable branch-protection gap.
Apply the same staged provider-side review to the newly blocking Playwright and
SonarQube checks: observe at least one successful updated run, then require the
exact display names above. The workflow independently blocks image publication
and downstream deployment if either job fails.
This repository change does not update GitHub settings automatically. Review
the active ruleset after merge for any former raw contexts such as
`deploy-staging`, `verify-staging-tls`, `sonarqube`, or `sonarqube-comment`.
Post-merge deployment and reporting-only jobs should remain non-required unless
a separate reviewed policy change explicitly promotes them.

OpenSSF Scorecard `Branch-Protection` is `provider-state-only`: a low or missing
result is not resolved by claiming this document enforces GitHub settings.
Retain a sanitized ruleset export or screenshot, compare it with this contract,
and open a focused follow-up for drift. Scorecard remains informational and not
a required pull-request check.

The sanitized GitHub API review on 2026-07-02 found status checks and stale
review dismissal configured, but zero required approving reviews, Code Owner
review disabled, and administrator enforcement disabled. That live state does
not meet the expected contract above and remains a provider-setting follow-up;
this repository change does not silently mutate branch protection. The public
Scorecard API had no SITBank project baseline before workflow rollout, so the
first merged workflow run must record the numeric score and key findings.
