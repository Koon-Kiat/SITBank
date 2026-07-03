# SonarQube and SonarCloud Rules for SITBank Agents

Use these rules whenever a branch or pull request has a SonarQube or
SonarCloud analysis.

These are standing completion rules:

- Inspect all open issues for the current branch or pull request after analysis,
  even when the quality gate passes.
- Fix every actionable issue with focused code and tests.
- Mark an issue false positive only when the reported rule genuinely does not
  apply. Preserve the technical reason in the pull request, a narrowly scoped
  code comment, or other durable review evidence before changing provider
  status.
- Do not mark an issue false positive merely to clear a dashboard, avoid a
  refactor, raise coverage, or make a gate pass.
- Do not accept or suppress a real security, reliability, or maintainability
  issue unless the user explicitly authorizes that risk decision.
- Rerun or wait for the updated analysis and confirm that every current finding
  is fixed, false positive with evidence, or otherwise explicitly authorized.
- Report provider-side status changes honestly. A passing quality gate is not
  evidence that the branch has no remaining issues.

Keep Sonar configuration aligned with the supported runtime and preserve the
repository coverage and quality-gate requirements.
