# Security Documentation

Security documentation is grouped by purpose so architecture, assurance
evidence, and governance records remain easy to navigate.

## Architecture

- [Access control](architecture/access-control.md)
- [Admin and staging zero-trust access](architecture/admin-and-staging-zero-trust-access.md)
- [Cloudflare staging access](architecture/cloudflare-staging-access.md)
- [Production Cloudflare origin boundary](architecture/production-cloudflare-origin-boundary.md)
- [Cryptography and authentication](architecture/cryptography-and-authentication.md)
- [Session management](architecture/session-management.md)
- [Threat model](architecture/threat-model.md)

## Assurance

- [Audit and alerting](assurance/audit-and-alerting.md)
- [Operational observability with Grafana and Loki](assurance/operational-observability.md)
- [Repository secret scanning](assurance/secret-scanning.md)
- [Secure coding](assurance/secure-coding.md)
- [SonarQube Cloud](assurance/sonarqube.md)
- [Test automation and dependencies](assurance/test-automation-and-dependencies.md)

## Governance

- [Data retention and deactivation](governance/data-retention-and-deactivation.md)
- [Design risk register](governance/design-risk-register.md)
- [Framework control matrix](governance/framework-control-matrix.md)
- [GitHub branch protection evidence](governance/github-branch-protection-evidence.md)
- [Incident response](governance/incident-response.md)
- [Legacy and out-of-scope technology](governance/legacy-and-out-of-scope-technology.md)
- [Privacy and PDPA](governance/privacy-and-pdpa.md)
- [Security gap register](governance/security-gap-register.md)
- [Security governance](governance/security-governance.md)

## Cross-Functional Runbooks

- [Global verification and EC2 path inventory](../runbooks/global-verification.md)

When a document moves, update repository references and the path-sensitive
documentation tests in the same change.
