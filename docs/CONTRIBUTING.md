# Contributing

## Local CI

Run the repository's normal local checks with:

```bash
scripts/ci-local
```

Normal mode runs the Python, package, security, Git Bash syntax, and whitespace
checks. When the Docker CLI or daemon is unavailable, it explicitly reports the
Docker/Compose checks as `SKIPPED`; that successful result is partial and does
not prove the deployment Compose models on the local machine.

Before a deployment-related pull request, require full Docker/Compose local
validation:

```bash
scripts/ci-local --require-docker
```

The equivalent environment-variable interface is:

```bash
CI_LOCAL_REQUIRE_DOCKER=1 scripts/ci-local
```

Strict mode fails closed unless the Docker CLI is installed, the daemon is
reachable, the Docker Compose plugin is available, and both
`compose.prod.yml` and `compose.staging.yml` pass the repository Compose model
validator. It validates configuration only and does not start containers.

The final summary labels individual checks `PASS`, `FAIL`, or `SKIPPED` and
labels the overall result as full, partial, or failed. CI/CD remains the source
of truth for deployment validation; local strict mode is the closest
contributor-side parity check, not a replacement for protected CI.
