# Private Grafana Loki Observability Runbook

Use this runbook to install and operate the private SITBank Grafana, Loki, and
Grafana Alloy stack from `ops/observability/`.

## Access Model

- Grafana binds to `127.0.0.1:3000` on the EC2 host.
- Loki binds to `127.0.0.1:3100` on the EC2 host.
- Alloy does not publish a host port.
- Grafana and Loki also join `sitbank-observability-loopback`.
  `sitbank-observability-loopback` is a bridge network used only for Docker's
  host-loopback port publishing. The private boundary is the explicit
  `127.0.0.1` host binding plus no public Nginx/Tailscale Funnel route.
- `sitbank-observability` remains an internal service network for
  container-to-container traffic.
- Normal operator access uses a private Tailscale path such as
  `https://grafana-sitbank.tailca101b.ts.net/` mapped to local Grafana.
- SSH local port forwarding is allowed only for bootstrap or break-glass
  troubleshooting.
- No public Nginx production, staging, customer, or admin route proxies Grafana,
  Loki, or Alloy.
- Private browser access must use SSH local forwarding or a reviewed private
  Tailscale access design, not public Nginx.
- The SITBank Flask and admin runtimes do not receive Grafana credentials, Loki
  credentials, datasource credentials, or broad log-reader credentials.

## Required Host Files

Create root-owned local files before bootstrap:

```text
/etc/sitbank-observability/observability.env
/etc/sitbank-observability/secrets/grafana_admin_user
/etc/sitbank-observability/secrets/grafana_admin_password
```

`observability.env` contains non-secret immutable image references and the
private root URL only:

```text
GRAFANA_IMAGE=example.invalid/grafana@sha256:<reviewed-digest>
LOKI_IMAGE=example.invalid/loki@sha256:<reviewed-digest>
ALLOY_IMAGE=example.invalid/alloy@sha256:<reviewed-digest>
GRAFANA_PRIVATE_ROOT_URL=https://grafana-sitbank.tailca101b.ts.net/
```

Do not put passwords, tokens, API keys, webhook URLs, cookies, database URLs, or
SMTP credentials in `observability.env`. Secret files must be `root:root` mode
`0600`.

Bootstrap also creates root-owned runtime state directories under
`/var/lib/sitbank-observability`. Alloy keeps only its runtime state under
`/var/lib/alloy`, backed by
`/var/lib/sitbank-observability/alloy`, so the container can remain
`read_only: true` while its remoting/config services have writable storage.

## Bootstrap

From a reviewed checkout on EC2:

```bash
sudo install -d -o root -g root -m 0700 /etc/sitbank-observability/secrets
sudo install -o root -g root -m 0600 /dev/null /etc/sitbank-observability/secrets/grafana_admin_user
sudo install -o root -g root -m 0600 /dev/null /etc/sitbank-observability/secrets/grafana_admin_password
sudoedit /etc/sitbank-observability/secrets/grafana_admin_user
sudoedit /etc/sitbank-observability/secrets/grafana_admin_password
sudoedit /etc/sitbank-observability/observability.env
sudo ops/deploy/bootstrap-observability-ec2 "$(pwd)"
```

Do not print the secret file contents.

## Verification

### Protected Live Workflow

Run **Verify private Grafana Loki observability** from `main` after the private
observability stack, Tailscale DNS/ACLs, Grafana credentials, or datasource
provisioning changes. Select `staging` or `production`; the job uses the
matching protected GitHub Environment `observability-staging` or
`observability-production`.

Each environment must require trusted maintainer approval and restrict
deployment branches to `main`. Configure:

- `GRAFANA_PRIVATE_URL` as the private Tailscale HTTPS URL, for example
  `https://grafana-sitbank.tailca101b.ts.net/`;
- optional `OBSERVABILITY_PUBLIC_PROBE_URLS` as newline-separated public
  denial probes for `/grafana`, `/loki`, `/logs`, and `/metrics`;
- `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET` for a narrowly scoped Tailscale
  OAuth client tagged `tag:github-ci-observability-verify`;
- `GRAFANA_HEALTH_TOKEN` as a least-privilege Grafana service account token
  that can read `/api/health`, its own `/api/user` role, datasources, and
  datasource health.

Do not store operator passwords, browser sessions, cookies, MFA values,
Grafana admin credentials, Loki credentials, datasource passwords, raw logs, or
provider exports in GitHub secrets or artifacts. The token must not have
Grafana admin privileges. The workflow first confirms the private URL is not
reachable from the public runner, then joins Tailscale, verifies Grafana API
health, verifies anonymous API denial, checks the verifier role is not admin,
checks Loki datasource health through Grafana, and verifies public SITBank
paths do not expose Grafana or Loki. It uploads only
`observability-evidence/private-observability.json`, a sanitized summary with
HTTP status codes and check names, not raw API responses.

The protected workflow is live network-path evidence. It is not a pull-request
check and must never run on forks, untrusted branches, or public GitHub-hosted
TLS jobs.

When running the verifier directly on EC2, pass `--verify-host-loopback` to
include the local Grafana and Loki readiness checks in the sanitized evidence.
Do not use that flag from a GitHub-hosted runner because `127.0.0.1` would be
the runner, not the EC2 host.

### Host Checks

```bash
sudo docker compose --env-file /etc/sitbank-observability/observability.env -f /etc/sitbank-observability/compose.yml ps
sudo docker network inspect sitbank-observability --format '{{.Internal}}'
sudo docker network inspect sitbank-observability-loopback --format '{{.Internal}}'
sudo docker port sitbank-grafana 3000/tcp
sudo docker port sitbank-loki 3100/tcp
test -z "$(sudo docker port sitbank-alloy)"
sudo ss -ltnp | grep -E '127\.0\.0\.1:(3000|3100)([[:space:]]|$)'
sudo ss -ltnp | grep -E '0\.0\.0\.0:(3000|3100)|\[::\]:(3000|3100)|\*:(3000|3100)' && exit 1 || true
curl -fsSI http://127.0.0.1:3000/login
curl -fsS http://127.0.0.1:3100/ready
sudo nginx -T | grep -iE 'grafana|loki' && exit 1 || true
```

Expected:

- `sitbank-observability` reports `true` for `Internal`.
- `sitbank-observability-loopback` reports `false` for `Internal` so Docker's
  host-loopback port publishing works on EC2.
- Grafana listens only on `127.0.0.1:3000`.
- Loki listens only on `127.0.0.1:3100`.
- Alloy publishes no host listener.
- Public SITBank Nginx configs contain no Grafana or Loki route.
- The private Tailscale URL reaches Grafana only for approved operators.

## Approved Log Sources

Alloy collects only:

- SITBank production and staging Nginx access/error logs.
- Docker logs from containers with `sitbank.log_collect=true`.
- Allowlisted systemd journal units for SITBank security alerts, Certbot, and
  Docker operational status.

The collector labels are coarse and non-secret: `service`, `environment`,
`host_role`, and `source`.

Alloy redacts recognized authorization, cookie, CSRF, session, password,
token, secret, TOTP, recovery-code, database URL, SMTP credential, API key,
webhook URL, Cloudflare token, Tailscale key, and SSH key fields before writing
to Loki, and drops raw request-body, environment-dump, and private-key-block
lines. Treat this as defense in depth rather than approval to collect sensitive
paths or raw command transcripts.

Do not add home directories, shell history, environment dumps, raw command
transcripts, secret files, request bodies, authorization headers, cookies, CSRF
tokens, session IDs, reset links, TOTP values, recovery codes, database URLs,
SMTP credentials, Cloudflare tokens, Tailscale keys, SSH keys, or raw provider
exports to collector paths.

## Retention

Loki retention is configured in `ops/observability/loki/loki.yml` with a
concrete `168h` retention period. Increase it only with a reviewed storage and
privacy decision.

## Credential Rotation And Offboarding

- Rotate Grafana admin credentials by updating the root-owned secret files and
  restarting the Grafana container.
- Remove departed operators from Grafana and from the private Tailscale access
  path.
- Rotate optional alert-delivery credentials in the provider UI or host secret
  store; do not commit them.
- Review dashboard roles so normal viewers are read-only.

## Rollback Or Disable

```bash
sudo docker compose --env-file /etc/sitbank-observability/observability.env -f /etc/sitbank-observability/compose.yml down
sudo ss -ltnp | grep -E ':(3000|3100)([[:space:]]|$)' && exit 1 || true
```

Disabling observability must not change SITBank customer, staging, or admin app
routing. The admin audit viewer remains backed by `SecurityAuditEvent`, not
Loki.

Rollback stops the containers but intentionally leaves
`/var/lib/sitbank-observability/alloy` and the Grafana/Loki state directories
in place for review or a later restart. Remove state only through a separate
approved retention decision.
