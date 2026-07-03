# Private Grafana Loki Observability Runbook

Use this runbook to install and operate the private SITBank Grafana, Loki, and
Grafana Alloy stack from `ops/observability/`.

## Access Model

- Grafana binds to `127.0.0.1:3000` on the EC2 host.
- Loki binds to `127.0.0.1:3100` on the EC2 host.
- Alloy does not publish a host port.
- Normal operator access uses a private Tailscale path such as
  `https://grafana-sitbank.tailca101b.ts.net/` mapped to local Grafana.
- SSH local port forwarding is allowed only for bootstrap or break-glass
  troubleshooting.
- No public Nginx production, staging, customer, or admin route proxies Grafana,
  Loki, or Alloy.
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

### Host Checks

```bash
sudo docker compose --env-file /etc/sitbank-observability/observability.env -f /etc/sitbank-observability/compose.yml ps
sudo ss -ltnp | grep -E ':(3000|3100)([[:space:]]|$)'
curl -fsS http://127.0.0.1:3100/ready
curl -fsSI http://127.0.0.1:3000/login
sudo nginx -T | grep -iE 'grafana|loki' && exit 1 || true
```

Expected:

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
