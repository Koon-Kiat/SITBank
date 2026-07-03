# Global Verification And EC2 Path Inventory Runbook

Use this runbook as the first stop for SITBank verification commands and EC2
operational path lookup. It consolidates safe command references and links to
specialized runbooks. It does not replace deployment gates, Cloudflare Access,
Tailscale private access, Nginx routing, Certbot, database role separation,
audit integrity, encrypted backup controls, or protected GitHub environments.

Active public domains are `sitbank.pp.ua`, `www.sitbank.pp.ua`, and
`staging-sitbank.pp.ua`. The production admin path is private through
`https://admin-sitbank.tailca101b.ts.net/`.

## Legend

| Label | Meaning | Sharing rule |
| --- | --- | --- |
| Safe to show | Expected non-secret status, version, path existence, owner, mode, count, or certificate metadata | May be attached to an issue after reviewing for local usernames and hostnames |
| Metadata only | Path, owner, mode, size, hash, timestamp, or high-level command result only | Share only summarized metadata, not file contents |
| Redact before sharing | Output may include identifiers, URLs, request context, or operational details | Remove tokens, credentials, personal data, internal IPs when not needed, and raw payloads |
| Never print | Secret-bearing material or sensitive private data | Do not display, paste, attach, upload, or log contents |

Safe evidence normally means command name, environment, timestamp, sanitized
success or failure indicator, relevant path metadata, and the next action. Do
not include real secrets, cookies, JWTs, private keys, database URLs, SMTP
credentials, webhook URLs, MFA material, HMAC keys, password peppers, reset
links, recovery codes, TOTP values, CSRF tokens, session IDs, raw provider
exports, raw database dumps, decrypted backups, shell history, or full request
bodies.

## Verification Commands By Context

### Local Windows/PowerShell Checks

Run from a clean local checkout before committing or before asking for review.
These commands are safe for PR CI and local development.

```powershell
git diff --check
.\.venv\Scripts\python.exe -m pytest -q -n auto
.\.venv\Scripts\python.exe -m pytest -q -n auto --cov=. --cov-config=.coveragerc --cov-report=xml:coverage.xml --cov-report=term
.\.venv\Scripts\python.exe -m compileall app config.py wsgi.py admin_wsgi.py
```

Expected safe success indicators: no whitespace errors, pytest passes, total
coverage remains at least 90 percent, `coverage.xml` is generated for
SonarQube/SonarCloud import, and compileall reports no syntax failures.

For Playwright browser E2E checks:

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = ".playwright-browsers"
.\.venv\Scripts\python.exe -m playwright install chromium
$env:SITBANK_RUN_E2E = "1"
.\.venv\Scripts\python.exe -m pytest -q tests/e2e
```

The browser tests cover authentication, MFA, session, banking, and boundary
regressions against a loopback Flask server. They do not prove live staging or
production provider state and do not target staging, production, or the private
admin hostname.

### Normal CI-Equivalent Checks

Run from local checkout or GitHub Actions. These are routine pre-merge checks.

```bash
scripts/ci-local
scripts/ci-local --require-docker
```

In GitHub Actions, review these jobs in `.github/workflows/ci-deploy.yml`:

- `Workflow security`
- `Test and security checks`
- `Playwright E2E browser tests`
- `Container image test`
- `Deployment preflight`
- `Release verification`
- `Verify staging TLS`
- `Verify production TLS`
- `Verify private admin tailnet`

Expected safe success indicators: pinned workflow actions pass actionlint and
zizmor, full pytest runs unscoped with coverage, scanners complete with
redacted output, and deployment jobs run only after their required protected
gates.

### Docker And Image Checks

Run from local checkout for pull-request image validation, or inside the
trusted workflow for release verification.

```bash
bash ops/container/validate-compose.sh sitbank:pr
bash ops/container/smoke-test.sh sitbank:pr
```

On EC2, prefer service-level status over broad container inspection:

```bash
sudo docker compose -f /opt/sitbank/compose.yml ps
sudo docker compose -f /opt/sitbank-staging/compose.yml ps
sudo docker ps --filter label=app=sitbank --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
```

Expected safe success indicators: production and staging Compose models render,
containers are healthy, and no customer/admin boundary is collapsed. Do not
display container environment, mounted secret contents, registry credentials,
or runtime secret files.

### EC2 Host Checks

Run on the relevant EC2 host with approved operator access. These are metadata
and status checks unless a specialized runbook says otherwise.

```bash
sudo systemctl status sitbank-container.service
sudo systemctl status sitbank-staging-container.service
sudo systemctl status sitbank-security-alerts.timer
sudo systemctl list-timers 'sitbank*'
sudo systemctl cat sitbank-container.service
sudo systemctl cat sitbank-staging-container.service
sudo journalctl -u sitbank-container.service --since '30 minutes ago' --no-pager
sudo journalctl -u sitbank-security-alerts.service --since '30 minutes ago' --no-pager
sudo find /opt/sitbank /opt/sitbank-staging -maxdepth 2 -type f -printf '%M %u:%g %p\n'
sudo find /usr/local/sbin -maxdepth 1 -type f -name 'sitbank-*' -printf '%M %u:%g %p\n'
```

Expected safe success indicators: services are active where expected, timers
are scheduled, wrappers are root-owned, and logs show sanitized application or
service status only. Redact personal data, request bodies, webhook URLs,
authorization headers, cookies, reset links, and command arguments containing
sensitive values before sharing.

### Nginx And TLS Checks

Run on EC2 for host-managed edge state.

```bash
sudo nginx -t
sudo nginx -T | grep -E 'server_name|ssl_certificate|ssl_verify_client|proxy_pass|add_header X-Content-Type-Options'
sudo ls -la /etc/nginx/sites-enabled /etc/nginx/sites-available /etc/nginx/snippets /etc/nginx/conf.d
sudo tail -n 100 /var/log/nginx/error.log
```

Expected safe success indicators: production customer traffic points to
`sitbank.pp.ua`, staging uses `staging-sitbank.pp.ua` with Cloudflare Access
and Authenticated Origin Pull controls, public Nginx has no production admin
upstream, and readiness remains loopback-owned. Nginx configs are usually
metadata only or redact before sharing because they can reveal internal paths
or host layout.

### Certbot Renewal Checks

Run on EC2. Certbot manages certificate lineages; do not create manual
symlinks under `/etc/letsencrypt/live`.

```bash
sudo certbot certificates
sudo certbot renew --dry-run
sudo openssl x509 -in /etc/letsencrypt/live/sitbank.pp.ua/fullchain.pem -noout -subject -issuer -dates
sudo openssl x509 -in /etc/letsencrypt/live/staging-sitbank.pp.ua/fullchain.pem -noout -subject -issuer -dates
sudo ls -la /etc/letsencrypt/live /etc/letsencrypt/renewal
```

Expected safe success indicators: active lineages include
`/etc/letsencrypt/live/sitbank.pp.ua` and
`/etc/letsencrypt/live/staging-sitbank.pp.ua`, renewal dry-run succeeds, and
certificate subjects and dates match the reviewed domains. Private keys,
archive material, and Cloudflare DNS credential files are never safe to print.

### Cloudflare Access And Staging Boundary Checks

Run local repository checks without provider secrets, or use protected
GitHub/Cloudflare operator access for live verification.

```bash
python ops/cloudflare/provision-staging-access --verify
gh workflow run cloudflare-access-verify.yml
```

Expected safe success indicators: staging Access policy and direct-origin
denial are verified with sanitized evidence, public staging host remains
`staging-sitbank.pp.ua`, and direct-origin bypass stays blocked. Cloudflare API
tokens, Access JWTs, provider exports, service tokens, request headers, and raw
provider JSON are never safe to print.

### Tailscale And Private Admin Checks

Run protected GitHub verification for reachability evidence and EC2 host
preflight for local host posture.

```bash
gh workflow run tailscale-private-admin-verify.yml
sudo /usr/local/sbin/verify-tailscale-admin-access --mode serve
sudo /usr/local/sbin/verify-tailscale-admin-access --mode ssh
```

Expected safe success indicators: private admin access uses Tailscale Serve,
Funnel is disabled, the admin app listens only on loopback, public Nginx has no
admin upstream, and protected GitHub verification runs only after production
deploy and public TLS verification. Tailscale auth keys, OAuth secrets, device
exports, and ACL provider exports are never safe to print.

### Database Privilege And Migration-Baseline Checks

Run inside the appropriate app container or trusted deployment workflow.
Production database changes require staging success and an encrypted backup
decision first.

```bash
sudo docker exec sitbank-app python -m flask --app wsgi:app production-check
sudo docker exec sitbank-app python -m flask --app wsgi:app verify-migration-baseline
sudo docker exec sitbank-app python -m flask --app wsgi:app verify-runtime-db-privileges
sudo docker exec sitbank-app python -m flask --app admin_wsgi:app production-check
curl --fail -H 'Host: sitbank.pp.ua' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-Proto: https' http://127.0.0.1:5000/health/ready
curl --fail -H 'Host: sitbank-admin.internal' -H 'X-Forwarded-Proto: https' http://127.0.0.1:5002/health/ready
```

Expected safe success indicators: production prerequisites pass, current
database schema matches migration metadata, runtime roles cannot mutate schema
objects, and customer/admin readiness is proven through EC2 loopback. Do not
display database URLs, passwords, connection strings, raw dumps, row-level
customer data, or migration-role credentials.

### Audit Chain, Audit Anchor, And Security Alerts

Run inside the app container or trusted scheduler. The security alert timer is
host-managed by systemd.

```bash
sudo docker exec sitbank-app python -m flask --app wsgi:app verify-audit-log-chain
sudo docker exec sitbank-app python -m flask --app wsgi:app verify-audit-log-chain --anchor /var/lib/sitbank/security-audit.anchor
sudo docker exec sitbank-app python -m flask --app wsgi:app export-audit-log-anchor --output /var/lib/sitbank/security-audit.anchor
sudo docker exec sitbank-app python -m flask --app wsgi:app check-security-alerts --report-only --no-delivery
sudo systemctl status sitbank-security-alerts.timer
```

Expected safe success indicators: chain verification is valid, exact anchors
report `anchor_validated=true`, normal append-only drift reports
`anchor_status=stale`, `events_since_anchor`, and `anchor_refresh_required`
without an `audit_anchor_mismatch` alert, report-only alert output contains
sanitized alert summaries, and the timer is active. Audit HMAC keys, raw
payloads, webhook URLs, alert delivery credentials, and sensitive audit
metadata are never safe to print.

Do not blindly refresh anchors. For stale append-only drift, preserve current
verification evidence first, export a refreshed sanitized anchor only after the
chain is valid, rerun `check-security-alerts --report-only --no-delivery`, and
resume or restart alert timers only after `alert_count=0` or after any
remaining non-anchor alerts are separately explained. For
`audit_anchor_mismatch` or `audit_chain_verification_failed`, preserve evidence
and investigate tampering, rollback, truncation, malformed anchor state, or
anchored event hash changes before rotating anchors.

### Backup And Restore Verification

Run only on EC2 with approved root/operator access. Backup creation is
state-changing but reviewed; restore commands are emergency or maintenance
actions and require explicit approval.

```bash
sudo /usr/local/sbin/sitbank-backup-encrypted --environment staging
sudo /usr/local/sbin/sitbank-backup-encrypted --environment production
sudo find /var/backups/sitbank /var/backups/sitbank-staging -maxdepth 1 -type f -name '*.pgdump.age' -printf '%M %u:%g %s %TY-%Tm-%Td %p\n'
sudo /usr/local/sbin/sitbank-restore-preflight --environment staging --backup-file /var/backups/sitbank-staging/<backup>.pgdump.age --target-database <staging-db-name> --identity-file /root/.config/sitbank-backups/age-identity.txt
```

Expected safe success indicators: encrypted `.pgdump.age` archives are
root-owned mode `0600`, restore preflight validates the selected encrypted
archive and target database, and plaintext temporary files are removed by the
helper. Raw database dumps, decrypted backups, age identity files, and backup
private material are never safe to print or upload.

### Grafana/Loki Observability Checks

Use `docs/runbooks/private-observability-grafana-loki.md` for the detailed
private observability runbook. Run on EC2 after private observability is
installed.

```bash
sudo docker compose --env-file /etc/sitbank-observability/observability.env -f /etc/sitbank-observability/compose.yml ps
sudo ss -ltnp | grep -E ':(3000|3100)([[:space:]]|$)'
curl -fsS http://127.0.0.1:3100/ready
curl -fsSI http://127.0.0.1:3000/login
sudo nginx -T | grep -iE 'grafana|loki' && exit 1 || true
```

Expected safe success indicators: Grafana listens only on `127.0.0.1:3000`,
Loki listens only on `127.0.0.1:3100`, Alloy publishes no host listener, and
public SITBank Nginx routes do not proxy observability services. Grafana
credentials, datasource credentials, Loki credentials, broad log-reader
credentials, and raw log exports are never safe to print.

### Emergency And Break-Glass Checks

Emergency checks are not routine PR CI. Use them during an incident with the
incident-response runbook, protected approvals, and evidence preservation.

- Preserve safe metadata first: time window, affected environment, command
  category, sanitized outcome, and relevant service/path metadata.
- Prefer read-only verification commands before state-changing commands.
- Use staging first whenever production is not actively impaired.
- Do not bypass GitHub environments, trusted bootstrap verification, staging
  gates, Tailscale/private admin controls, Cloudflare Access, or database role
  separation to save time.
- Do not delete certificate lineages, Nginx configs, bootstrap files, backups,
  evidence, or audit anchors during triage. Preserve first, then follow a
  reviewed recovery plan.

## EC2 Path Inventory

| Path group | Owner/mode expectation | Purpose | Safe inspection | Sharing rule |
| --- | --- | --- | --- | --- |
| `/etc/nginx/sites-enabled`, `/etc/nginx/sites-available` | `root:root`, config files normally `0644` | Active and available Nginx server blocks | `sudo ls -la ...`, `sudo nginx -t`, targeted `sudo nginx -T | grep -E ...` | Metadata only or redact before sharing |
| `/etc/nginx/snippets`, `/etc/nginx/conf.d` | `root:root`, config files normally `0644` | Shared snippets, TLS policy, rate-limit config | `sudo ls -la ...`, targeted grep for reviewed directives | Metadata only or redact before sharing |
| `/var/log/nginx` | `root:adm` or distro default | Access and error logs for production and staging edge | `sudo tail -n 100 /var/log/nginx/error.log` with redaction | Redact before sharing |
| `/etc/letsencrypt/live/sitbank.pp.ua`, `/etc/letsencrypt/live/staging-sitbank.pp.ua` | Certbot-managed symlinks, private keys restricted by Certbot | Active public certificate lineages | `sudo certbot certificates`, `sudo openssl x509 -in .../fullchain.pem -noout -subject -issuer -dates` | Certificate metadata safe to show; private keys never print |
| `/etc/letsencrypt/renewal` | `root:root`, renewal configs | Certbot renewal metadata | `sudo ls -la /etc/letsencrypt/renewal` | Metadata only; redact credential path values if needed |
| `/etc/letsencrypt/archive` | Certbot-managed, key material restricted | Historical certificate and private-key material | `sudo find /etc/letsencrypt/archive -maxdepth 2 -type f -printf '%M %u:%g %p\n'` | Metadata only; private material never print |
| `/root/.secrets/certbot/production.ini`, `/root/.secrets/certbot/staging.ini` | `root:root 0600` | Certbot DNS-01 Cloudflare credential files | `sudo stat -c '%A %U:%G %n' /root/.secrets/certbot/<environment>.ini` | Never print content |
| `/etc/systemd/system/sitbank*.service`, `/etc/systemd/system/sitbank*.timer` | `root:root 0644` | Host service and timer definitions | `sudo systemctl cat <unit>`, `sudo systemctl status <unit>` | Metadata only or redact before sharing |
| `/opt/sitbank`, `/opt/sitbank-staging` | Root-managed deployment directories | Compose files and runtime deployment state | `sudo find <dir> -maxdepth 2 -type f -printf '%M %u:%g %p\n'` | Metadata only; generated credential files never print |
| `/opt/sitbank-bootstrap` | Root-managed trusted bootstrap workspace | Bootstrap artifacts and trusted source material | `sudo find /opt/sitbank-bootstrap -maxdepth 2 -printf '%M %u:%g %p\n'` | Metadata only |
| `/usr/local/sbin/sitbank-container-bootstrap`, `/usr/local/sbin/sitbank-container-deploy`, `/usr/local/sbin/sitbank-container-runtime`, `/usr/local/sbin/verify-tailscale-admin-access` | `root:root 0755` | Trusted deployment, runtime, and verification wrappers | `sudo stat -c '%A %U:%G %n' /usr/local/sbin/sitbank-* /usr/local/sbin/verify-tailscale-admin-access` | Safe to show metadata |
| `/etc/sudoers.d` entries for SITBank deploy users | `root:root 0440` | Least-privilege wrapper authorization | `sudo visudo -cf /etc/sudoers.d/<file>`, `sudo ls -la /etc/sudoers.d` | Metadata only; redact usernames if needed |
| `/etc/sitbank/secrets`, `/etc/sitbank-staging/secrets`, `/run/secrets` | Root-owned secret files, typically `0600`; runtime mounts read-only | Runtime application, admin, database, SMTP, alert, session, MFA, and cryptographic secrets | `sudo find <dir> -maxdepth 1 -type f -printf '%M %U:%G %p\n'` | Never print content |
| `/var/lib/sitbank/evidence`, `/var/lib/sitbank-staging/evidence` | `root:root 0700` for directories; evidence files restricted | Sanitized deployment, TLS, Cloudflare, Tailscale, and incident evidence | `sudo find <dir> -maxdepth 2 -type f -printf '%M %u:%g %s %TY-%Tm-%Td %p\n'` | Safe only after confirming evidence is sanitized |
| `/var/backups/sitbank`, `/var/backups/sitbank-staging` | `root:root 0700` directories; encrypted archives `0600` | Encrypted PostgreSQL backups | `sudo find <dir> -maxdepth 1 -name '*.pgdump.age' -printf '%M %u:%g %s %p\n'` | Metadata only; backup contents never print |
| `/root/.config/sitbank-backups/age-identity.txt` | `root:root 0600` | Restore identity for encrypted backups | `sudo stat -c '%A %U:%G %n' /root/.config/sitbank-backups/age-identity.txt` | Never print content |
| `/var/lib/sitbank/security-audit.anchor`, `/var/lib/sitbank-staging/security-audit.anchor` | Root-managed or app-readable as configured | Audit hash-chain anchor | `sudo stat -c '%A %U:%G %n' <anchor>` and app `verify-audit-log-chain --anchor <anchor>` | Anchor JSON is sanitized but review before sharing |
| `/var/lib/sitbank/alerts`, `/run/state/security-alert-state.json` | Root/app-managed state | Alert state and dedupe baseline paths | `sudo stat -c '%A %U:%G %n' <path>` | Metadata only or redact before sharing |
| `/var/log/journal`, `journalctl -u sitbank*` | System journal policy | Service logs and alert timer logs | `sudo journalctl -u <unit> --since '<window>' --no-pager` | Redact before sharing |
| `/etc/sitbank-observability`, `/etc/sitbank-observability/secrets` | Config root `root:root`; secret files `0600` | Private Grafana/Loki/Alloy config and credentials | `sudo find /etc/sitbank-observability -maxdepth 2 -printf '%M %u:%g %p\n'` | Config metadata only; secrets never print |
| `ops/cloudflare/provision-staging-access` and protected Cloudflare evidence | Repository script plus provider-owned state | Staging Access and direct-origin denial verification | Run `--verify`; retain sanitized evidence only | Provider tokens and raw exports never print |
| `ops/tailscale/*`, `/usr/local/sbin/verify-tailscale-admin-access`, protected tailnet workflow evidence | Repository scripts plus provider-owned state | Private admin access provisioning and verification | Run verifier modes and protected workflow | Tailscale keys, OAuth secrets, device exports, raw ACL exports never print |

## Deeper References

- Deployment model and environment variables: `docs/DEPLOYMENT.md`
- Operations, rollback, backups, audit, and alerts: `docs/OPERATIONS.md`
- Incident response: `docs/security/governance/incident-response.md`
- Audit and alert implementation: `docs/security/assurance/audit-and-alerting.md`
- Cloudflare staging access: `docs/security/architecture/cloudflare-staging-access.md`
- Admin and staging zero-trust access: `docs/security/architecture/admin-and-staging-zero-trust-access.md`
- Private observability: `docs/runbooks/private-observability-grafana-loki.md`
- Tailscale host automation: `ops/tailscale/README.md`
