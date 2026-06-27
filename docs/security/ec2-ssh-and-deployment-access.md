# EC2 SSH And Deployment Access

This runbook hardens EC2 management access for SITBank. It is intentionally
operator-driven: OpenSSH and firewall changes can lock out the current operator
if they are applied blindly by an application deploy.

## Current Model

The repository deployment path still uses SSH from GitHub Actions to a
restricted deploy user. The EC2 bootstrap creates `sitbank-deploy`, gives it an
incoming upload directory, and grants only the reviewed deployment/bootstrap
wrappers through `ops/sudoers/sitbank-container-deploy`.

The approved SSH allowlist for this project is:

- `student12`: administrative operator account.
- `sitbank-deploy`: restricted deployment account created by
  `ops/deploy/bootstrap-container-ec2`.

Before installing the drop-in, verify those accounts on the target host:

```bash
getent passwd student12
getent passwd sitbank-deploy
sudo -l -U sitbank-deploy
```

If the live administrative account is not `student12`, replace that name in the
host-local drop-in before applying it. Do not keep unused local accounts in
`AllowUsers`.

## OpenSSH Drop-In

Use a drop-in file instead of editing `/etc/ssh/sshd_config` directly. The
reviewed template is `ops/ssh/99-sitbank-hardening.conf`; the host target is:

```text
/etc/ssh/sshd_config.d/99-sitbank-hardening.conf
```

Required content:

```sshconfig
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers student12 sitbank-deploy
MaxAuthTries 4
```

This blocks root SSH login, keeps password and keyboard-interactive login
disabled, requires public-key authentication, restricts accepted local
accounts, and reduces brute-force attempts.

## Safe Rollout

Do this from an existing working SSH session and keep it open until a fresh
login has succeeded.

1. Keep the current SSH session open.
2. Create the drop-in directory if needed:

   ```bash
   sudo install -d -o root -g root -m 0755 /etc/ssh/sshd_config.d
   ```

3. Edit the host-local drop-in with `sudoedit`:

   ```bash
   sudoedit /etc/ssh/sshd_config.d/99-sitbank-hardening.conf
   ```

4. Paste the reviewed content, adjusting `AllowUsers` only after verifying the
   real administrative and deployment accounts.
5. Validate OpenSSH syntax:

   ```bash
   sudo sshd -t
   ```

6. Reload SSH without killing the current session:

   ```bash
   sudo systemctl reload ssh
   ```

7. In a new terminal, verify fresh login for each required account:

   ```bash
   ssh -i <operator-key> student12@<ec2-host>
   ssh -i <deploy-key> sitbank-deploy@<ec2-host> true
   ```

8. Only after fresh login succeeds, close the old session.
9. If the fresh login fails, use the original session to fix or remove the
   drop-in, then rerun `sudo sshd -t` and `sudo systemctl reload ssh`.

Do not use `systemctl restart ssh` as the first rollout action when reload is
available.

## UFW Hardening

Global SSH access is not an acceptable final state:

```text
22/tcp ALLOW IN Anywhere
22/tcp (v6) ALLOW IN Anywhere (v6)
```

List current rules:

```bash
sudo ufw status numbered verbose
sudo ufw status verbose
```

Allow a stable trusted source before deleting global SSH rules:

```bash
sudo ufw allow from <trusted-operator-ip-or-cidr> to any port 22 proto tcp comment 'SITBank SSH allowlist'
sudo ufw allow from <trusted-vpn-or-bastion-cidr> to any port 22 proto tcp comment 'SITBank SSH private path'
```

If IPv6 is enabled, add an explicit IPv6 allowlist or remove IPv6 SSH exposure:

```bash
sudo ufw allow from <trusted-ipv6-cidr> to any port 22 proto tcp comment 'SITBank SSH IPv6 allowlist'
```

Remove global SSH only after the allowlisted path has been tested from a new
terminal:

```bash
sudo ufw status numbered
sudo ufw delete <global-ssh-rule-number>
sudo ufw delete <global-ipv6-ssh-rule-number>
sudo ufw status numbered verbose
```

Delete rules by number from highest to lowest so numbering does not shift under
you. Do not restrict SSH to one dynamic home IP unless a bastion, VPN,
allowlisted runner, AWS Systems Manager, or console recovery path is already
tested.

If the trusted source changes, add the new trusted source, test a new login,
then delete the old source. Keep the old SSH session open until the new source
is proven.

## AWS Security Group Hardening

UFW is not a substitute for the EC2 security group. An AWS administrator should
also remove global TCP 22 ingress and allow only approved sources:

```bash
aws ec2 describe-security-groups --group-ids <security-group-id>
aws ec2 authorize-security-group-ingress \
  --group-id <security-group-id> \
  --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=<trusted-cidr>,Description="SITBank SSH allowlist"}]'
aws ec2 revoke-security-group-ingress \
  --group-id <security-group-id> \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0
aws ec2 revoke-security-group-ingress \
  --group-id <security-group-id> \
  --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,Ipv6Ranges='[{CidrIpv6=::/0}]'
```

These commands require AWS IAM permissions. If the maintainer only has EC2
shell access, prepare the requested security-group change for an AWS
administrator rather than leaving SSH open globally.

## GitHub-Hosted Runner Conflict

Restricting SSH to a stable source improves the EC2 edge. GitHub-hosted runners
use changing public IP ranges, so allowing them directly usually means leaving
SSH open too broadly. The repository must not depend permanently on global
`22/tcp` exposure for deployment.

The existing workflows can continue only when their SSH source is allowlisted,
for example through a self-hosted runner, bastion, VPN egress, or a temporary
administrator-approved maintenance window. GitHub-hosted Actions must not be
the reason to keep `22/tcp ALLOW IN Anywhere`.

## Safer Deployment Path A: Self-Hosted Runner Or Bastion

Use this path when AWS IAM permissions for OIDC plus Systems Manager are not
available.

Required properties:

- The runner or bastion has a stable source IP or private network path.
- EC2 SSH allows only that source and approved operator sources.
- GitHub-hosted runners do not SSH directly to staging or production.
- Runner and bastion hosts are managed as trusted infrastructure.
- Deployment keys are scoped to `sitbank-deploy` and rotated on operator
  changes.
- Runner, bastion, and deployment secrets are not committed.

Operator checklist:

```bash
sudo ufw allow from <runner-or-bastion-cidr> to any port 22 proto tcp comment 'SITBank deployment source'
sudo ufw delete <global-ssh-rule-number>
ssh -i <deploy-key> sitbank-deploy@<ec2-host> true
```

If the runner or bastion is unavailable, use an approved break-glass operator
source, restore the previous signed image if needed, and avoid widening SSH
globally except through a time-boxed, reviewed maintenance decision.

## Safer Deployment Path B: OIDC Plus AWS Systems Manager

Use this path when the project has AWS IAM, EC2, and SSM permissions. It
reduces reliance on inbound SSH from GitHub Actions.

AWS-side prerequisites:

- GitHub OIDC identity provider exists in IAM.
- IAM deployment role trusts only the intended repository, branch, and GitHub
  environment, for example `repo:hetp88/SITBank:environment:production`.
- The role requires the GitHub OIDC audience `sts.amazonaws.com`.
- The workflow grants `id-token: write` only on jobs that assume the role.
- The EC2 instance has an instance profile with required Systems Manager
  permissions.
- SSM Agent is installed and running.
- The instance has outbound HTTPS access to SSM endpoints.
- Session Manager or Run Command actions are limited to approved commands or
  documents.
- CloudTrail or equivalent audit logging records deployment actions where
  available.

Repository-side expectations:

- Use OIDC-based AWS authentication instead of long-lived AWS access keys.
- Preserve production environment approval and signed-image verification.
- Reuse the existing root deployment wrappers; do not grant general shell or
  Docker access to the workflow.
- Do not require inbound SSH from GitHub-hosted runners.
- Store no AWS access keys, secret access keys, session tokens, private SSH
  keys, or SSM session logs in the repository.

If IAM/EC2/SSM permissions are not available, document that blocker and keep
the SSH hardening work separate. Do not claim OIDC plus SSM is implemented
until the IAM provider, role trust, instance profile, SSM agent, and deployment
command path have been created and verified.

## Validation

Host-side validation:

```bash
sudo sshd -t
sudo systemctl reload ssh
sudo ufw status verbose
ssh -i <operator-key> student12@<ec2-host>
ssh -i <deploy-key> sitbank-deploy@<ec2-host> true
```

Repository-side validation:

```bash
git diff --check
python -m pytest -q tests/test_ec2_ssh_hardening_docs.py
python -m pytest -q tests/test_deployment.py
```

## Rollback

If fresh login fails, use the original session:

```bash
sudo cp /etc/ssh/sshd_config.d/99-sitbank-hardening.conf /root/99-sitbank-hardening.conf.failed
sudo rm /etc/ssh/sshd_config.d/99-sitbank-hardening.conf
sudo sshd -t
sudo systemctl reload ssh
```

If a firewall allowlist blocks the operator, use the still-open session,
approved console recovery, VPN, bastion, or AWS Systems Manager path to restore
the last known-good source. Do not add `0.0.0.0/0` or `::/0` back as a silent
default; if temporary global SSH is unavoidable, record the approval, time box,
source reason, and removal command.

## Secrets And Host State

Never commit private SSH keys, deployment private keys, EC2 key pairs, AWS
access keys, AWS secret access keys, AWS session tokens, GitHub OIDC role
secrets, SSM session logs containing secrets, copied `authorized_keys` content,
Cloudflare tokens, Tailscale tokens, or host firewall exports containing
sensitive operational detail.
