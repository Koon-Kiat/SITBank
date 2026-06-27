from pathlib import Path


DOC_PATH = Path("docs/security/ec2-ssh-and-deployment-access.md")
DROPIN_PATH = Path("ops/ssh/99-sitbank-hardening.conf")


def _docs_text() -> str:
    paths = [
        Path("README.md"),
        Path("SECURITY.md"),
        Path("docs/DEPLOYMENT.md"),
        Path("docs/OPERATIONS.md"),
        Path("docs/GITHUB_ACTIONS.md"),
        DOC_PATH,
    ]
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def _normalized(text: str) -> str:
    return " ".join(text.split())


def test_ec2_ssh_runbook_documents_required_dropin_and_safe_rollout():
    doc = _normalized(DOC_PATH.read_text(encoding="utf-8"))

    for required in (
        "/etc/ssh/sshd_config.d/99-sitbank-hardening.conf",
        "ops/ssh/99-sitbank-hardening.conf",
        "PermitRootLogin no",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PubkeyAuthentication yes",
        "AuthenticationMethods publickey",
        "AllowUsers student12 sitbank-deploy",
        "MaxAuthTries 4",
        "sudoedit /etc/ssh/sshd_config.d/99-sitbank-hardening.conf",
        "Keep the current SSH session open",
        "sudo sshd -t",
        "sudo systemctl reload ssh",
        "ssh -i <operator-key> student12@<ec2-host>",
        "ssh -i <deploy-key> sitbank-deploy@<ec2-host> true",
        "Only after fresh login succeeds, close the old session.",
        "Do not use `systemctl restart ssh` as the first rollout action",
    ):
        assert required in doc


def test_ssh_dropin_template_keeps_public_key_only_restricted_access():
    dropin = DROPIN_PATH.read_text(encoding="utf-8")

    expected_directives = {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
        "KbdInteractiveAuthentication": "no",
        "PubkeyAuthentication": "yes",
        "AuthenticationMethods": "publickey",
        "AllowUsers": "student12 sitbank-deploy",
        "MaxAuthTries": "4",
    }
    for key, value in expected_directives.items():
        assert f"{key} {value}" in dropin

    assert "PermitRootLogin without-password" not in dropin
    assert "PasswordAuthentication yes" not in dropin
    assert "KbdInteractiveAuthentication yes" not in dropin
    assert "AllowGroups" not in dropin


def test_firewall_and_deployment_path_guidance_blocks_global_ssh_assumption():
    docs = _normalized(_docs_text())
    workflows = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            Path(".github/workflows/ci-deploy.yml"),
            Path(".github/workflows/bootstrap-ec2.yml"),
        )
    )

    for required in (
        "22/tcp ALLOW IN Anywhere",
        "22/tcp (v6) ALLOW IN Anywhere (v6)",
        "sudo ufw status numbered verbose",
        "sudo ufw allow from <trusted-operator-ip-or-cidr> to any port 22 proto tcp",
        "sudo ufw delete <global-ssh-rule-number>",
        "sudo ufw delete <global-ipv6-ssh-rule-number>",
        "revoke-security-group-ingress",
        "0.0.0.0/0",
        "::/0",
        "GitHub-hosted runners use changing public IP ranges",
        "self-hosted runner, bastion, VPN egress",
        "OIDC Plus AWS Systems Manager",
        "AWS IAM, EC2, and SSM permissions",
        "GitHub OIDC identity provider exists in IAM",
        "id-token: write",
        "SSM Agent is installed and running",
        "Do not claim OIDC plus SSM is implemented",
    ):
        assert required in docs

    assert "0.0.0.0/0" not in workflows
    assert "::/0" not in workflows
    assert "ALLOW IN Anywhere" not in workflows


def test_existing_docs_link_to_ec2_ssh_access_runbook():
    docs = _normalized(_docs_text())

    for required in (
        "docs/security/ec2-ssh-and-deployment-access.md",
        "EC2 SSH and deployment access",
        "OpenSSH drop-in",
        "GitHub-hosted runners do not have stable source IPs",
        "normal GitHub-hosted SSH deployment is acceptable only when the runner source is allowlisted",
    ):
        assert required in docs
