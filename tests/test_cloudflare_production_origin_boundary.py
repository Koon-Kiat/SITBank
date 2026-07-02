from __future__ import annotations

from pathlib import Path


PRODUCTION_NGINX = Path("ops/nginx/sitbank-production.conf")
DEFAULT_NGINX = Path("ops/nginx/sitbank-default.conf")
BOOTSTRAP = Path("ops/deploy/bootstrap-container-ec2")


def test_production_http_ip_redirect_and_https_origin_pull_are_fail_closed():
    production = PRODUCTION_NGINX.read_text(encoding="utf-8")
    default = DEFAULT_NGINX.read_text(encoding="utf-8")

    assert "server_name sitbank.pp.ua www.sitbank.pp.ua 18.188.152.24;" in production
    assert "return 301 https://sitbank.pp.ua$request_uri;" in production
    assert "18.188.152.24" not in default
    assert "listen 443 ssl http2 default_server;" in default
    assert "ssl_reject_handshake on;" in default
    assert production.count(
        "ssl_client_certificate "
        "/etc/nginx/sitbank-production-cloudflare-origin-pull-ca.pem;"
    ) == 2
    assert production.count("ssl_verify_client on;") == 2
    assert "proxy_pass http://127.0.0.1:5002;" not in production


def test_production_hsts_matches_six_month_cloudflare_policy():
    production = PRODUCTION_NGINX.read_text(encoding="utf-8")

    assert production.count(
        'Strict-Transport-Security "max-age=15552000; includeSubDomains"'
    ) == 2
    assert "max-age=31536000; includeSubDomains" not in production
    assert "preload" not in production


def test_production_bootstrap_verifies_distinct_origin_pull_material():
    bootstrap = BOOTSTRAP.read_text(encoding="utf-8")

    assert (
        'PRODUCTION_CLOUDFLARE_ORIGIN_PULL_CA_FILE="/etc/nginx/'
        'sitbank-production-cloudflare-origin-pull-ca.pem"'
    ) in bootstrap
    assert (
        'STAGING_CLOUDFLARE_ORIGIN_PULL_CA_FILE="/etc/nginx/'
        'cloudflare-authenticated-origin-pull-ca.pem"'
    ) in bootstrap
    assert (
        'PRODUCTION_CLOUDFLARE_ORIGIN_PULL_CA_ALLOWLIST="/etc/sitbank/'
        'cloudflare-origin-pull-ca-allowlist.json"'
    ) in bootstrap
    assert (
        'STAGING_CLOUDFLARE_ORIGIN_PULL_CA_ALLOWLIST="/etc/sitbank-staging/'
        'cloudflare-origin-pull-ca-allowlist.json"'
    ) in bootstrap
    assert "Production Cloudflare Authenticated Origin Pull CA validation failed." in bootstrap
    assert "Cloudflare Authenticated Origin Pull CA validation failed." in bootstrap
