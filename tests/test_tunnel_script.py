"""Tests for Cloudflare Tunnel configuration templates."""

from pathlib import Path


def test_tunnel_template_format():
    template_path = Path("scripts/cloudflared/config.yml.template")
    assert template_path.exists()
    content = template_path.read_text()
    assert "tunnel: ${TUNNEL_ID}" in content
    assert "service: http://127.0.0.1:8000" in content
    assert "connectTimeout: 30s" in content
    assert "keepAliveTimeout: 90s" in content


def test_setup_tunnel_script_exists_and_executable():
    script_path = Path("scripts/cloudflared/setup_tunnel.sh")
    assert script_path.exists()
    import os

    assert os.access(script_path, os.X_OK)
