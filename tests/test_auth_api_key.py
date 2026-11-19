"""Tests for optional API key and Cloudflare Access authentication in Argus."""

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.server import app


@pytest.fixture
def api_client():
    return TestClient(app)


def test_loopback_unauthenticated_request_is_allowed(
    api_client, monkeypatch, sample_image_bytes
):
    """Local edge hardware (Hermes on 127.0.0.1) without Cloudflare headers does not require API key."""
    monkeypatch.setattr(settings, "ARGUS_API_KEY", "secret-test-key")
    response = api_client.post(
        "/recognize",
        files={"file": ("test.jpg", sample_image_bytes, "image/jpeg")},
    )
    assert response.status_code == 200


def test_remote_tunnel_request_without_key_is_rejected(
    api_client, monkeypatch, sample_image_bytes
):
    """Requests carrying Cloudflare tunnel headers without valid API key or CF Access token must fail with 401."""
    monkeypatch.setattr(settings, "ARGUS_API_KEY", "secret-test-key")
    response = api_client.post(
        "/recognize",
        files={"file": ("test.jpg", sample_image_bytes, "image/jpeg")},
        headers={
            "CF-Connecting-IP": "203.0.113.42",
            "CF-RAY": "8f1234567890abcd-IAD",
        },
    )
    assert response.status_code == 401
    assert "Invalid or missing API key" in response.json()["message"]


def test_remote_tunnel_request_with_valid_api_key_passes(
    api_client, monkeypatch, sample_image_bytes
):
    """Requests carrying Cloudflare tunnel headers with matching X-API-Key header must succeed."""
    monkeypatch.setattr(settings, "ARGUS_API_KEY", "secret-test-key")
    response = api_client.post(
        "/recognize",
        files={"file": ("test.jpg", sample_image_bytes, "image/jpeg")},
        headers={
            "CF-Connecting-IP": "203.0.113.42",
            "CF-RAY": "8f1234567890abcd-IAD",
            "X-API-Key": "secret-test-key",
        },
    )
    assert response.status_code == 200


def test_spoofed_forwarded_for_is_rejected(api_client, monkeypatch, sample_image_bytes):
    """Attacker sending X-Forwarded-For: 127.0.0.1 over Cloudflare tunnel must still be rejected."""
    monkeypatch.setattr(settings, "ARGUS_API_KEY", "secret-test-key")
    response = api_client.post(
        "/recognize",
        files={"file": ("test.jpg", sample_image_bytes, "image/jpeg")},
        headers={
            "CF-Connecting-IP": "198.51.100.1",
            "X-Forwarded-For": "127.0.0.1",
        },
    )
    assert response.status_code == 401
