"""FastAPI dependencies for request handling and concurrency throttling."""

import asyncio
from typing import Annotated

from fastapi import Depends, Header, Request

from app.core import constants
from app.core.config import settings
from app.core.exceptions import ANPRServiceError

_inference_semaphore: asyncio.Semaphore | None = None


def get_semaphore() -> asyncio.Semaphore:
    """Return singleton asyncio semaphore limiting concurrent AI pipeline executions."""
    global _inference_semaphore
    if _inference_semaphore is None:
        _inference_semaphore = asyncio.Semaphore(constants.MAX_CONCURRENT_INFERENCES)
    return _inference_semaphore


type InferenceSemaphore = Annotated[asyncio.Semaphore, Depends(get_semaphore)]


def verify_api_key(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> None:
    """Verify API key for remote tunnel access while exempting raw local loopback requests."""
    expected_key = settings.ARGUS_API_KEY
    if not expected_key:
        return

    # Check if this is an external ingress request passing through Cloudflare Tunnel
    is_cloudflare_ingress = bool(
        request.headers.get("CF-Connecting-IP")
        or request.headers.get("CF-RAY")
        or request.headers.get("X-Forwarded-For")
    )

    client_host = request.client.host if request.client else "127.0.0.1"
    is_local_socket = client_host in ("127.0.0.1", "::1", "localhost", "testclient")

    # Only exempt pure local loopback calls that did NOT arrive via Cloudflare Tunnel or external proxy
    if is_local_socket and not is_cloudflare_ingress:
        return

    if x_api_key != expected_key:
        raise ANPRServiceError("Invalid or missing API key", status_code=401)
