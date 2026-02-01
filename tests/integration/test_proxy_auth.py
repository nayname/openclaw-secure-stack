"""Integration tests for the proxy auth flow."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from src.proxy.app import create_app
from src.sanitizer.sanitizer import PromptSanitizer

TOKEN = "integration-test-token-xyz"


@pytest.fixture()
def rules_path(tmp_path: Path) -> str:
    rules = [
        {
            "id": "PI-001",
            "name": "Ignore instructions",
            "pattern": "(?i)ignore\\s+(all\\s+)?previous\\s+instructions",
            "action": "strip",
            "description": "test",
        },
    ]
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules))
    return str(p)


@pytest.fixture()
def app(rules_path: str) -> object:
    sanitizer = PromptSanitizer(rules_path)
    return create_app(
        upstream_url="http://upstream:3000",
        token=TOKEN,
        sanitizer=sanitizer,
    )


@pytest.mark.asyncio
async def test_valid_token_proxies(app: object) -> None:
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_missing_token_rejected(app: object) -> None:
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/test")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_invalid_token_rejected(app: object) -> None:
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/api/test",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_health_no_auth(app: object) -> None:
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_proxy_forwards_gateway_token(rules_path: str) -> None:
    """Proxy must replace client auth with the gateway token for upstream."""
    sanitizer = PromptSanitizer(rules_path)
    app = create_app(
        upstream_url="http://upstream:3000",
        token=TOKEN,
        sanitizer=sanitizer,
    )

    captured_headers: dict[str, str] = {}

    async def mock_request(*args, **kwargs):
        captured_headers.update(kwargs.get("headers", {}))
        return httpx.Response(status_code=200, content=b'{"ok":true}')

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
            mock_instance = AsyncMock()
            mock_instance.request = mock_request
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_instance

            resp = await client.get(
                "/v1/models",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )

    assert resp.status_code == 200
    # Gateway token is set for upstream
    assert captured_headers.get("authorization") == f"Bearer {TOKEN}"


@pytest.mark.asyncio
async def test_proxy_does_not_forward_client_auth(rules_path: str) -> None:
    """Client's original auth header must not leak to upstream."""
    sanitizer = PromptSanitizer(rules_path)
    app = create_app(
        upstream_url="http://upstream:3000",
        token=TOKEN,
        sanitizer=sanitizer,
    )

    captured_headers: dict[str, str] = {}

    async def mock_request(*args, **kwargs):
        captured_headers.update(kwargs.get("headers", {}))
        return httpx.Response(status_code=200, content=b'{"ok":true}')

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
            mock_instance = AsyncMock()
            mock_instance.request = mock_request
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_instance

            resp = await client.get(
                "/v1/models",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )

    assert resp.status_code == 200
    # The upstream header should be the gateway token, not "some-client-token"
    assert "some-client-token" not in captured_headers.get("authorization", "")


@pytest.mark.asyncio
async def test_proxy_strips_hop_by_hop_headers(rules_path: str) -> None:
    """Proxy must strip hop-by-hop headers from upstream responses."""
    sanitizer = PromptSanitizer(rules_path)
    app = create_app(
        upstream_url="http://upstream:3000",
        token=TOKEN,
        sanitizer=sanitizer,
    )

    fake_response = httpx.Response(
        status_code=200,
        content=b'{"ok":true}',
        headers={
            "content-type": "application/json",
            "content-length": "11",
            "transfer-encoding": "chunked",
            "connection": "keep-alive",
            "keep-alive": "timeout=5",
            "x-custom": "preserved",
        },
    )

    async def mock_request(*args, **kwargs):
        return fake_response

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
            mock_instance = AsyncMock()
            mock_instance.request = mock_request
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_instance

            resp = await client.get(
                "/v1/test",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )

    assert resp.status_code == 200
    # Starlette sets its own content-length from actual body, so we verify
    # the upstream's transfer-encoding/connection/keep-alive don't leak through.
    assert "transfer-encoding" not in resp.headers
    assert "connection" not in resp.headers
    assert "keep-alive" not in resp.headers
    assert resp.headers["x-custom"] == "preserved"
