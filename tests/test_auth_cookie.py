"""Tests for auth cookie fallback used by the dashboard."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.deps import get_db
from app.core.security import create_access_token
from app.main import create_app


@pytest.mark.asyncio
async def test_me_endpoint_accepts_access_token_cookie():
    """The backend should authenticate dashboard requests via cookie fallback."""
    user_id = uuid.uuid4()
    jwt_token = create_access_token(subject=str(user_id))

    mock_user = MagicMock()
    mock_user.id = user_id
    mock_user.access_token = "ghp_test_token"
    mock_user.username = "testuser"
    mock_user.email = "test@example.com"
    mock_user.avatar_url = "https://example.com/avatar.png"

    mock_db = AsyncMock()
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = mock_user
    mock_db.execute = AsyncMock(return_value=mock_exec)
    mock_db.commit = AsyncMock()

    app = create_app()

    async def _override_db():
        yield mock_db

    app.dependency_overrides[get_db] = _override_db

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.is_error = False

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client_cm = AsyncMock()
    mock_client_cm.__aenter__.return_value = mock_client
    mock_client_cm.__aexit__.return_value = False

    with patch("app.api.deps.httpx.AsyncClient", return_value=mock_client_cm):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(
                "/api/auth/me",
                cookies={"access_token": jwt_token},
            )

    app.dependency_overrides.clear()

    assert resp.status_code == 200
    assert resp.json()["username"] == "testuser"
