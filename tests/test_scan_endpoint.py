"""Tests for the scan trigger, status, and results endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.deps import get_current_user
from app.db.session import get_db
from app.main import create_app
from app.models.scan import ScanJob, ScanResult


@pytest.fixture
def mock_user():
    user = MagicMock()
    user.id = uuid.uuid4()
    user.access_token = "ghp_test_token"
    user.username = "testuser"
    user.email = "test@example.com"
    return user


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.commit = AsyncMock()
    db.add = MagicMock()
    return db


@pytest.fixture
def app(mock_user, mock_db):
    _app = create_app()
    _app.dependency_overrides[get_current_user] = lambda: mock_user

    async def _override_db():
        yield mock_db

    _app.dependency_overrides[get_db] = _override_db
    yield _app
    _app.dependency_overrides.clear()


@pytest.fixture
def unauth_app():
    """App WITHOUT auth overrides – for testing auth enforcement."""
    _app = create_app()
    yield _app


# ── POST trigger ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_trigger_scan_returns_202(app, mock_db):
    """POST /api/repos/{owner}/{repo}/scan should return 202 with job_id."""

    async def _fake_refresh(obj):
        if not hasattr(obj, "id") or obj.id is None:
            obj.id = uuid.uuid4()
        if not hasattr(obj, "status") or obj.status is None:
            obj.status = "pending"

    mock_db.refresh = AsyncMock(side_effect=_fake_refresh)

    with patch("app.api.endpoints.scan.job_runner") as mock_runner:
        mock_runner.submit = MagicMock()

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post(
                "/api/repos/owner/repo/scan",
                json={"ecosystem": "npm"},
            )

    assert resp.status_code == 202
    body = resp.json()
    assert "job_id" in body
    assert body["status"] == "pending"
    mock_runner.submit.assert_called_once()


@pytest.mark.asyncio
async def test_trigger_scan_rejects_invalid_ecosystem(app):
    """Ecosystem must be 'npm' or 'pypi'."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.post(
            "/api/repos/owner/repo/scan",
            json={"ecosystem": "maven"},
        )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_trigger_scan_requires_auth(unauth_app):
    """Unauthenticated requests should be rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=unauth_app),
        base_url="http://test",
    ) as client:
        resp = await client.post(
            "/api/repos/owner/repo/scan",
            json={"ecosystem": "npm"},
        )
    assert resp.status_code in (401, 403)


# ── GET job status ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_scan_job_not_found(app, mock_db):
    """GET with a non-existent job_id should return 404."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)

    job_id = uuid.uuid4()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            f"/api/repos/owner/repo/scan/{job_id}",
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_scan_job_returns_results(app, mock_db):
    """GET with a valid job_id should return the job and its results."""
    job_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    mock_job = MagicMock(spec=ScanJob)
    mock_job.id = job_id
    mock_job.owner = "owner"
    mock_job.repo_name = "repo"
    mock_job.ecosystem = "npm"
    mock_job.status = "completed"
    mock_job.total_packages = 1
    mock_job.scanned_packages = 1
    mock_job.error_message = None
    mock_job.started_at = now
    mock_job.completed_at = now
    mock_job.created_at = now

    mock_result = MagicMock(spec=ScanResult)
    mock_result.id = uuid.uuid4()
    mock_result.package_name = "lodash"
    mock_result.package_version = "4.17.21"
    mock_result.ecosystem = "npm"
    mock_result.malware_status = "clean"
    mock_result.malware_score = 0.05
    mock_result.scanner_version = "1.0.0"
    mock_result.error_message = None
    mock_result.scan_timestamp = now

    mock_job.results = [mock_result]

    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = mock_job
    mock_db.execute = AsyncMock(return_value=exec_result)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            f"/api/repos/owner/repo/scan/{job_id}",
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert len(body["results"]) == 1
    assert body["results"][0]["package_name"] == "lodash"
    assert body["results"][0]["malware_status"] == "clean"
