"""Tests for graph-data enrichment / scan-result mapping."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

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
    return AsyncMock()


@pytest.fixture
def app(mock_user, mock_db):
    _app = create_app()
    _app.dependency_overrides[get_current_user] = lambda: mock_user

    async def _override_db():
        yield mock_db

    _app.dependency_overrides[get_db] = _override_db
    yield _app
    _app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_latest_results_returns_map_keyed_by_identity(app, mock_db):
    """The latest results endpoint should return {pkg@version: verdict}."""
    now = datetime.now(timezone.utc)
    job_id = uuid.uuid4()

    mock_job = MagicMock(spec=ScanJob)
    mock_job.id = job_id

    result1 = MagicMock(spec=ScanResult)
    result1.package_name = "lodash"
    result1.package_version = "4.17.21"
    result1.malware_status = "clean"
    result1.malware_score = 0.02
    result1.scan_timestamp = now
    result1.scanner_version = "1.0.0"

    result2 = MagicMock(spec=ScanResult)
    result2.package_name = "express"
    result2.package_version = "4.18.2"
    result2.malware_status = "malicious"
    result2.malware_score = 0.95
    result2.scan_timestamp = now
    result2.scanner_version = "1.0.0"

    call_count = {"n": 0}

    async def _execute_side_effect(stmt):
        call_count["n"] += 1
        m = MagicMock()
        if call_count["n"] == 1:
            m.scalar_one_or_none.return_value = mock_job
        else:
            m.scalars.return_value.all.return_value = [result1, result2]
        return m

    mock_db.execute = _execute_side_effect

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/api/repos/owner/repo/scan/latest/results")

    assert resp.status_code == 200
    body = resp.json()

    assert "lodash@4.17.21" in body
    assert body["lodash@4.17.21"]["malware_status"] == "clean"

    assert "express@4.18.2" in body
    assert body["express@4.18.2"]["malware_status"] == "malicious"
    assert body["express@4.18.2"]["malware_score"] == 0.95


@pytest.mark.asyncio
async def test_latest_results_empty_when_no_completed_job(app, mock_db):
    """When there's no completed scan job, return an empty dict."""
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_exec)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/api/repos/owner/repo/scan/latest/results")

    assert resp.status_code == 200
    assert resp.json() == {}


@pytest.mark.asyncio
async def test_result_map_keys_match_tree_node_identities(app, mock_db):
    """Verify that result map keys use the format 'name@version' which
    is what the frontend uses to match against tree nodes."""
    now = datetime.now(timezone.utc)
    job_id = uuid.uuid4()

    mock_job = MagicMock(spec=ScanJob)
    mock_job.id = job_id

    result = MagicMock(spec=ScanResult)
    result.package_name = "@babel/core"
    result.package_version = "7.22.0"
    result.malware_status = "clean"
    result.malware_score = 0.001
    result.scan_timestamp = now
    result.scanner_version = "1.0.0"

    call_count = {"n": 0}

    async def _execute_side_effect(stmt):
        call_count["n"] += 1
        m = MagicMock()
        if call_count["n"] == 1:
            m.scalar_one_or_none.return_value = mock_job
        else:
            m.scalars.return_value.all.return_value = [result]
        return m

    mock_db.execute = _execute_side_effect

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/api/repos/owner/repo/scan/latest/results")

    body = resp.json()
    assert "@babel/core@7.22.0" in body
