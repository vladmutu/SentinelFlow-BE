"""Tests for graph-data enrichment / scan-result mapping."""

from __future__ import annotations

import asyncio
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


@pytest.mark.asyncio
async def test_pypi_dependency_tree_returns_graph_shape(app):
    """The PyPI dependency endpoint should return nested graph data for frontend rendering."""
    manifest = {
        "name": "sentinel-project",
        "version": "1.2.3",
        "dependencies": {
            "requests": "2.31.0",
            "flask": "3.0.2",
        },
    }
    deep_tree = {
        "name": "sentinel-project",
        "version": "1.2.3",
        "children": [
            {
                "name": "requests",
                "version": "2.31.0",
                "children": [
                    {"name": "urllib3", "version": "2.2.2", "children": []},
                ],
            },
            {
                "name": "flask",
                "version": "3.0.2",
                "children": [
                    {"name": "werkzeug", "version": "3.0.1", "children": []},
                ],
            },
        ],
    }

    with patch(
        "app.api.endpoints.repos.manifest_utils.fetch_pypi_manifest",
        AsyncMock(return_value=manifest),
    ), patch(
        "app.api.endpoints.repos.manifest_utils.build_pypi_dependency_tree_deep",
        AsyncMock(return_value=deep_tree),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/repos/owner/repo/dependencies/pypi")

    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "sentinel-project"
    assert body["version"] == "1.2.3"
    assert {child["name"] for child in body["children"]} == {"requests", "flask"}
    requests_node = next(child for child in body["children"] if child["name"] == "requests")
    assert requests_node["children"][0]["name"] == "urllib3"


@pytest.mark.asyncio
async def test_pypi_dependency_tree_falls_back_to_shallow_when_deep_fails(app):
    """If deep PyPI resolution fails, endpoint should still return a usable graph."""
    manifest = {
        "name": "sentinel-project",
        "version": "1.2.3",
        "dependencies": {
            "requests": "2.31.0",
            "flask": "3.0.2",
        },
    }

    with patch(
        "app.api.endpoints.repos.manifest_utils.fetch_pypi_manifest",
        AsyncMock(return_value=manifest),
    ), patch(
        "app.api.endpoints.repos.manifest_utils.build_pypi_dependency_tree_deep",
        AsyncMock(side_effect=RuntimeError("pypi unavailable")),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/repos/owner/repo/dependencies/pypi")

    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "sentinel-project"
    assert body["version"] == "1.2.3"
    assert {child["name"] for child in body["children"]} == {"requests", "flask"}


@pytest.mark.asyncio
async def test_pypi_dependency_tree_limits_metadata_concurrency():
    """Large PyPI dependency sets should not exceed the configured fetch concurrency."""

    class DummyResponse:
        def __init__(self, package_name: str):
            self.status_code = 200
            self.is_error = False
            self._package_name = package_name

        def json(self):
            return {
                "info": {
                    "name": self._package_name,
                    "version": "1.0.0",
                    "requires_dist": [],
                }
            }

    active_requests = 0
    peak_requests = 0

    async def fake_get(url: str):
        nonlocal active_requests, peak_requests
        active_requests += 1
        peak_requests = max(peak_requests, active_requests)
        try:
            await asyncio.sleep(0.02)
            package_name = url.split("/pypi/", 1)[1].split("/", 1)[0]
            return DummyResponse(package_name)
        finally:
            active_requests -= 1

    manifest = {
        "name": "sentinel-project",
        "version": "1.2.3",
        "dependencies": {f"pkg-{index}": "1.0.0" for index in range(20)},
    }

    mock_client = AsyncMock()
    mock_client.get = fake_get

    from app.services.manifest_utils import build_pypi_dependency_tree_deep

    tree = await build_pypi_dependency_tree_deep(
        mock_client,
        manifest,
        max_depth=2,
        max_children=5,
        max_concurrency=3,
    )

    assert tree["name"] == "sentinel-project"
    assert len(tree["children"]) == 20
    assert peak_requests <= 3
