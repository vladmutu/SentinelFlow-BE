"""Tests for the scan trigger, status, and results endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
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
        def _submit_and_close(coro):
            coro.close()
            return MagicMock()

        mock_runner.submit = MagicMock(side_effect=_submit_and_close)

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
async def test_trigger_scan_accepts_selected_packages(app, mock_db):
    """Selected package identifiers should be passed to orchestration."""

    async def _fake_refresh(obj):
        if not hasattr(obj, "id") or obj.id is None:
            obj.id = uuid.uuid4()
        if not hasattr(obj, "status") or obj.status is None:
            obj.status = "pending"

    mock_db.refresh = AsyncMock(side_effect=_fake_refresh)

    with patch("app.api.endpoints.scan.job_runner") as mock_runner:
        captured = {"kwargs": None}

        def _submit_and_close(coro):
            frame = getattr(coro, "cr_frame", None)
            if frame is not None:
                captured["kwargs"] = dict(frame.f_locals)
            coro.close()
            return MagicMock()

        mock_runner.submit = MagicMock(side_effect=_submit_and_close)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post(
                "/api/repos/owner/repo/scan",
                json={
                    "ecosystem": "npm",
                    "selected_packages": ["lodash", "@types/node@22.0.0"],
                },
            )

    assert resp.status_code == 202
    assert captured["kwargs"] is not None
    assert captured["kwargs"]["selected_packages"] == ["lodash", "@types/node@22.0.0"]


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
    mock_job.scan_mode = "full"
    mock_job.status = "completed"
    mock_job.total_packages = 1
    mock_job.scanned_packages = 1
    mock_job.total_dependency_nodes = 1
    mock_job.total_unique_packages = 1
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
    mock_result.risk_assessment = {
        "schema_version": "2026-04-20",
        "package_name": "lodash",
        "package_version": "4.17.21",
        "ecosystem": "npm",
        "overall_status": "clean",
        "overall_score": 0.05,
        "confidence": 0.05,
        "analysis_mode": "static-classifier",
        "allowlisted": False,
        "suppressed": False,
        "static_signals": [],
        "dynamic_signals": [],
        "vulnerability_signals": [],
        "reputation_signals": [],
        "policy_signals": [],
        "evidence": [],
        "explanation": "Static classifier score 0.050000 for lodash@4.17.21",
        "metadata": {"scanner_version": "1.0.0"},
    }
    mock_result.risk_breakdown = {"classifier": {"score": 0.05, "weight": 1.0}}
    mock_result.advisory_references = ["GHSA-1234"]
    mock_result.risk_allowlisted = True
    mock_result.risk_suppressed = False
    mock_result.risk_suppression_reason = None
    mock_result.analysis_status = "skipped"
    mock_result.analysis_coverage = "none"
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
    assert body["results"][0]["risk_breakdown"] == {"classifier": {"score": 0.05, "weight": 1.0}}
    assert body["results"][0]["advisory_references"] == ["GHSA-1234"]
    assert body["results"][0]["risk_allowlisted"] is True
    assert body["results"][0]["analysis_status"] == "skipped"
    assert body["results"][0]["risk_assessment"]["overall_status"] == "clean"
    assert body["progress_percent"] == 100.0
    assert body["estimated_seconds_remaining"] == 0


@pytest.mark.asyncio
async def test_trigger_scan_with_scan_mode(app, mock_db):
    """ScanJob is created with the requested scan_mode."""
    captured_job = {}

    def _capture_add(obj):
        captured_job["obj"] = obj

    mock_db.add = MagicMock(side_effect=_capture_add)

    async def _fake_refresh(obj):
        if not hasattr(obj, "id") or obj.id is None:
            obj.id = uuid.uuid4()
        if not hasattr(obj, "status") or obj.status is None:
            obj.status = "pending"

    mock_db.refresh = AsyncMock(side_effect=_fake_refresh)

    with patch("app.api.endpoints.scan.job_runner") as mock_runner:
        def _submit_and_close(coro):
            coro.close()
            return MagicMock()

        mock_runner.submit = MagicMock(side_effect=_submit_and_close)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/repos/owner/repo/scan",
                json={"ecosystem": "npm", "scan_mode": "static_only"},
            )

    assert resp.status_code == 202
    added = captured_job.get("obj")
    assert added is not None
    assert added.scan_mode == "static_only"


@pytest.mark.asyncio
async def test_get_scan_history(app, mock_db):
    """History endpoint returns paginated list of scan jobs, newest first."""
    now = datetime.now(timezone.utc)

    def _make_history_job(i: int):
        j = MagicMock(spec=ScanJob)
        j.id = uuid.uuid4()
        j.ecosystem = "npm"
        j.scan_mode = "full"
        j.status = "completed"
        j.total_packages = 5
        j.processed_packages = 5
        j.scanned_packages = 5
        j.error_message = None
        j.created_at = now - timedelta(minutes=i)
        j.started_at = now - timedelta(minutes=i)
        j.completed_at = now - timedelta(minutes=i - 1)
        return j

    jobs = [_make_history_job(i) for i in range(3)]

    count_result = MagicMock()
    count_result.scalar_one.return_value = 3

    scalars_mock = MagicMock()
    scalars_mock.all.return_value = jobs
    jobs_result = MagicMock()
    jobs_result.scalars.return_value = scalars_mock

    mock_db.execute = AsyncMock(side_effect=[count_result, jobs_result])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/repos/owner/repo/scan/history")

    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3
    assert body["page"] == 1
    assert body["per_page"] == 20
    assert len(body["jobs"]) == 3
    assert all(j["scan_mode"] == "full" for j in body["jobs"])


@pytest.mark.asyncio
async def test_get_scan_history_pagination(app, mock_db):
    """History endpoint respects page and per_page query parameters."""
    now = datetime.now(timezone.utc)

    def _make_history_job(i: int):
        j = MagicMock(spec=ScanJob)
        j.id = uuid.uuid4()
        j.ecosystem = "pypi"
        j.scan_mode = "static_only"
        j.status = "completed"
        j.total_packages = 3
        j.processed_packages = 3
        j.scanned_packages = 3
        j.error_message = None
        j.created_at = now - timedelta(minutes=i)
        j.started_at = now - timedelta(minutes=i)
        j.completed_at = now - timedelta(minutes=i - 1)
        return j

    page2_jobs = [_make_history_job(i) for i in range(2, 4)]

    count_result = MagicMock()
    count_result.scalar_one.return_value = 5

    scalars_mock = MagicMock()
    scalars_mock.all.return_value = page2_jobs
    jobs_result = MagicMock()
    jobs_result.scalars.return_value = scalars_mock

    mock_db.execute = AsyncMock(side_effect=[count_result, jobs_result])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/repos/owner/repo/scan/history?page=2&per_page=2")

    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 5
    assert body["page"] == 2
    assert body["per_page"] == 2
    assert len(body["jobs"]) == 2


@pytest.mark.asyncio
async def test_scan_result_includes_static_features(app, mock_db):
    """ScanResult with feature_snapshot in metadata → static_features is populated."""
    job_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    mock_job = MagicMock(spec=ScanJob)
    mock_job.id = job_id
    mock_job.owner = "owner"
    mock_job.repo_name = "repo"
    mock_job.ecosystem = "npm"
    mock_job.scan_mode = "static_only"
    mock_job.status = "completed"
    mock_job.total_packages = 1
    mock_job.processed_packages = 1
    mock_job.scanned_packages = 1
    mock_job.total_dependency_nodes = 1
    mock_job.total_unique_packages = 1
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
    mock_result.risk_assessment = {
        "schema_version": "2026-04-20",
        "package_name": "lodash",
        "package_version": "4.17.21",
        "ecosystem": "npm",
        "overall_status": "clean",
        "overall_score": 0.05,
        "confidence": 0.05,
        "analysis_mode": "static-classifier",
        "allowlisted": False,
        "suppressed": False,
        "static_signals": [],
        "dynamic_signals": [],
        "vulnerability_signals": [],
        "reputation_signals": [],
        "policy_signals": [],
        "evidence": [],
        "explanation": "clean",
        "metadata": {
            "feature_snapshot": {
                "has_install_script": 0.0,
                "entropy": 0.35,
                "obfuscated_strings": 0.0,
            },
        },
    }
    mock_result.risk_breakdown = None
    mock_result.advisory_references = []
    mock_result.risk_allowlisted = False
    mock_result.risk_suppressed = False
    mock_result.risk_suppression_reason = None
    mock_result.analysis_status = None
    mock_result.analysis_coverage = None
    mock_result.scanner_version = "1.0.0"
    mock_result.error_message = None
    mock_result.scan_timestamp = now

    mock_job.results = [mock_result]

    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = mock_job
    mock_db.execute = AsyncMock(return_value=exec_result)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(f"/api/repos/owner/repo/scan/{job_id}")

    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["static_features"] is not None
    assert result["static_features"]["has_install_script"] == 0.0
    assert result["static_features"]["entropy"] == 0.35


@pytest.mark.asyncio
async def test_scan_result_includes_dynamic_findings(app, mock_db):
    """ScanResult with metadata.dynamic → dynamic_findings accessible in response."""
    job_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    mock_job = MagicMock(spec=ScanJob)
    mock_job.id = job_id
    mock_job.owner = "owner"
    mock_job.repo_name = "repo"
    mock_job.ecosystem = "npm"
    mock_job.scan_mode = "full"
    mock_job.status = "completed"
    mock_job.total_packages = 1
    mock_job.processed_packages = 1
    mock_job.scanned_packages = 1
    mock_job.total_dependency_nodes = 1
    mock_job.total_unique_packages = 1
    mock_job.error_message = None
    mock_job.started_at = now
    mock_job.completed_at = now
    mock_job.created_at = now

    mock_result = MagicMock(spec=ScanResult)
    mock_result.id = uuid.uuid4()
    mock_result.package_name = "evil-pkg"
    mock_result.package_version = "1.0.0"
    mock_result.ecosystem = "npm"
    mock_result.malware_status = "malicious"
    mock_result.malware_score = 0.97
    mock_result.risk_assessment = {
        "schema_version": "2026-04-20",
        "package_name": "evil-pkg",
        "package_version": "1.0.0",
        "ecosystem": "npm",
        "overall_status": "malicious",
        "overall_score": 0.97,
        "confidence": 0.97,
        "analysis_mode": "static-classifier",
        "allowlisted": False,
        "suppressed": False,
        "static_signals": [],
        "dynamic_signals": [],
        "vulnerability_signals": [],
        "reputation_signals": [],
        "policy_signals": [],
        "evidence": [],
        "explanation": "malicious",
        "metadata": {
            "dynamic": {
                "syscall_trace": ["execve", "socket", "connect"],
                "network_activity": [{"host": "evil.com", "port": 443}],
                "filesystem_changes": ["/etc/passwd"],
                "ioc_detail": {"c2_candidates": ["evil.com"]},
            },
        },
    }
    mock_result.risk_breakdown = None
    mock_result.advisory_references = []
    mock_result.risk_allowlisted = False
    mock_result.risk_suppressed = False
    mock_result.risk_suppression_reason = None
    mock_result.analysis_status = "completed"
    mock_result.analysis_coverage = "full"
    mock_result.scanner_version = "1.0.0"
    mock_result.error_message = None
    mock_result.scan_timestamp = now

    mock_job.results = [mock_result]

    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = mock_job
    mock_db.execute = AsyncMock(return_value=exec_result)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(f"/api/repos/owner/repo/scan/{job_id}")

    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["dynamic_findings"] is not None
    assert "syscall_trace" in result["dynamic_findings"]
    assert "execve" in result["dynamic_findings"]["syscall_trace"]
    assert result["dynamic_findings"]["ioc_detail"]["c2_candidates"] == ["evil.com"]


@pytest.mark.asyncio
async def test_get_scan_job_running_includes_progress_metrics(app, mock_db):
    """Running jobs should expose counters, rate and ETA fields."""
    job_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    mock_job = MagicMock(spec=ScanJob)
    mock_job.id = job_id
    mock_job.owner = "owner"
    mock_job.repo_name = "repo"
    mock_job.ecosystem = "npm"
    mock_job.scan_mode = "full"
    mock_job.status = "running"
    mock_job.total_packages = 20
    mock_job.scanned_packages = 10
    mock_job.total_dependency_nodes = 30
    mock_job.total_unique_packages = 20
    mock_job.error_message = None
    mock_job.started_at = now - timedelta(minutes=2)
    mock_job.completed_at = None
    mock_job.created_at = now
    mock_job.results = []

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
    assert body["total_dependency_nodes"] == 30
    assert body["total_unique_packages"] == 20
    assert body["progress_percent"] == 50.0
    assert body["elapsed_seconds"] is not None
    assert body["packages_per_minute"] is not None
    assert body["estimated_seconds_remaining"] is not None
