"""Tests for the scan orchestrator – parallelism, partial failures, and flow."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.manifest_utils import PackageRef
from app.services.scanner_service import ScanVerdict


# ── Parallel execution ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_packages_scanned_in_parallel():
    """Verify that multiple packages are scanned concurrently, not serially."""
    import time
    start_times: list[float] = []

    async def fake_fetch_npm(name, version, dest, *, client=None):
        start_times.append(time.monotonic())
        await asyncio.sleep(0.05)  # simulate I/O
        fake_file = dest / f"{name}-{version}.tgz"
        fake_file.write_bytes(b"fake")
        return fake_file

    packages = [PackageRef(f"pkg-{i}", "1.0.0") for i in range(5)]
    fake_tree = {
        "name": "project",
        "version": "1.0.0",
        "children": [{"name": p.name, "version": p.version, "children": []} for p in packages],
    }

    job_id = uuid.uuid4()
    fake_job = MagicMock()
    fake_job.id = job_id
    fake_job.status = "pending"
    fake_job.total_packages = 0
    fake_job.scanned_packages = 0
    fake_job.started_at = None
    fake_job.completed_at = None
    fake_job.error_message = None

    mock_db = AsyncMock()
    mock_exec = MagicMock()
    mock_exec.scalar_one.return_value = fake_job
    mock_db.execute = AsyncMock(return_value=mock_exec)
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()

    verdict = ScanVerdict(malware_status="clean", malware_score=0.01)

    with (
        patch("app.services.scan_orchestrator.AsyncSessionLocal") as mock_session_cls,
        patch("app.services.scan_orchestrator.manifest_utils") as mock_manifest,
        patch("app.services.scan_orchestrator.package_fetcher") as mock_fetcher,
        patch("app.services.scan_orchestrator.scanner_service") as mock_scanner,
        patch("app.services.scan_orchestrator.httpx.AsyncClient") as mock_client_cls,
        patch("app.api.endpoints.repos._build_npm_tree_from_lockfile", return_value=fake_tree),
        patch("app.api.endpoints.repos._build_tree_from_package_json", return_value=fake_tree),
    ):
        # Configure the async context manager for the session
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        # Configure httpx client context manager
        mock_http_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_manifest.fetch_npm_manifest = AsyncMock(return_value={"lockfileVersion": 2})
        mock_manifest.flatten_dependencies = MagicMock(return_value=packages)
        mock_fetcher.fetch_npm_package = fake_fetch_npm
        mock_scanner.classify = MagicMock(return_value=verdict)
        mock_scanner.SCANNER_VERSION = "1.0.0"

        from app.services.scan_orchestrator import run_scan_job
        await run_scan_job(job_id, "owner", "repo", "npm", "token")

    # If run in parallel, all start times should be very close together.
    if len(start_times) >= 2:
        span = max(start_times) - min(start_times)
        # Sequential would take ~5 * 0.05 = 0.25s. Parallel should be < 0.1s.
        assert span < 0.15, f"Tasks appear sequential (span={span:.3f}s)"


# ── Partial failure handling ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_single_package_failure_does_not_abort_job():
    """If one package download fails, other packages should still be scanned."""

    async def fail_first_fetch(name, version, dest, *, client=None):
        if name == "bad-pkg":
            raise FileNotFoundError("not on registry")
        fake_file = dest / f"{name}-{version}.tgz"
        fake_file.write_bytes(b"fake")
        return fake_file

    packages = [
        PackageRef("bad-pkg", "1.0.0"),
        PackageRef("good-pkg", "2.0.0"),
    ]
    fake_tree = {
        "name": "project",
        "version": "1.0.0",
        "children": [{"name": p.name, "version": p.version, "children": []} for p in packages],
    }

    job_id = uuid.uuid4()
    fake_job = MagicMock()
    fake_job.id = job_id
    fake_job.status = "pending"
    fake_job.total_packages = 0
    fake_job.scanned_packages = 0
    fake_job.started_at = None
    fake_job.completed_at = None
    fake_job.error_message = None

    mock_db = AsyncMock()
    mock_exec = MagicMock()
    mock_exec.scalar_one.return_value = fake_job
    mock_db.execute = AsyncMock(return_value=mock_exec)
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()

    saved_results: list = []
    original_add = mock_db.add

    def track_add(obj):
        if hasattr(obj, "malware_status"):
            saved_results.append(obj)
        return original_add(obj)

    mock_db.add = track_add

    verdict = ScanVerdict(malware_status="clean", malware_score=0.02)

    with (
        patch("app.services.scan_orchestrator.AsyncSessionLocal") as mock_session_cls,
        patch("app.services.scan_orchestrator.manifest_utils") as mock_manifest,
        patch("app.services.scan_orchestrator.package_fetcher") as mock_fetcher,
        patch("app.services.scan_orchestrator.scanner_service") as mock_scanner,
        patch("app.services.scan_orchestrator.httpx.AsyncClient") as mock_client_cls,
        patch("app.api.endpoints.repos._build_npm_tree_from_lockfile", return_value=fake_tree),
        patch("app.api.endpoints.repos._build_tree_from_package_json", return_value=fake_tree),
    ):
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_http_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_manifest.fetch_npm_manifest = AsyncMock(return_value={"lockfileVersion": 2})
        mock_manifest.flatten_dependencies = MagicMock(return_value=packages)
        mock_fetcher.fetch_npm_package = fail_first_fetch
        mock_scanner.classify = MagicMock(return_value=verdict)
        mock_scanner.SCANNER_VERSION = "1.0.0"

        from app.services.scan_orchestrator import run_scan_job
        await run_scan_job(job_id, "owner", "repo", "npm", "token")

    # Both packages should have a result – one error, one clean.
    assert len(saved_results) == 2
    statuses = {r.malware_status for r in saved_results}
    assert "error" in statuses
    assert "clean" in statuses

    # Job should still be marked completed (not failed).
    assert fake_job.status == "completed"
