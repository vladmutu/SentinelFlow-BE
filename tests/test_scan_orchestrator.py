"""Tests for task-based scan orchestration and worker flow."""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.manifest_utils import PackageRef
from app.services.scanner_service import ScanVerdict


@pytest.mark.asyncio
async def test_run_scan_job_creates_tasks_and_enqueues_each_package():
    """Orchestrator should create tasks and enqueue work without scanning inline."""
    packages = [PackageRef(f"pkg-{i}", "1.0.0") for i in range(4)]

    job_id = uuid.uuid4()
    fake_job = MagicMock()
    fake_job.id = job_id
    fake_job.status = "pending"
    fake_job.total_packages = 0
    fake_job.processed_packages = 0
    fake_job.scanned_packages = 0
    fake_job.started_at = None
    fake_job.completed_at = None
    fake_job.error_message = None

    mock_db = AsyncMock()
    mock_exec = MagicMock()
    mock_exec.scalar_one.return_value = fake_job
    mock_db.execute = AsyncMock(return_value=mock_exec)
    mock_db.add_all = MagicMock()
    mock_db.flush = AsyncMock()
    mock_db.commit = AsyncMock()

    fake_tree = {
        "name": "project",
        "version": "1.0.0",
        "children": [{"name": p.name, "version": p.version, "children": []} for p in packages],
    }

    with (
        patch("app.services.scan_orchestrator.AsyncSessionLocal") as mock_session_cls,
        patch("app.services.scan_orchestrator.manifest_utils") as mock_manifest,
        patch("app.services.scan_orchestrator.httpx.AsyncClient") as mock_client_cls,
        patch("app.services.scan_orchestrator.enqueue_scan_task", new_callable=AsyncMock) as mock_enqueue,
        patch("app.api.endpoints.repos._build_npm_tree_from_lockfile", return_value=fake_tree),
        patch("app.api.endpoints.repos._build_tree_from_package_json", return_value=fake_tree),
        patch("app.services.scan_orchestrator._scan_single_package", new_callable=AsyncMock) as mock_old_worker,
    ):
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_http_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_manifest.fetch_npm_manifest = AsyncMock(return_value={"lockfileVersion": 2})
        mock_workload = MagicMock()
        mock_workload.refs = packages
        mock_workload.total_dependency_nodes = len(packages)
        mock_workload.unique_packages = len(packages)
        mock_manifest.build_npm_scan_workload = MagicMock(return_value=mock_workload)

        from app.services.scan_orchestrator import run_scan_job

        await run_scan_job(job_id, "owner", "repo", "npm", "token")

    assert fake_job.status == "running"
    assert mock_enqueue.await_count == len(packages)
    mock_old_worker.assert_not_called()


@pytest.mark.asyncio
async def test_scan_single_package_success_transitions_in_order():
    """Worker should transition through all task states and persist done verdict."""
    task_id = uuid.uuid4()
    fake_task = MagicMock()
    fake_task.id = task_id
    fake_task.job_id = uuid.uuid4()
    fake_task.package_name = "lodash"
    fake_task.package_version = "4.17.21"
    fake_task.ecosystem = "npm"
    fake_task.status = "pending"

    artifact = Path("C:/tmp/lodash-4.17.21.tgz")
    verdict = ScanVerdict(malware_status="clean", malware_score=0.01)

    with (
        patch("app.services.scan_orchestrator._load_task", new=AsyncMock(return_value=fake_task)),
        patch("app.services.scan_orchestrator._is_job_cancelled", new=AsyncMock(return_value=False)),
        patch("app.services.scan_orchestrator._set_task_status", new_callable=AsyncMock) as mock_status,
        patch("app.services.scan_orchestrator._set_task_done", new_callable=AsyncMock) as mock_done,
        patch("app.services.scan_orchestrator._set_task_failed", new_callable=AsyncMock) as mock_failed,
        patch("app.services.scan_orchestrator.enqueue_scan_task", new_callable=AsyncMock) as mock_requeue,
        patch("app.services.scan_orchestrator.package_fetcher.fetch_npm_package", new=AsyncMock(return_value=artifact)),
        patch("app.services.scan_orchestrator.scanner_service.extract_features", return_value={"f": 1.0}),
        patch("app.services.scan_orchestrator.scanner_service.classify_features", return_value=verdict),
        patch("app.services.scan_orchestrator.httpx.AsyncClient") as mock_client_cls,
        patch("app.services.scan_orchestrator.shutil.rmtree") as mock_rmtree,
    ):
        mock_http_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        from app.services.scan_orchestrator import _scan_single_package

        await _scan_single_package(task_id)

    assert [call.args[1] for call in mock_status.await_args_list] == [
        "downloading",
        "analyzing",
        "classifying",
    ]
    mock_done.assert_awaited_once()
    mock_failed.assert_not_awaited()
    mock_requeue.assert_not_awaited()
    mock_rmtree.assert_called_once()


@pytest.mark.asyncio
async def test_scan_single_package_failure_marks_failed_without_inline_retry():
    """Download failure should mark task as failed with no inline retry loop."""
    task_id = uuid.uuid4()
    fake_task = MagicMock()
    fake_task.id = task_id
    fake_task.job_id = uuid.uuid4()
    fake_task.package_name = "bad-pkg"
    fake_task.package_version = "1.0.0"
    fake_task.ecosystem = "npm"
    fake_task.status = "pending"

    with (
        patch("app.services.scan_orchestrator._load_task", new=AsyncMock(return_value=fake_task)),
        patch("app.services.scan_orchestrator._is_job_cancelled", new=AsyncMock(return_value=False)),
        patch("app.services.scan_orchestrator._set_task_status", new_callable=AsyncMock),
        patch("app.services.scan_orchestrator._set_task_done", new_callable=AsyncMock) as mock_done,
        patch("app.services.scan_orchestrator._set_task_failed", new_callable=AsyncMock) as mock_failed,
        patch("app.services.scan_orchestrator.enqueue_scan_task", new_callable=AsyncMock) as mock_requeue,
        patch(
            "app.services.scan_orchestrator.package_fetcher.fetch_npm_package",
            new=AsyncMock(side_effect=FileNotFoundError("not found")),
        ),
        patch("app.services.scan_orchestrator.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_http_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        from app.services.scan_orchestrator import _scan_single_package

        await _scan_single_package(task_id)

    mock_done.assert_not_awaited()
    mock_failed.assert_awaited_once()
    mock_requeue.assert_not_awaited()


def test_filter_selected_packages_supports_name_and_exact_name_version():
    """Selection filter should match by package name and by exact name@version."""
    from app.services.scan_orchestrator import _filter_selected_packages

    packages = [
        PackageRef(name="lodash", version="4.17.21"),
        PackageRef(name="react", version="19.2.4"),
        PackageRef(name="@types/node", version="22.0.0"),
    ]

    filtered = _filter_selected_packages(
        packages,
        ["lodash", "@types/node@22.0.0"],
    )

    assert {(p.name, p.version) for p in filtered} == {
        ("lodash", "4.17.21"),
        ("@types/node", "22.0.0"),
    }


def test_filter_selected_packages_empty_selection_returns_all():
    """No selection should preserve original full scan behavior."""
    from app.services.scan_orchestrator import _filter_selected_packages

    packages = [
        PackageRef(name="lodash", version="4.17.21"),
        PackageRef(name="react", version="19.2.4"),
    ]

    assert _filter_selected_packages(packages, None) == packages
    assert _filter_selected_packages(packages, []) == packages
