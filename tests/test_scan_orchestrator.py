"""Tests for task-based scan orchestration and worker flow."""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.manifest_utils import PackageRef
from app.services.scanner_service import ScanVerdict
from app.services.dynamic_analysis_service import DynamicAnalysisResult
from app.services.vulnerability_service import VulnerabilityLookupResult


@pytest.mark.asyncio
async def test_run_scan_job_creates_tasks_and_enqueues_each_package():
    """Orchestrator should create tasks and enqueue work without scanning inline."""
    packages = [
        PackageRef(
            f"pkg-{i}",
            "1.0.0",
            resolution={
                "source": "npm-manifest",
                "resolution_kind": "resolved",
                "is_direct_dependency": True,
                "transitive_depth": 1,
                "requested_spec": "^1.0.0",
                "resolved_version": "1.0.0",
                "resolved_artifact": True,
                "is_exact_version": False,
                "is_version_range": True,
            },
        )
        for i in range(4)
    ]

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
        mock_manifest.resolve_npm_dependency_tree = AsyncMock(return_value=fake_tree)
        mock_workload = MagicMock()
        mock_workload.refs = packages
        mock_workload.total_dependency_nodes = len(packages)
        mock_workload.unique_packages = len(packages)
        mock_manifest.build_npm_scan_workload = MagicMock(return_value=mock_workload)

        from app.services.scan_orchestrator import run_scan_job

        await run_scan_job(job_id, "owner", "repo", "npm", "token")

    assert fake_job.status == "running"
    assert mock_enqueue.await_count == len(packages)
    created_tasks = mock_db.add_all.call_args.args[0]
    assert created_tasks[0].dependency_context["requested_spec"] == "^1.0.0"
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
        patch("app.services.scan_orchestrator._find_recent_cached_result", new=AsyncMock(return_value=None)),
        patch("app.services.scan_orchestrator._set_task_status", new_callable=AsyncMock) as mock_status,
        patch("app.services.scan_orchestrator._set_task_done", new_callable=AsyncMock) as mock_done,
        patch("app.services.scan_orchestrator._set_task_failed", new_callable=AsyncMock) as mock_failed,
        patch("app.services.scan_orchestrator.enqueue_scan_task", new_callable=AsyncMock) as mock_requeue,
        patch("app.services.scan_orchestrator.package_fetcher.fetch_npm_package", new=AsyncMock(return_value=artifact)),
        patch("app.services.scan_orchestrator.scanner_service.extract_features", return_value={"f": 1.0}),
        patch("app.services.scan_orchestrator.scanner_service.classify_features", return_value=verdict),
        patch(
            "app.services.scan_orchestrator.dynamic_analysis_service.analyze_package_dynamically",
            new=AsyncMock(
                return_value=DynamicAnalysisResult(
                    signals=[],
                    evidence=["dynamic:skipped:disabled"],
                    metadata={"status": "skipped", "coverage": "none", "reason": "disabled"},
                )
            ),
        ) as mock_dynamic_lookup,
        patch(
            "app.services.scan_orchestrator.vulnerability_service.lookup_package_vulnerabilities",
            new=AsyncMock(
                return_value=VulnerabilityLookupResult(
                    signals=[],
                    advisory_references=[],
                    evidence=[],
                    metadata={"osv_match_count": 0, "nvd_match_count": 0},
                )
            ),
        ) as mock_vuln_lookup,
        patch("app.services.scan_orchestrator.scanner_service.build_package_risk_assessment") as mock_risk,
        patch("app.services.scan_orchestrator.httpx.AsyncClient") as mock_client_cls,
        patch("app.services.scan_orchestrator.shutil.rmtree") as mock_rmtree,
    ):
        mock_http_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_risk.return_value = MagicMock(model_dump=MagicMock(return_value={"overall_status": "clean"}))

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
    mock_risk.assert_called_once()
    mock_dynamic_lookup.assert_awaited_once_with("npm", "lodash", "4.17.21", artifact)
    mock_vuln_lookup.assert_awaited_once_with("npm", "lodash", "4.17.21")
    assert mock_risk.call_args.kwargs["dynamic_metadata"] == {
        "status": "skipped",
        "coverage": "none",
        "reason": "disabled",
    }
    assert mock_risk.call_args.kwargs["vulnerability_metadata"] == {
        "osv_match_count": 0,
        "nvd_match_count": 0,
    }


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
        patch("app.services.scan_orchestrator._find_recent_cached_result", new=AsyncMock(return_value=None)),
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


@pytest.mark.asyncio
async def test_scan_single_package_reuses_recent_cached_result():
    """Recent cached scan results should short-circuit expensive package analysis."""
    task_id = uuid.uuid4()
    fake_task = MagicMock()
    fake_task.id = task_id
    fake_task.job_id = uuid.uuid4()
    fake_task.package_name = "lodash"
    fake_task.package_version = "4.17.21"
    fake_task.ecosystem = "npm"
    fake_task.status = "pending"

    cached_result = MagicMock()
    cached_result.id = uuid.uuid4()
    cached_result.malware_status = "clean"
    cached_result.malware_score = 0.02
    cached_result.scanner_version = "1.0.0"
    cached_result.error_message = None
    cached_result.risk_assessment = {"overall_status": "clean", "metadata": {}, "evidence": []}

    with (
        patch("app.services.scan_orchestrator._load_task", new=AsyncMock(return_value=fake_task)),
        patch("app.services.scan_orchestrator._is_job_cancelled", new=AsyncMock(return_value=False)),
        patch("app.services.scan_orchestrator._find_recent_cached_result", new=AsyncMock(return_value=cached_result)),
        patch("app.services.scan_orchestrator._set_task_status", new_callable=AsyncMock) as mock_status,
        patch("app.services.scan_orchestrator._set_task_done", new_callable=AsyncMock) as mock_done,
        patch("app.services.scan_orchestrator.package_fetcher.fetch_npm_package", new=AsyncMock()) as mock_fetch,
    ):
        from app.services.scan_orchestrator import _scan_single_package

        await _scan_single_package(task_id)

    mock_status.assert_awaited_once_with(task_id, "downloading")
    mock_done.assert_awaited_once()
    mock_fetch.assert_not_awaited()
    risk_payload = mock_done.await_args.kwargs["risk_assessment"]
    assert "cache:scan_result_reuse" in risk_payload["evidence"]


@pytest.mark.asyncio
async def test_scan_single_package_skips_dynamic_for_low_priority_when_enabled():
    """Low-priority packages should skip remote dynamic analysis to preserve capacity."""
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
        patch("app.services.scan_orchestrator._find_recent_cached_result", new=AsyncMock(return_value=None)),
        patch("app.services.scan_orchestrator._set_task_status", new_callable=AsyncMock),
        patch("app.services.scan_orchestrator._set_task_done", new_callable=AsyncMock) as mock_done,
        patch("app.services.scan_orchestrator._set_task_failed", new_callable=AsyncMock),
        patch("app.services.scan_orchestrator.package_fetcher.fetch_npm_package", new=AsyncMock(return_value=artifact)),
        patch("app.services.scan_orchestrator.scanner_service.extract_features", return_value={"f": 1.0}),
        patch("app.services.scan_orchestrator.scanner_service.classify_features", return_value=verdict),
        patch(
            "app.services.scan_orchestrator.vulnerability_service.lookup_package_vulnerabilities",
            new=AsyncMock(
                return_value=VulnerabilityLookupResult(
                    signals=[],
                    advisory_references=[],
                    evidence=[],
                    metadata={"osv_match_count": 0, "nvd_match_count": 0},
                )
            ),
        ),
        patch(
            "app.services.scan_orchestrator.dynamic_analysis_service.analyze_package_dynamically",
            new=AsyncMock(),
        ) as mock_dynamic,
        patch(
            "app.services.scan_orchestrator.dynamic_analysis_service.build_skipped_dynamic_result",
            return_value=DynamicAnalysisResult(
                signals=[],
                evidence=["dynamic:skipped:priority_filtered"],
                metadata={"status": "skipped", "reason": "priority_filtered", "coverage": "none"},
            ),
        ) as mock_dynamic_skip,
        patch("app.services.scan_orchestrator.scanner_service.build_package_risk_assessment") as mock_risk,
        patch("app.services.scan_orchestrator.httpx.AsyncClient") as mock_client_cls,
        patch("app.services.scan_orchestrator.settings.dynamic_analysis_enabled", True),
        patch("app.services.scan_orchestrator.settings.dynamic_analysis_priority_threshold", 0.5),
    ):
        mock_http_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_risk.return_value = MagicMock(model_dump=MagicMock(return_value={"overall_status": "clean"}))

        from app.services.scan_orchestrator import _scan_single_package

        await _scan_single_package(task_id)

    mock_dynamic.assert_not_awaited()
    mock_dynamic_skip.assert_called_once()
    mock_done.assert_awaited_once()


@pytest.mark.asyncio
async def test_upsert_result_from_task_persists_risk_visibility_fields():
    """Persisted scan results should store derived risk visibility fields alongside the JSON payload."""
    task = MagicMock()
    task.job_id = uuid.uuid4()
    task.package_name = "lodash"
    task.package_version = "4.17.21"
    task.ecosystem = "npm"
    task.malware_status = "clean"
    task.malware_score = 0.12
    task.error_message = None

    risk_assessment = {
        "overall_status": "clean",
        "overall_score": 0.12,
        "allowlisted": True,
        "suppressed": False,
        "suppression_reason": None,
        "advisory_references": ["GHSA-1234"],
        "metadata": {
            "scoring": {"breakdown": {"classifier": {"score": 0.12, "weight": 1.0}}},
            "dynamic": {"status": "skipped", "coverage": "none"},
        },
    }

    mock_db = AsyncMock()
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_exec)
    mock_db.add = MagicMock()

    from app.services.scan_orchestrator import _upsert_result_from_task

    await _upsert_result_from_task(
        mock_db,
        task,
        scanner_version="1.0.0",
        risk_assessment=risk_assessment,
    )

    created_result = mock_db.add.call_args.args[0]
    assert created_result.risk_breakdown == {"classifier": {"score": 0.12, "weight": 1.0}}
    assert created_result.advisory_references == ["GHSA-1234"]
    assert created_result.risk_allowlisted is True
    assert created_result.risk_suppressed is False
    assert created_result.analysis_status == "skipped"
    assert created_result.analysis_coverage == "none"


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
