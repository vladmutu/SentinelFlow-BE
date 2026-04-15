"""Task-based background scan orchestration.

`run_scan_job` is intentionally lightweight. It only discovers package work,
persists one `ScanTask` row per package, and enqueues each task to workers.
Per-package execution and state transitions happen in `_scan_single_package`.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import httpx
from sqlalchemy import and_, case, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.models.scan import ScanJob, ScanResult, ScanTask
from app.services import manifest_utils, package_fetcher, scanner_service

logger = logging.getLogger(__name__)

_TASK_PENDING = "pending"
_TASK_DOWNLOADING = "downloading"
_TASK_ANALYZING = "analyzing"
_TASK_CLASSIFYING = "classifying"
_TASK_DONE = "done"
_TASK_FAILED = "failed"
_TASK_TERMINAL_STATES = {_TASK_DONE, _TASK_FAILED}

_scan_task_queue: asyncio.Queue[UUID] | None = None
_scan_worker_tasks: list[asyncio.Task] = []
_scan_worker_lock = asyncio.Lock()


async def run_scan_job(
    job_id: UUID,
    owner: str,
    repo: str,
    ecosystem: str,
    access_token: str,
    selected_packages: list[str] | None = None,
) -> None:
    """Create DB-backed package tasks and enqueue them for worker execution."""
    async with AsyncSessionLocal() as db:
        try:
            await _set_job_status(db, job_id, "running", started_at=datetime.now(timezone.utc))

            headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {access_token}",
                "X-GitHub-Api-Version": "2022-11-28",
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                if ecosystem == "npm":
                    manifest = await manifest_utils.fetch_npm_manifest(client, owner, repo, headers)
                    from app.api.endpoints.repos import (
                        _build_npm_tree_from_lockfile,
                        _build_tree_from_package_json,
                    )

                    if "lockfileVersion" in manifest or "packages" in manifest or "dependencies" in manifest:
                        tree = _build_npm_tree_from_lockfile(manifest)
                    else:
                        tree = _build_tree_from_package_json(manifest)

                    workload = manifest_utils.build_npm_scan_workload(manifest, tree)
                    packages = workload.refs
                    total_dependency_nodes = workload.total_dependency_nodes
                    total_unique_packages = workload.unique_packages
                elif ecosystem == "pypi":
                    manifest = await manifest_utils.fetch_pypi_manifest(client, owner, repo, headers)
                    packages = manifest_utils.flatten_pypi_manifest(manifest)
                    total_dependency_nodes = len(packages)
                    total_unique_packages = len(packages)
                else:
                    raise ValueError(f"Unsupported ecosystem: {ecosystem}")

            packages = _filter_selected_packages(packages, selected_packages)
            total_unique_packages = len(packages)

            if not packages:
                await _set_package_metrics(
                    db,
                    job_id,
                    total_packages=0,
                    total_dependency_nodes=total_dependency_nodes,
                    total_unique_packages=total_unique_packages,
                )
                await _set_job_status(
                    db,
                    job_id,
                    "completed",
                    completed_at=datetime.now(timezone.utc),
                )
                return

            await _set_package_metrics(
                db,
                job_id,
                total_packages=len(packages),
                total_dependency_nodes=total_dependency_nodes,
                total_unique_packages=total_unique_packages,
            )

            tasks = [
                ScanTask(
                    job_id=job_id,
                    package_name=ref.name,
                    package_version=ref.version,
                    ecosystem=ecosystem,
                    status=_TASK_PENDING,
                )
                for ref in packages
            ]
            db.add_all(tasks)
            await db.flush()
            await db.commit()

            for task in tasks:
                await enqueue_scan_task(task.id)

        except Exception as exc:
            logger.exception("Scan job %s failed during orchestration", job_id)
            try:
                await _set_job_status(
                    db,
                    job_id,
                    "failed",
                    error_message=str(exc),
                    completed_at=datetime.now(timezone.utc),
                )
            except Exception:
                logger.exception("Could not mark job %s as failed", job_id)


def _filter_selected_packages(
    packages: list[manifest_utils.PackageRef],
    selected_packages: list[str] | None,
) -> list[manifest_utils.PackageRef]:
    """Filter package refs by user-selected identifiers.

    Accepts either package name (e.g. ``lodash``) or exact name@version
    (e.g. ``lodash@4.17.21`` or ``@types/node@22.0.0``).
    """
    if not selected_packages:
        return packages

    selected_names: set[str] = set()
    selected_exact: set[str] = set()

    for raw in selected_packages:
        token = (raw or "").strip()
        if not token:
            continue

        # Parse as exact name@version using the last '@' to support scoped npm names.
        last_at = token.rfind("@")
        if last_at > 0 and last_at < len(token) - 1:
            pkg_name = token[:last_at].strip().lower()
            pkg_version = token[last_at + 1 :].strip()
            if pkg_name and pkg_version:
                selected_exact.add(f"{pkg_name}@{pkg_version}")
                continue

        selected_names.add(token.lower())

    if not selected_names and not selected_exact:
        return []

    filtered: list[manifest_utils.PackageRef] = []
    for ref in packages:
        name = ref.name.lower()
        exact = f"{name}@{ref.version}"
        if name in selected_names or exact in selected_exact:
            filtered.append(ref)

    return filtered


async def enqueue_scan_task(task_id: UUID) -> None:
    """Enqueue a single package task for asynchronous worker processing."""
    await _ensure_scan_workers_started()
    assert _scan_task_queue is not None
    await _scan_task_queue.put(task_id)


async def _ensure_scan_workers_started() -> None:
    global _scan_task_queue

    if _scan_task_queue is not None and _scan_worker_tasks:
        return

    async with _scan_worker_lock:
        if _scan_task_queue is None:
            _scan_task_queue = asyncio.Queue()

        if _scan_worker_tasks:
            return

        worker_count = max(1, settings.scanner_concurrency)
        for worker_index in range(worker_count):
            worker = asyncio.create_task(_scan_task_worker(worker_index))
            _scan_worker_tasks.append(worker)


async def _scan_task_worker(worker_index: int) -> None:
    assert _scan_task_queue is not None

    while True:
        task_id = await _scan_task_queue.get()
        try:
            await _scan_single_package(task_id)
        except Exception as exc:
            logger.exception("Worker %s crashed processing task %s: %s", worker_index, task_id, exc)
        finally:
            _scan_task_queue.task_done()


async def _scan_single_package(task_id: UUID) -> None:
    """Execute one package task by id with explicit status transitions."""
    task = await _load_task(task_id)
    if task is None:
        logger.warning("Task %s not found", task_id)
        return

    if task.status in _TASK_TERMINAL_STATES:
        return

    if task.status not in {_TASK_PENDING, _TASK_FAILED}:
        logger.info("Task %s already in-flight with status=%s; skipping duplicate", task_id, task.status)
        return

    if await _is_job_cancelled(task.job_id):
        logger.info("Task %s skipped: parent job %s is cancelled", task_id, task.job_id)
        await _set_task_status(task_id, _TASK_DONE)
        return

    tmp_dir = Path(tempfile.mkdtemp(prefix="sentinel_pkg_"))
    try:
        await _set_task_status(task_id, _TASK_DOWNLOADING)

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
                if task.ecosystem == "npm":
                    artifact_path = await package_fetcher.fetch_npm_package(
                        task.package_name,
                        task.package_version,
                        tmp_dir,
                        client=client,
                    )
                else:
                    artifact_path = await package_fetcher.fetch_pypi_package(
                        task.package_name,
                        task.package_version,
                        tmp_dir,
                        client=client,
                    )
        except Exception as exc:
            await _set_task_failed(task_id, f"Download failed: {exc}")
            return

        await _set_task_status(task_id, _TASK_ANALYZING)
        try:
            features = await asyncio.to_thread(scanner_service.extract_features, artifact_path)
        except Exception as exc:
            await _set_task_failed(task_id, f"Feature extraction failed: {exc}")
            return

        await _set_task_status(task_id, _TASK_CLASSIFYING)
        verdict = await asyncio.to_thread(scanner_service.classify_features, features)

        if verdict.malware_status == "error":
            await _set_task_failed(task_id, verdict.error_message or "Classifier returned error")
            return

        await _set_task_done(task_id, verdict)

    except Exception as exc:
        logger.exception("Task %s failed", task_id)
        await _set_task_failed(task_id, str(exc))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def _is_job_cancelled(job_id: UUID) -> bool:
    """Return whether a scan job is currently marked as cancelled."""
    async with AsyncSessionLocal() as db:
        stmt = select(ScanJob.status).where(ScanJob.id == job_id)
        result = await db.execute(stmt)
        status_value = result.scalar_one_or_none()
        return status_value == "cancelled"


# -- persistence helpers ------------------------------------------------

async def _load_task(task_id: UUID) -> ScanTask | None:
    async with AsyncSessionLocal() as db:
        stmt = select(ScanTask).where(ScanTask.id == task_id)
        return (await db.execute(stmt)).scalar_one_or_none()


async def _set_task_status(task_id: UUID, status: str) -> None:
    async with AsyncSessionLocal() as db:
        stmt = select(ScanTask).where(ScanTask.id == task_id)
        task = (await db.execute(stmt)).scalar_one_or_none()
        if task is None:
            return

        now = datetime.now(timezone.utc)
        task.status = status
        task.updated_at = now
        if status == _TASK_DOWNLOADING and task.started_at is None:
            task.started_at = now
        await db.commit()


async def _set_task_done(task_id: UUID, verdict: scanner_service.ScanVerdict) -> None:
    async with AsyncSessionLocal() as db:
        stmt = select(ScanTask).where(ScanTask.id == task_id)
        task = (await db.execute(stmt)).scalar_one_or_none()
        if task is None or task.status in _TASK_TERMINAL_STATES:
            return

        now = datetime.now(timezone.utc)
        task.status = _TASK_DONE
        task.malware_status = verdict.malware_status
        task.malware_score = verdict.malware_score
        task.error_message = verdict.error_message
        task.updated_at = now
        task.completed_at = now

        await _upsert_result_from_task(db, task, scanner_version=verdict.scanner_version)
        await _increment_processed_once(db, task.job_id)
        await db.commit()


async def _set_task_failed(task_id: UUID, error_message: str) -> None:
    async with AsyncSessionLocal() as db:
        stmt = select(ScanTask).where(ScanTask.id == task_id)
        task = (await db.execute(stmt)).scalar_one_or_none()
        if task is None or task.status in _TASK_TERMINAL_STATES:
            return

        now = datetime.now(timezone.utc)
        task.status = _TASK_FAILED
        task.error_message = error_message
        task.malware_status = "error"
        task.updated_at = now
        task.completed_at = now

        await _upsert_result_from_task(db, task, scanner_version=scanner_service.SCANNER_VERSION)
        await _increment_processed_once(db, task.job_id)
        await db.commit()


async def _upsert_result_from_task(
    db: AsyncSession,
    task: ScanTask,
    *,
    scanner_version: str,
) -> None:
    stmt = select(ScanResult).where(
        ScanResult.job_id == task.job_id,
        ScanResult.package_name == task.package_name,
        ScanResult.package_version == task.package_version,
        ScanResult.ecosystem == task.ecosystem,
    )
    existing = (await db.execute(stmt)).scalar_one_or_none()

    if existing is None:
        db.add(
            ScanResult(
                job_id=task.job_id,
                package_name=task.package_name,
                package_version=task.package_version,
                ecosystem=task.ecosystem,
                malware_status=task.malware_status or "unknown",
                malware_score=task.malware_score,
                scanner_version=scanner_version,
                error_message=task.error_message,
            )
        )
        return

    existing.malware_status = task.malware_status or "unknown"
    existing.malware_score = task.malware_score
    existing.error_message = task.error_message
    existing.scanner_version = scanner_version
    existing.scan_timestamp = datetime.now(timezone.utc)


async def _increment_processed_once(db: AsyncSession, job_id: UUID) -> None:
    now = datetime.now(timezone.utc)
    will_complete = and_(
        ScanJob.status == "running",
        ScanJob.total_packages > 0,
        (ScanJob.processed_packages + 1) >= ScanJob.total_packages,
    )
    stmt = (
        update(ScanJob)
        .where(ScanJob.id == job_id)
        .values(
            processed_packages=ScanJob.processed_packages + 1,
            scanned_packages=ScanJob.scanned_packages + 1,
            status=case((will_complete, "completed"), else_=ScanJob.status),
            completed_at=case((will_complete, now), else_=ScanJob.completed_at),
        )
    )
    await db.execute(stmt)


async def _set_job_status(
    db: AsyncSession,
    job_id: UUID,
    status: str,
    *,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    error_message: str | None = None,
) -> None:
    stmt = select(ScanJob).where(ScanJob.id == job_id)
    row = (await db.execute(stmt)).scalar_one()
    row.status = status
    if started_at is not None:
        row.started_at = started_at
    if completed_at is not None:
        row.completed_at = completed_at
    if error_message is not None:
        row.error_message = error_message
    await db.commit()


async def _set_package_metrics(
    db: AsyncSession,
    job_id: UUID,
    *,
    total_packages: int,
    total_dependency_nodes: int,
    total_unique_packages: int,
) -> None:
    stmt = select(ScanJob).where(ScanJob.id == job_id)
    row = (await db.execute(stmt)).scalar_one()
    row.total_packages = total_packages
    row.total_dependency_nodes = total_dependency_nodes
    row.total_unique_packages = total_unique_packages
    row.processed_packages = 0
    row.scanned_packages = 0
    await db.commit()
