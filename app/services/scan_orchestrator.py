"""Background scan orchestration.

This module contains the main coroutine that is spawned by the job runner
when the user triggers a scan.  It:

1. Fetches the repository manifest from GitHub.
2. Flattens it into a list of ``PackageRef`` items.
3. Downloads and classifies each package **in parallel** (bounded by a
   semaphore so we don't exhaust file descriptors or memory).
4. Persists a ``ScanResult`` row per package and updates the ``ScanJob``.
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
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.models.scan import ScanJob, ScanResult
from app.services import manifest_utils, package_fetcher, scanner_service

logger = logging.getLogger(__name__)


async def run_scan_job(
    job_id: UUID,
    owner: str,
    repo: str,
    ecosystem: str,
    access_token: str,
) -> None:
    """Top-level background coroutine executed by the job runner.

    Args:
        job_id: Scan job identifier.
        owner: Repository owner.
        repo: Repository name.
        ecosystem: Dependency ecosystem (``npm`` or ``pypi``).
        access_token: GitHub OAuth token used to read repository manifests.
    """

    async with AsyncSessionLocal() as db:
        try:
            await _set_job_status(db, job_id, "running", started_at=datetime.now(timezone.utc))

            # ── 1. Fetch manifest from GitHub ──────────────────────────
            headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {access_token}",
                "X-GitHub-Api-Version": "2022-11-28",
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                if ecosystem == "npm":
                    manifest = await manifest_utils.fetch_npm_manifest(
                        client, owner, repo, headers,
                    )
                    # Build the tree the same way repos.py does so we can flatten it.
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
                    manifest = await manifest_utils.fetch_pypi_manifest(
                        client, owner, repo, headers,
                    )
                    packages = manifest_utils.flatten_pypi_manifest(manifest)
                    total_dependency_nodes = len(packages)
                    total_unique_packages = len(packages)
                else:
                    raise ValueError(f"Unsupported ecosystem: {ecosystem}")

            if not packages:
                await _set_package_metrics(
                    db,
                    job_id,
                    total_packages=0,
                    total_dependency_nodes=total_dependency_nodes,
                    total_unique_packages=total_unique_packages,
                )
                await _set_job_status(
                    db, job_id, "completed",
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

            # ── 2. Scan each package in parallel ───────────────────────
            semaphore = asyncio.Semaphore(settings.scanner_concurrency)

            async def _scan_one(ref: manifest_utils.PackageRef) -> None:
                """Process one dependency under the shared concurrency semaphore.

                Args:
                    ref: Dependency package reference to scan.
                """
                async with semaphore:
                    await _scan_single_package(job_id, ref, ecosystem)

            await asyncio.gather(*[_scan_one(ref) for ref in packages])

            # ── 3. Mark job completed ──────────────────────────────────
            await _set_job_status(
                db, job_id, "completed",
                completed_at=datetime.now(timezone.utc),
            )

        except Exception as exc:
            logger.exception("Scan job %s failed", job_id)
            try:
                await _set_job_status(
                    db, job_id, "failed",
                    error_message=str(exc),
                    completed_at=datetime.now(timezone.utc),
                )
            except Exception:
                logger.exception("Could not mark job %s as failed", job_id)


# ── helpers ────────────────────────────────────────────────────────────

async def _scan_single_package(
    job_id: UUID,
    ref: manifest_utils.PackageRef,
    ecosystem: str,
) -> None:
    """Download, classify, and persist the result for one package.

    Args:
        job_id: Scan job identifier.
        ref: Target dependency package reference.
        ecosystem: Dependency ecosystem (``npm`` or ``pypi``).
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="sentinel_pkg_"))
    try:
        # Download artifact
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
                if ecosystem == "npm":
                    artifact_path = await package_fetcher.fetch_npm_package(
                        ref.name, ref.version, tmp_dir, client=client,
                    )
                else:
                    artifact_path = await package_fetcher.fetch_pypi_package(
                        ref.name, ref.version, tmp_dir, client=client,
                    )
        except FileNotFoundError as exc:
            async with AsyncSessionLocal() as write_db:
                await _save_result(
                    write_db, job_id, ref, ecosystem,
                    malware_status="error",
                    error_message=str(exc),
                )
                await _increment_scanned(write_db, job_id)
            return
        except Exception as exc:
            logger.warning("Download failed for %s@%s: %s", ref.name, ref.version, exc)
            async with AsyncSessionLocal() as write_db:
                await _save_result(
                    write_db, job_id, ref, ecosystem,
                    malware_status="error",
                    error_message=f"Download failed: {exc}",
                )
                await _increment_scanned(write_db, job_id)
            return

        # Classify (CPU-bound → offload to thread)
        verdict = await asyncio.to_thread(scanner_service.classify, artifact_path)

        async with AsyncSessionLocal() as write_db:
            await _save_result(
                write_db, job_id, ref, ecosystem,
                malware_status=verdict.malware_status,
                malware_score=verdict.malware_score,
                scanner_version=verdict.scanner_version,
                error_message=verdict.error_message,
            )
            await _increment_scanned(write_db, job_id)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def _save_result(
    db: AsyncSession,
    job_id: UUID,
    ref: manifest_utils.PackageRef,
    ecosystem: str,
    *,
    malware_status: str,
    malware_score: float | None = None,
    scanner_version: str = scanner_service.SCANNER_VERSION,
    error_message: str | None = None,
) -> None:
    """Persist a single package scan result row.

    Args:
        db: Active asynchronous database session.
        job_id: Scan job identifier.
        ref: Target dependency package reference.
        ecosystem: Dependency ecosystem.
        malware_status: Classification status.
        malware_score: Optional model confidence score.
        scanner_version: Scanner version string.
        error_message: Optional error context for failed scans.
    """
    result = ScanResult(
        job_id=job_id,
        package_name=ref.name,
        package_version=ref.version,
        ecosystem=ecosystem,
        malware_status=malware_status,
        malware_score=malware_score,
        scanner_version=scanner_version,
        error_message=error_message,
    )
    db.add(result)
    await db.commit()


async def _set_job_status(
    db: AsyncSession,
    job_id: UUID,
    status: str,
    *,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    error_message: str | None = None,
) -> None:
    """Update status and lifecycle fields for a scan job.

    Args:
        db: Active asynchronous database session.
        job_id: Scan job identifier.
        status: New job status.
        started_at: Optional start timestamp.
        completed_at: Optional completion timestamp.
        error_message: Optional terminal failure message.
    """
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
    """Persist package counting metrics discovered for the job.

    Args:
        db: Active asynchronous database session.
        job_id: Scan job identifier.
        total_packages: Number of packages queued for scanning.
        total_dependency_nodes: Total dependency nodes in manifest/tree.
        total_unique_packages: Unique package identities in the workload.
    """
    stmt = select(ScanJob).where(ScanJob.id == job_id)
    row = (await db.execute(stmt)).scalar_one()
    row.total_packages = total_packages
    row.total_dependency_nodes = total_dependency_nodes
    row.total_unique_packages = total_unique_packages
    await db.commit()


async def _increment_scanned(db: AsyncSession, job_id: UUID) -> None:
    """Increment the scanned package counter for a job.

    Args:
        db: Active asynchronous database session.
        job_id: Scan job identifier.
    """
    stmt = (
        update(ScanJob)
        .where(ScanJob.id == job_id)
        .values(scanned_packages=ScanJob.scanned_packages + 1)
    )
    await db.execute(stmt)
    await db.commit()
