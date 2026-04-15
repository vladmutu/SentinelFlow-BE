"""REST endpoints for the malware-scan workflow.

* ``POST /{owner}/{repo_name}/scan``      – trigger a new scan job.
* ``GET  /{owner}/{repo_name}/scan/{job_id}`` – poll job status + results.
* ``GET  /{owner}/{repo_name}/scan/latest/results`` – latest results map
  for graph highlighting.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user
from app.api.schemas.scan import (
    ScanJobResponse,
    ScanResultMapEntry,
    ScanResultResponse,
    ScanTriggerRequest,
    ScanTriggerResponse,
)
from app.db.session import get_db
from app.models.scan import ScanJob, ScanResult
from app.models.user import User
from app.services.job_runner import job_runner
from app.services.scan_orchestrator import run_scan_job

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Scan"])


def _to_int(value: object, default: int = 0) -> int:
    """Convert numeric-like values to int with a safe fallback."""
    try:
        if value is None:
            return default
        if not isinstance(value, (int, float, str)):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


# ── Trigger ────────────────────────────────────────────────────────────

@router.post(
    "/{owner}/{repo_name}/scan",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanTriggerResponse,
)
async def trigger_scan(
    owner: str,
    repo_name: str,
    body: ScanTriggerRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanTriggerResponse:
    """Create a scan job and start it in the background.

    Args:
        owner: Repository owner or organization.
        repo_name: Repository name.
        body: Scan trigger payload containing selected ecosystem.
        current_user: Authenticated user launching the scan.
        db: Active asynchronous database session.

    Returns:
        ScanTriggerResponse: Identifier and initial status of the created job.
    """
    job = ScanJob(
        owner=owner,
        repo_name=repo_name,
        ecosystem=body.ecosystem,
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Fire-and-forget background task.
    job_runner.submit(
        run_scan_job(
            job_id=job.id,
            owner=owner,
            repo=repo_name,
            ecosystem=body.ecosystem,
            access_token=current_user.access_token,
            selected_packages=body.selected_packages,
        )
    )

    return ScanTriggerResponse(job_id=job.id, status=job.status)


# ── Cancel ─────────────────────────────────────────────────────────────

@router.post(
    "/{owner}/{repo_name}/scan/{job_id}/cancel",
    status_code=status.HTTP_200_OK,
    response_model=dict,
)
async def cancel_scan(
    owner: str,
    repo_name: str,
    job_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Cancel an active scan job.

    Args:
        owner: Repository owner or organization.
        repo_name: Repository name.
        job_id: Scan job identifier.
        current_user: Authenticated user cancelling the scan.
        db: Active asynchronous database session.

    Returns:
        dict: Confirmation with new status.

    Raises:
        HTTPException: If no matching scan job exists or it's already completed.
    """
    stmt = select(ScanJob).where(
        ScanJob.id == job_id,
        ScanJob.owner == owner,
        ScanJob.repo_name == repo_name,
    )
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()

    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan job not found",
        )

    if job.status in ("completed", "cancelled", "failed"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel job with status '{job.status}'",
        )

    job.status = "cancelled"
    job.error_message = "Cancelled by user"
    await db.commit()
    await db.refresh(job)

    logger.info(f"Scan job {job_id} cancelled by user {current_user.id}")

    return {"job_id": job.id, "status": job.status, "message": "Scan cancelled"}


# ── Latest Completed Scan ─────────────────────────────────────────────

@router.get(
    "/{owner}/{repo_name}/scan/latest",
    response_model=Optional[ScanJobResponse],
)
async def get_latest_scan_job(
    owner: str,
    repo_name: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Optional[ScanJobResponse]:
    """Return the full job details (status, progress, timestamp, results) 
    for the most recent **completed** scan.

    This endpoint is used by the "Latest Completed Scan Summary" panel
    to display job metadata alongside results.

    Args:
        owner: Repository owner or organization.
        repo_name: Repository name.
        current_user: Authenticated user requesting job details.
        db: Active asynchronous database session.

    Returns:
        ScanJobResponse | None: Full job with metadata and results, or None 
            if no completed scan exists.
    """
    # Find the latest completed job for this repo.
    job_stmt = (
        select(ScanJob)
        .where(
            ScanJob.owner == owner,
            ScanJob.repo_name == repo_name,
            ScanJob.status == "completed",
        )
        .order_by(ScanJob.completed_at.desc())
        .limit(1)
        .options(selectinload(ScanJob.results))
    )
    job = (await db.execute(job_stmt)).scalar_one_or_none()

    if job is None:
        return None

    # Reuse the same logic from get_scan_job to compute progress metrics
    total_packages = _to_int(job.total_packages, 0)
    total_dependency_nodes = _to_int(job.total_dependency_nodes, 0)
    total_unique = _to_int(job.total_unique_packages, 0) or total_packages
    processed_raw = _to_int(getattr(job, "processed_packages", None), 0)
    scanned_raw = processed_raw if processed_raw > 0 else _to_int(job.scanned_packages, 0)
    scanned = min(scanned_raw, total_unique) if total_unique > 0 else scanned_raw

    progress_percent = 0.0
    if total_unique > 0:
        progress_percent = min(100.0, max(0.0, (scanned / total_unique) * 100.0))

    elapsed_seconds: int | None = None
    packages_per_minute: float | None = None
    estimated_seconds_remaining: int | None = None

    if job.started_at is not None:
        end_ts = job.completed_at or datetime.now(timezone.utc)
        elapsed_seconds = max(0, int((end_ts - job.started_at).total_seconds()))
        elapsed_minutes = elapsed_seconds / 60.0
        if elapsed_minutes > 0 and scanned > 0:
            packages_per_minute = round(scanned / elapsed_minutes, 2)

    if job.status == "completed":
        estimated_seconds_remaining = 0

    try:
        return ScanJobResponse(
            id=job.id,
            owner=job.owner,
            repo_name=job.repo_name,
            ecosystem=job.ecosystem,
            status=job.status,
            total_packages=total_packages,
            scanned_packages=scanned,
            total_dependency_nodes=total_dependency_nodes,
            total_unique_packages=total_unique,
            progress_percent=progress_percent,
            elapsed_seconds=elapsed_seconds,
            packages_per_minute=packages_per_minute,
            estimated_seconds_remaining=estimated_seconds_remaining,
            error_message=job.error_message,
            started_at=job.started_at,
            completed_at=job.completed_at,
            created_at=job.created_at,
            results=[ScanResultResponse.model_validate(item) for item in job.results],
        )
    except Exception as e:
        logger.error(
            f"Failed to construct ScanJobResponse for latest job {job.id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to serialize job data: {str(e)}",
        )


# ── Graph-highlighting companion ──────────────────────────────────────

@router.get(
    "/{owner}/{repo_name}/scan/latest/results",
    response_model=dict[str, ScanResultMapEntry],
)
async def get_latest_scan_results(
    owner: str,
    repo_name: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, ScanResultMapEntry]:
    """Return the results of the most recent **completed** scan as a map
    keyed by ``<package_name>@<version>`` so the frontend can merge them
    into the dependency-graph nodes.

    Each value contains ``malware_status``, ``malware_score``,
    ``scan_timestamp``, and ``scanner_version``.

    Args:
        owner: Repository owner or organization.
        repo_name: Repository name.
        current_user: Authenticated user requesting results.
        db: Active asynchronous database session.

    Returns:
        dict[str, ScanResultMapEntry]: Mapping keyed by package identity.
    """
    # Find the latest completed job for this repo.
    job_stmt = (
        select(ScanJob)
        .where(
            ScanJob.owner == owner,
            ScanJob.repo_name == repo_name,
            ScanJob.status == "completed",
        )
        .order_by(ScanJob.completed_at.desc())
        .limit(1)
    )
    job = (await db.execute(job_stmt)).scalar_one_or_none()

    if job is None:
        return {}

    results_stmt = select(ScanResult).where(ScanResult.job_id == job.id)
    rows = (await db.execute(results_stmt)).scalars().all()

    return {
        f"{r.package_name}@{r.package_version}": ScanResultMapEntry.model_validate(r)
        for r in rows
    }


# ── Status / results ──────────────────────────────────────────────────

@router.get(
    "/{owner}/{repo_name}/scan/{job_id}",
    response_model=ScanJobResponse,
)
async def get_scan_job(
    owner: str,
    repo_name: str,
    job_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanJobResponse:
    """Return full job status including per-package results.

    Args:
        owner: Repository owner or organization.
        repo_name: Repository name.
        job_id: Scan job identifier.
        current_user: Authenticated user requesting job status.
        db: Active asynchronous database session.

    Returns:
        ScanJobResponse: Complete job model including result rows.

    Raises:
        HTTPException: If no matching scan job exists.
    """
    stmt = (
        select(ScanJob)
        .where(ScanJob.id == job_id, ScanJob.owner == owner, ScanJob.repo_name == repo_name)
        .options(selectinload(ScanJob.results))
    )
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan job not found",
        )

    total_packages = _to_int(job.total_packages, 0)
    total_dependency_nodes = _to_int(job.total_dependency_nodes, 0)
    total_unique = _to_int(job.total_unique_packages, 0) or total_packages
    processed_raw = _to_int(getattr(job, "processed_packages", None), 0)
    scanned_raw = processed_raw if processed_raw > 0 else _to_int(job.scanned_packages, 0)
    scanned = min(scanned_raw, total_unique) if total_unique > 0 else scanned_raw

    progress_percent = 0.0
    if total_unique > 0:
        progress_percent = min(100.0, max(0.0, (scanned / total_unique) * 100.0))

    elapsed_seconds: int | None = None
    packages_per_minute: float | None = None
    estimated_seconds_remaining: int | None = None

    if job.started_at is not None:
        end_ts = job.completed_at or datetime.now(timezone.utc)
        elapsed_seconds = max(0, int((end_ts - job.started_at).total_seconds()))
        elapsed_minutes = elapsed_seconds / 60.0
        if elapsed_minutes > 0 and scanned > 0:
            packages_per_minute = round(scanned / elapsed_minutes, 2)

    if job.status == "completed":
        estimated_seconds_remaining = 0
    elif job.status == "running" and packages_per_minute and packages_per_minute > 0 and total_unique > 0:
        remaining = max(0, total_unique - scanned)
        estimated_seconds_remaining = int(round((remaining / packages_per_minute) * 60.0))

    return ScanJobResponse(
        id=job.id,
        owner=job.owner,
        repo_name=job.repo_name,
        ecosystem=job.ecosystem,
        status=job.status,
        total_packages=total_packages,
        scanned_packages=scanned,
        total_dependency_nodes=total_dependency_nodes,
        total_unique_packages=total_unique,
        progress_percent=progress_percent,
        elapsed_seconds=elapsed_seconds,
        packages_per_minute=packages_per_minute,
        estimated_seconds_remaining=estimated_seconds_remaining,
        error_message=job.error_message,
        started_at=job.started_at,
        completed_at=job.completed_at,
        created_at=job.created_at,
        results=[ScanResultResponse.model_validate(item) for item in job.results],
    )
