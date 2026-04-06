"""REST endpoints for the malware-scan workflow.

* ``POST /{owner}/{repo_name}/scan``      – trigger a new scan job.
* ``GET  /{owner}/{repo_name}/scan/{job_id}`` – poll job status + results.
* ``GET  /{owner}/{repo_name}/scan/latest/results`` – latest results map
  for graph highlighting.
"""

from __future__ import annotations

import logging
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
    """Create a scan job and start it in the background."""
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
        )
    )

    return ScanTriggerResponse(job_id=job.id, status=job.status)


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
    """Return full job status including per-package results."""
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
    return ScanJobResponse.model_validate(job)


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
