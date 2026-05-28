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

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user
from app.api.schemas.scan import (
    ScanHistoryResponse,
    ScanHistorySummary,
    ScanJobResponse,
    ScanJobResultsResponse,
    ScanResultMapEntry,
    ScanResultResponse,
    ScanTriggerRequest,
    ScanTriggerResponse,
)
from app.core.config import settings
from app.db.session import get_db
from app.models.scan import RepoPackageSource, ScanJob, ScanResult
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


def _to_bool(value: object, default: bool = False) -> bool:
    return value if isinstance(value, bool) else default


def _to_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _job_scan_mode(job: ScanJob) -> str:
    sm = getattr(job, "scan_mode", None)
    return sm if isinstance(sm, str) and sm else "unknown"


def _extract_scan_detail_fields(risk_assessment: dict[str, object] | None) -> dict[str, object]:
    """Extract static feature snapshot and dynamic analysis findings for frontend detail views."""
    if not isinstance(risk_assessment, dict):
        return {"static_features": None, "dynamic_findings": None}
    metadata = risk_assessment.get("metadata") or {}
    return {
        "static_features": metadata.get("feature_snapshot"),
        "dynamic_findings": metadata.get("dynamic"),
    }


def _extract_reputation_metadata(risk_assessment: dict[str, object] | None) -> dict[str, object] | None:
    """Surface reputation metadata (downloads, stars, source_rank, etc.) from the risk assessment blob."""
    if not isinstance(risk_assessment, dict):
        return None
    metadata = risk_assessment.get("metadata") or {}
    rep = metadata.get("reputation") if isinstance(metadata, dict) else None
    if not isinstance(rep, dict):
        return None
    keys = (
        "monthly_downloads", "package_age_days", "has_repository",
        "maintainer_count", "libraries_io_rank", "dependents_count",
        "stars", "forks", "trust_score",
    )
    result = {k: rep[k] for k in keys if k in rep}
    return result or None


def _extract_vulnerability_details(risk_assessment: dict[str, object] | None) -> list[dict[str, object]]:
    """Surface per-advisory details (CVE ID, source, CVSS score, description) from vulnerability signals."""
    if not isinstance(risk_assessment, dict):
        return []
    details: list[dict[str, object]] = []
    for signal in risk_assessment.get("vulnerability_signals") or []:
        if not isinstance(signal, dict):
            continue
        meta = signal.get("metadata") or {}
        advisory_id = meta.get("advisory_id") if isinstance(meta, dict) else None
        if not advisory_id:
            continue
        details.append({
            "advisory_id": advisory_id,
            "source": signal.get("source", "unknown"),
            "value": signal.get("value"),
            "details": meta.get("details") or meta.get("description"),
            "aliases": meta.get("aliases") or [],
        })
    return details


def _extract_lookup_status(risk_assessment: dict[str, object] | None) -> dict[str, str] | None:
    """Derive per-source lookup outcome so the frontend can flag missing or failed lookups."""
    if not isinstance(risk_assessment, dict):
        return None
    metadata = risk_assessment.get("metadata") or {}
    status: dict[str, str] = {}

    vuln_meta = metadata.get("vulnerability") or {}
    if isinstance(vuln_meta, dict):
        if vuln_meta.get("skipped"):
            status["cve"] = "skipped"
        elif vuln_meta.get("osv_error") or vuln_meta.get("nvd_error"):
            status["cve"] = "error"
        else:
            status["cve"] = "ok"

    rep_meta = metadata.get("reputation") or {}
    if isinstance(rep_meta, dict):
        if rep_meta.get("skipped"):
            status["librariesio"] = "skipped"
        elif rep_meta.get("libraries_io_not_found"):
            status["librariesio"] = "not_found"
        elif rep_meta.get("libraries_io_error") or rep_meta.get("error") == "lookup_failed":
            status["librariesio"] = "error"
        elif rep_meta.get("libraries_io_rank") is not None or rep_meta.get("trust_score") is not None:
            status["librariesio"] = "found"

    return status or None


def _extract_risk_breakdown(risk_assessment: dict[str, object] | None) -> dict[str, object] | None:
    if not isinstance(risk_assessment, dict):
        return None
    metadata = risk_assessment.get("metadata")
    if not isinstance(metadata, dict):
        return None
    scoring = metadata.get("scoring")
    if not isinstance(scoring, dict):
        return None
    breakdown = scoring.get("breakdown")
    return breakdown if isinstance(breakdown, dict) else None


def _extract_risk_visibility_fields(item: ScanResult) -> dict[str, object]:
    risk_assessment = item.risk_assessment if isinstance(item.risk_assessment, dict) else None
    metadata = risk_assessment.get("metadata") if isinstance(risk_assessment, dict) else None
    dynamic_meta = metadata.get("dynamic") if isinstance(metadata, dict) else None

    risk_breakdown = item.risk_breakdown
    if not isinstance(risk_breakdown, dict):
        risk_breakdown = _extract_risk_breakdown(risk_assessment)

    item_suppression_reason = item.risk_suppression_reason if isinstance(item.risk_suppression_reason, str) else None
    item_analysis_status = item.analysis_status if isinstance(item.analysis_status, str) else None
    item_analysis_coverage = item.analysis_coverage if isinstance(item.analysis_coverage, str) else None

    return {
        "risk_breakdown": risk_breakdown,
        "risk_overall_status": risk_assessment.get("overall_status") if isinstance(risk_assessment, dict) else None,
        "risk_overall_score": risk_assessment.get("overall_score") if isinstance(risk_assessment, dict) else None,
        "risk_allowlisted": _to_bool(item.risk_allowlisted, bool(risk_assessment.get("allowlisted", False)) if isinstance(risk_assessment, dict) else False),
        "risk_suppressed": _to_bool(item.risk_suppressed, bool(risk_assessment.get("suppressed", False)) if isinstance(risk_assessment, dict) else False),
        "risk_suppression_reason": item_suppression_reason or (risk_assessment.get("suppression_reason") if isinstance(risk_assessment, dict) else None),
        "analysis_status": item_analysis_status or (dynamic_meta.get("status") if isinstance(dynamic_meta, dict) else None),
        "analysis_coverage": item_analysis_coverage or (dynamic_meta.get("coverage") if isinstance(dynamic_meta, dict) else None),
        "advisory_references": item.advisory_references if isinstance(item.advisory_references, list) else _to_string_list(risk_assessment.get("advisory_references") if isinstance(risk_assessment, dict) else None),
    }


def _derive_analyzed_by(item: ScanResult) -> list[str]:
    """Derive which analysis microservices ran for this package result."""
    ra = item.risk_assessment if isinstance(item.risk_assessment, dict) else {}
    analysis_mode = ra.get("analysis_mode", "")

    if analysis_mode == "dynamic_only":
        return ["dynamic"]

    if analysis_mode == "lightweight":
        metadata = ra.get("metadata") or {}
        rep_meta = metadata.get("reputation") if isinstance(metadata, dict) else None
        vuln_meta = metadata.get("vulnerability") if isinstance(metadata, dict) else None
        analyzed: list[str] = []
        if isinstance(vuln_meta, dict) and not vuln_meta.get("skipped"):
            analyzed.append("cve")
        if isinstance(rep_meta, dict) and not rep_meta.get("skipped"):
            analyzed.append("librariesio")
        return analyzed or ["cve"]

    analyzed_by = ["static"]
    analysis_status = item.analysis_status if isinstance(item.analysis_status, str) else None
    if analysis_status and analysis_status not in {"skipped", "not_malicious", "mode_excluded"}:
        analyzed_by.append("dynamic")
    return analyzed_by


def _to_scan_result_response(item: ScanResult) -> ScanResultResponse:
    ra = item.risk_assessment if isinstance(item.risk_assessment, dict) else None
    payload = {
        "id": item.id,
        "package_name": item.package_name,
        "package_version": item.package_version,
        "ecosystem": item.ecosystem,
        "malware_status": item.malware_status,
        "malware_score": item.malware_score,
        "scanner_version": item.scanner_version,
        "error_message": item.error_message,
        "scan_timestamp": item.scan_timestamp,
        "risk_assessment": item.risk_assessment,
        "analyzed_by": _derive_analyzed_by(item),
        "reputation_metadata": _extract_reputation_metadata(ra),
        "vulnerability_details": _extract_vulnerability_details(ra),
        "lookup_status": _extract_lookup_status(ra),
    }
    payload.update(_extract_risk_visibility_fields(item))
    payload.update(_extract_scan_detail_fields(ra))
    return ScanResultResponse.model_validate(payload)


def _to_scan_result_map_entry(item: ScanResult) -> ScanResultMapEntry:
    ra = item.risk_assessment if isinstance(item.risk_assessment, dict) else None
    payload = {
        "malware_status": item.malware_status,
        "malware_score": item.malware_score,
        "scan_timestamp": item.scan_timestamp,
        "scanner_version": item.scanner_version,
        "risk_assessment": ra,
        "analyzed_by": _derive_analyzed_by(item),
        "reputation_metadata": _extract_reputation_metadata(ra),
        "vulnerability_details": _extract_vulnerability_details(ra),
        "lookup_status": _extract_lookup_status(ra),
    }
    payload.update(_extract_risk_visibility_fields(item))
    payload.update(_extract_scan_detail_fields(ra))
    return ScanResultMapEntry.model_validate(payload)


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
    existing_stmt = select(ScanJob).where(
        ScanJob.owner == owner,
        ScanJob.repo_name == repo_name,
        ScanJob.status.in_(["pending", "running"]),
    )
    existing_job = (await db.execute(existing_stmt)).scalar_one_or_none()
    if existing_job is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"A scan is already in progress for this repository (job_id: {existing_job.id}). "
                "Cancel it or wait for it to finish."
            ),
        )

    # For graph-tab modes: if we already have a stored source hash and a completed
    # job with that hash, return it immediately without creating a new job.
    _GRAPH_TAB_MODES = {"full", "static_enrichment", "dynamic"}
    if body.scan_mode in _GRAPH_TAB_MODES and not body.force_rescan:
        stored_source_stmt = select(RepoPackageSource).where(
            RepoPackageSource.owner == owner,
            RepoPackageSource.repo_name == repo_name,
            RepoPackageSource.ecosystem == body.ecosystem,
        )
        stored_source = (await db.execute(stored_source_stmt)).scalar_one_or_none()
        if stored_source is not None:
            cached_job_stmt = (
                select(ScanJob)
                .where(
                    ScanJob.owner == owner,
                    ScanJob.repo_name == repo_name,
                    ScanJob.ecosystem == body.ecosystem,
                    ScanJob.scan_mode == body.scan_mode,
                    ScanJob.status == "completed",
                    ScanJob.package_source_hash == stored_source.source_hash,
                )
                .order_by(ScanJob.completed_at.desc())
                .limit(1)
            )
            cached_job = (await db.execute(cached_job_stmt)).scalar_one_or_none()
            if cached_job is not None:
                logger.info(
                    "Returning cached scan results for %s/%s (job_id=%s, hash=%s)",
                    owner,
                    repo_name,
                    cached_job.id,
                    stored_source.source_hash,
                )
                return ScanTriggerResponse(
                    job_id=cached_job.id,
                    status=cached_job.status,
                    from_cache=True,
                )

    job = ScanJob(
        owner=owner,
        repo_name=repo_name,
        ecosystem=body.ecosystem,
        scan_mode=body.scan_mode,
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    logger.info(
        "Scan job created: owner=%s repo=%s ecosystem=%s mode=%s job_id=%s",
        owner,
        repo_name,
        body.ecosystem,
        body.scan_mode,
        job.id,
    )

    # Fire-and-forget background task.
    job_runner.submit(
        run_scan_job(
            job_id=job.id,
            owner=owner,
            repo=repo_name,
            ecosystem=body.ecosystem,
            access_token=current_user.access_token,
            selected_packages=body.selected_packages,
            scan_mode=body.scan_mode,
            force_rescan=body.force_rescan,
        )
    )

    logger.info(
        "Scan trigger → FE: job_id=%s status=%s from_cache=False",
        job.id,
        job.status,
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

    if settings.static_analysis_remote_url:
        cancel_url = f"{settings.static_analysis_remote_url.rstrip('/')}/jobs/{job_id}"
        logger.info("Static analysis cancel → DELETE %s", cancel_url)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.delete(cancel_url)
            logger.debug("Static analysis cancel response: HTTP %s", resp.status_code)
        except Exception as exc:
            logger.warning("Failed to cancel static analysis job %s: %s", job_id, exc)

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
    scanned_raw = _to_int(job.scanned_packages, 0)
    scanned = min(scanned_raw, total_unique) if total_unique > 0 else scanned_raw
    processed = _to_int(job.processed_packages, 0)

    progress_percent = 0.0
    if total_unique > 0:
        progress_percent = min(100.0, max(0.0, (processed / total_unique) * 100.0))

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
            scan_mode=_job_scan_mode(job),
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
            results=[_to_scan_result_response(item) for item in job.results],
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
        f"{r.package_name}@{r.package_version}": _to_scan_result_map_entry(r)
        for r in rows
    }


# ── Scan history ──────────────────────────────────────────────────────

@router.get(
    "/{owner}/{repo_name}/scan/history",
    response_model=ScanHistoryResponse,
)
async def get_scan_history(
    owner: str,
    repo_name: str,
    page: int = Query(default=1, ge=1, description="Page number (1-based)"),
    per_page: int = Query(default=20, ge=1, le=100, description="Results per page"),
    scan_mode: str | None = Query(
        default=None,
        pattern=r"^(full|static_enrichment|dynamic|static|lightweight)$",
        description="Optional scan mode filter",
    ),
    status: str | None = Query(
        default=None,
        pattern=r"^(pending|running|completed|failed|cancelled)$",
        description="Optional scan status filter",
    ),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanHistoryResponse:
    """Return a paginated list of all scan jobs for a repository, newest first.

    Each entry shows the scan mode, status, package counts and timestamps.
    Use ``GET /{owner}/{repo_name}/scan/{job_id}`` to fetch full results for
    any entry, including per-package static features and dynamic findings.
    """
    offset = (page - 1) * per_page
    base_filter = and_(ScanJob.owner == owner, ScanJob.repo_name == repo_name)
    if scan_mode:
        base_filter = and_(base_filter, ScanJob.scan_mode == scan_mode)
    if status:
        base_filter = and_(base_filter, ScanJob.status == status)

    total = (
        await db.execute(select(func.count()).select_from(ScanJob).where(base_filter))
    ).scalar_one()

    rows = (
        await db.execute(
            select(ScanJob)
            .where(base_filter)
            .order_by(ScanJob.created_at.desc())
            .offset(offset)
            .limit(per_page)
        )
    ).scalars().all()

    # Build per-job aggregated stats with two queries covering all jobs on the page.
    job_ids = [j.id for j in rows]
    job_status_stats: dict[object, dict[str, int]] = {}
    job_cve_stats: dict[object, tuple[int, int]] = {}  # job_id → (packages_with_cves, total_cve_count)

    if job_ids:
        # Status distribution: one GROUP BY query for the whole page.
        status_rows = (
            await db.execute(
                select(ScanResult.job_id, ScanResult.malware_status, func.count().label("cnt"))
                .where(ScanResult.job_id.in_(job_ids))
                .group_by(ScanResult.job_id, ScanResult.malware_status)
            )
        ).all()
        for row in status_rows:
            stats = job_status_stats.setdefault(row.job_id, {})
            stats[row.malware_status or "unknown"] = int(row.cnt)

        # CVE counts: load (job_id, advisory_references) and aggregate in Python.
        cve_rows = (
            await db.execute(
                select(ScanResult.job_id, ScanResult.advisory_references)
                .where(ScanResult.job_id.in_(job_ids))
            )
        ).all()
        for row in cve_rows:
            refs = row.advisory_references if isinstance(row.advisory_references, list) else []
            if refs:
                pkg_count, total_count = job_cve_stats.get(row.job_id, (0, 0))
                job_cve_stats[row.job_id] = (pkg_count + 1, total_count + len(refs))

    def _to_history_summary(j: ScanJob) -> ScanHistorySummary:
        stats = job_status_stats.get(j.id, {})
        pkgs_with_cves, total_cves = job_cve_stats.get(j.id, (0, 0))
        return ScanHistorySummary(
            id=j.id,
            repo_name=j.repo_name if isinstance(j.repo_name, str) else "",
            ecosystem=j.ecosystem if isinstance(j.ecosystem, str) else "",
            scan_mode=_job_scan_mode(j),
            status=j.status if isinstance(j.status, str) else "",
            total_packages=_to_int(j.total_packages),
            processed_packages=_to_int(getattr(j, "processed_packages", None)),
            scanned_packages=_to_int(j.scanned_packages),
            total_dependency_nodes=_to_int(getattr(j, "total_dependency_nodes", None)),
            total_unique_packages=_to_int(getattr(j, "total_unique_packages", None)),
            error_message=j.error_message if isinstance(j.error_message, str) else None,
            created_at=j.created_at,
            started_at=j.started_at if isinstance(j.started_at, datetime) else None,
            completed_at=j.completed_at if isinstance(j.completed_at, datetime) else None,
            malicious_count=stats.get("malicious", 0),
            clean_count=stats.get("clean", 0),
            error_count=stats.get("error", 0),
            unknown_count=stats.get("unknown", 0),
            packages_with_cves=pkgs_with_cves,
            total_cve_count=total_cves,
        )

    return ScanHistoryResponse(
        jobs=[_to_history_summary(j) for j in rows],
        total=total,
        page=page,
        per_page=per_page,
    )


# ── Job results (searchable, paginated) ───────────────────────────────

@router.get(
    "/{owner}/{repo_name}/scan/{job_id}/results",
    response_model=ScanJobResultsResponse,
)
async def get_scan_job_results(
    owner: str,
    repo_name: str,
    job_id: UUID,
    q: str | None = Query(default=None, max_length=214, description="Filter by package name (case-insensitive substring)"),
    malware_status: str | None = Query(default=None, pattern=r"^(clean|malicious|error|unknown)$"),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanJobResultsResponse:
    """Return paginated, searchable per-package results for a scan job."""
    del current_user

    job_stmt = select(ScanJob).where(
        ScanJob.id == job_id,
        ScanJob.owner == owner,
        ScanJob.repo_name == repo_name,
    )
    job = (await db.execute(job_stmt)).scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    base_filter = [ScanResult.job_id == job_id]
    if q:
        base_filter.append(ScanResult.package_name.ilike(f"%{q}%"))
    if malware_status:
        base_filter.append(ScanResult.malware_status == malware_status)

    total = (
        await db.execute(select(func.count()).select_from(ScanResult).where(and_(*base_filter)))
    ).scalar_one()

    offset = (page - 1) * per_page
    rows = (
        await db.execute(
            select(ScanResult)
            .where(and_(*base_filter))
            .order_by(ScanResult.scan_timestamp.desc())
            .offset(offset)
            .limit(per_page)
        )
    ).scalars().all()

    logger.debug(
        "GET scan job results → FE: job_id=%s page=%d per_page=%d total=%d results=%d",
        job_id,
        page,
        per_page,
        total,
        len(rows),
    )
    return ScanJobResultsResponse(
        job_id=job_id,
        total=total,
        page=page,
        per_page=per_page,
        results=[_to_scan_result_response(r) for r in rows],
    )


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
    scanned_raw = _to_int(job.scanned_packages, 0)
    scanned = min(scanned_raw, total_unique) if total_unique > 0 else scanned_raw
    processed = _to_int(job.processed_packages, 0)

    progress_percent = 0.0
    if total_unique > 0:
        progress_percent = min(100.0, max(0.0, (processed / total_unique) * 100.0))

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
        scan_mode=getattr(job, "scan_mode", "full") or "full",
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
        results=[_to_scan_result_response(item) for item in job.results],
    )
