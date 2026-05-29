"""Background scan orchestration.

``run_scan_job`` discovers package work, persists one ``ScanTask`` row per
package, and enqueues each task to workers.  Per-package execution and state
transitions happen in ``_scan_single_package``.

Scan modes
----------
Graph-tab modes (support source-hash deduplication):
  full              static → enrichment (if suspicious/malicious) → dynamic (if still risky)
  static_enrichment static → enrichment (if suspicious/malicious)
  dynamic           dynamic analysis for all packages unconditionally

Individual-tab modes (always run fresh, no deduplication):
  static            pure static analysis only
  lightweight       CVE + reputation lookup only
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime, timezone
from uuid import UUID

import httpx
from sqlalchemy import and_, case, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.models.scan import RepoPackageSource, ScanJob, ScanResult, ScanTask
from typing import TYPE_CHECKING

from app.services import (
    dynamic_analysis_service,
    manifest_utils,
    reputation_service,
    scanner_service,
    vulnerability_service,
)

if TYPE_CHECKING:
    from app.api.schemas.risk import PackageRiskAssessment

logger = logging.getLogger(__name__)

_TASK_PENDING = "pending"
_TASK_DONE = "done"
_TASK_FAILED = "failed"
_TASK_TERMINAL_STATES = {_TASK_DONE, _TASK_FAILED}

# Modes that support source-hash deduplication (triggered from the Dependency Graph tab).
GRAPH_TAB_MODES = {"full", "static_enrichment", "dynamic"}

_scan_task_queue: asyncio.Queue[tuple[UUID, str]] | None = None
_scan_worker_tasks: list[asyncio.Task] = []
_scan_worker_lock = asyncio.Lock()


async def run_scan_job(
    job_id: UUID,
    owner: str,
    repo: str,
    ecosystem: str,
    access_token: str,
    selected_packages: list[str] | None = None,
    scan_mode: str = "full",
    force_rescan: bool = False,
) -> None:
    """Create DB-backed package tasks and enqueue them for worker execution.

    For graph-tab modes (full, static_enrichment, dynamic) and when
    ``force_rescan`` is False, the job is short-circuited to "completed" if a
    previous completed scan exists with an identical package source hash.
    """
    async with AsyncSessionLocal() as db:
        try:
            await _set_job_status(db, job_id, "running", started_at=datetime.now(timezone.utc), scan_mode=scan_mode)

            headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {access_token}",
                "X-GitHub-Api-Version": "2022-11-28",
            }

            _DEP_RESOLVE_TIMEOUT = 90
            try:
                async with asyncio.timeout(_DEP_RESOLVE_TIMEOUT):
                    async with httpx.AsyncClient(timeout=30.0) as client:
                        if ecosystem == "npm":
                            fetched = await manifest_utils.fetch_npm_manifest(client, owner, repo, headers)
                            tree = await manifest_utils.resolve_npm_dependency_tree(client, fetched.parsed)
                            workload = manifest_utils.build_npm_scan_workload(fetched.parsed, tree)
                            packages = workload.refs
                            total_dependency_nodes = workload.total_dependency_nodes
                            total_unique_packages = workload.unique_packages
                        elif ecosystem == "pypi":
                            fetched = await manifest_utils.fetch_pypi_manifest(client, owner, repo, headers)
                            tree = await manifest_utils.build_pypi_dependency_tree_deep(client, fetched.parsed)
                            packages = manifest_utils.flatten_dependencies(tree)
                            total_dependency_nodes = manifest_utils.count_dependency_nodes(tree)
                            total_unique_packages = len(packages)
                        else:
                            raise ValueError(f"Unsupported ecosystem: {ecosystem}")
            except asyncio.TimeoutError:
                logger.warning(
                    "Dependency resolution timed out after %ss for job %s",
                    _DEP_RESOLVE_TIMEOUT,
                    job_id,
                )
                await _set_job_status(
                    db,
                    job_id,
                    "failed",
                    error_message=f"Dependency resolution timed out after {_DEP_RESOLVE_TIMEOUT}s",
                    completed_at=datetime.now(timezone.utc),
                )
                return

            # Compute source hash for deduplication.
            source_hash = hashlib.sha256(fetched.raw_content.encode("utf-8")).hexdigest()

            # For graph-tab modes: check if a completed job with the same source hash exists.
            if scan_mode in GRAPH_TAB_MODES and not force_rescan:
                cached_job = await _find_completed_job_for_hash(db, owner, repo, ecosystem, source_hash, scan_mode)
                if cached_job is not None:
                    logger.info(
                        "Scan job %s: source unchanged (hash=%s), reusing results from job %s",
                        job_id,
                        source_hash,
                        cached_job.id,
                    )
                    await _set_package_source_hash(db, job_id, source_hash)
                    await _set_job_status(
                        db,
                        job_id,
                        "completed",
                        completed_at=datetime.now(timezone.utc),
                    )
                    return

            # Persist updated package source and record hash on this job.
            await _upsert_package_source(db, owner, repo, ecosystem, fetched, source_hash)
            await _set_package_source_hash(db, job_id, source_hash)
            await db.commit()

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
                    dependency_context=ref.resolution,
                )
                for ref in packages
            ]
            db.add_all(tasks)
            await db.flush()
            await db.commit()

            await asyncio.gather(*(enqueue_scan_task(t.id, scan_mode) for t in tasks))

        except asyncio.CancelledError:
            logger.warning("Scan job %s cancelled (server shutdown or task cancellation)", job_id)
            try:
                await _set_job_status(
                    db,
                    job_id,
                    "failed",
                    error_message="interrupted by server shutdown",
                    completed_at=datetime.now(timezone.utc),
                )
            except Exception:
                logger.exception("Could not mark cancelled job %s as failed", job_id)
            raise

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


# ── Package source helpers ─────────────────────────────────────────────

async def _get_stored_source(
    db: AsyncSession,
    owner: str,
    repo_name: str,
    ecosystem: str,
) -> RepoPackageSource | None:
    stmt = select(RepoPackageSource).where(
        RepoPackageSource.owner == owner,
        RepoPackageSource.repo_name == repo_name,
        RepoPackageSource.ecosystem == ecosystem,
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def _upsert_package_source(
    db: AsyncSession,
    owner: str,
    repo_name: str,
    ecosystem: str,
    fetched: manifest_utils.FetchedManifest,
    source_hash: str,
) -> None:
    existing = await _get_stored_source(db, owner, repo_name, ecosystem)
    now = datetime.now(timezone.utc)
    if existing is None:
        db.add(
            RepoPackageSource(
                owner=owner,
                repo_name=repo_name,
                ecosystem=ecosystem,
                source_type=fetched.source_type,
                source_content=fetched.raw_content,
                source_hash=source_hash,
                created_at=now,
                updated_at=now,
            )
        )
    else:
        existing.source_type = fetched.source_type
        existing.source_content = fetched.raw_content
        existing.source_hash = source_hash
        existing.updated_at = now


async def _find_completed_job_for_hash(
    db: AsyncSession,
    owner: str,
    repo_name: str,
    ecosystem: str,
    source_hash: str,
    scan_mode: str,
) -> ScanJob | None:
    stmt = (
        select(ScanJob)
        .where(
            ScanJob.owner == owner,
            ScanJob.repo_name == repo_name,
            ScanJob.ecosystem == ecosystem,
            ScanJob.scan_mode == scan_mode,
            ScanJob.status == "completed",
            ScanJob.package_source_hash == source_hash,
        )
        .order_by(ScanJob.completed_at.desc())
        .limit(1)
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def _set_package_source_hash(db: AsyncSession, job_id: UUID, source_hash: str) -> None:
    stmt = select(ScanJob).where(ScanJob.id == job_id)
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is not None:
        row.package_source_hash = source_hash
    await db.commit()


# ── Package filtering ──────────────────────────────────────────────────

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


# ── Worker pool ────────────────────────────────────────────────────────

async def enqueue_scan_task(task_id: UUID, scan_mode: str = "full") -> None:
    """Enqueue a single package task for asynchronous worker processing."""
    await _ensure_scan_workers_started()
    assert _scan_task_queue is not None
    await _scan_task_queue.put((task_id, scan_mode))


async def _ensure_scan_workers_started() -> None:
    global _scan_task_queue

    async with _scan_worker_lock:
        if _scan_task_queue is None:
            _scan_task_queue = asyncio.Queue()

        alive = [t for t in _scan_worker_tasks if not t.done()]
        _scan_worker_tasks.clear()
        _scan_worker_tasks.extend(alive)

        needed = max(1, settings.scanner_concurrency) - len(_scan_worker_tasks)
        for _ in range(needed):
            worker = asyncio.create_task(_scan_task_worker(len(_scan_worker_tasks)))
            _scan_worker_tasks.append(worker)


async def _worker_safety_net(task_id: UUID) -> None:
    """Last-resort cleanup when _scan_single_package double-faults.

    Uses two separate sessions so a failure in one step does not prevent
    the other.  The goal is to ensure processed_packages is always
    incremented so the parent job can transition to "completed".
    """
    job_id: UUID | None = None

    try:
        async with AsyncSessionLocal() as db:
            now = datetime.now(timezone.utc)
            # Mark task failed only if it is still in a non-terminal state.
            await db.execute(
                update(ScanTask)
                .where(
                    ScanTask.id == task_id,
                    ScanTask.status.notin_(list(_TASK_TERMINAL_STATES)),
                )
                .values(
                    status=_TASK_FAILED,
                    error_message="double-fault during error handling; see server logs",
                    updated_at=now,
                    completed_at=now,
                )
            )
            row = (
                await db.execute(select(ScanTask.job_id).where(ScanTask.id == task_id))
            ).scalar_one_or_none()
            job_id = row
            await db.commit()
    except Exception:
        logger.exception("Safety-net: could not mark task %s as failed", task_id)

    if job_id is not None:
        try:
            async with AsyncSessionLocal() as db:
                await _increment_processed_once(db, job_id, also_scanned=False)
                await db.commit()
        except Exception:
            logger.exception(
                "Safety-net: could not increment processed_packages for job %s", job_id
            )


async def _scan_task_worker(worker_index: int) -> None:
    assert _scan_task_queue is not None

    while True:
        try:
            task_id, scan_mode = await _scan_task_queue.get()
        except asyncio.CancelledError:
            raise

        try:
            await _scan_single_package(task_id, scan_mode)
        except asyncio.CancelledError:
            # Graceful shutdown — release the queue slot before propagating.
            _scan_task_queue.task_done()
            raise
        except Exception as exc:
            logger.exception(
                "Worker %s: unhandled exception for task %s — running safety-net update",
                worker_index,
                task_id,
            )
            # _scan_single_package has its own except block that calls _set_task_failed.
            # If we reached here that handler also raised (double-fault).  Force-mark the
            # task and increment the job counter so the job is not stuck as "running".
            await _worker_safety_net(task_id)
        finally:
            _scan_task_queue.task_done()


# ── Per-package pipeline ───────────────────────────────────────────────

async def _scan_single_package(task_id: UUID, scan_mode: str = "full") -> None:
    """Execute one package task with the pipeline defined by ``scan_mode``.

    Modes
    -----
    full              static → enrichment (CVE+rep, if suspicious/malicious)
                      → dynamic (if still suspicious/malicious)
    static_enrichment static → enrichment (CVE+rep, if suspicious/malicious)
    dynamic           dynamic analysis unconditionally
    static            pure static analysis; no CVE, reputation, or dynamic
    lightweight       CVE + reputation lookup unconditionally; no static or dynamic
    """
    task = await _load_task(task_id)
    if task is None:
        logger.warning("Task %s not found", task_id)
        return

    if task.status in _TASK_TERMINAL_STATES:
        return

    if task.status not in {_TASK_PENDING, _TASK_FAILED}:
        logger.info("Task %s already in-flight with status=%s; skipping", task_id, task.status)
        return

    if await _is_job_cancelled(task.job_id):
        logger.info("Task %s skipped: parent job %s is cancelled", task_id, task.job_id)
        await _set_task_status(task_id, _TASK_DONE)
        return

    # Derive execution flags from scan_mode.
    run_static = scan_mode in {"full", "static_enrichment", "static"}
    run_conditional_enrichment = scan_mode in {"full", "static_enrichment"}
    run_lightweight = scan_mode == "lightweight"
    force_dynamic = scan_mode == "dynamic"

    try:
        # ── Phase 1: Static analysis ──────────────────────────────────
        if run_static:
            verdict = await scanner_service.analyze_package_static(
                str(task.id),
                task.package_name,
                task.package_version,
                task.ecosystem,
            )
        else:
            verdict = scanner_service.ScanVerdict(malware_status="unknown", malware_score=None)

        dependency_context = getattr(task, "dependency_context", None)
        dep_ctx = dependency_context if isinstance(dependency_context, dict) else {}
        is_direct_dep = bool(dep_ctx.get("is_direct_dependency", False))

        # ── Phase 2: Determine CVE / reputation enrichment need ───────
        # Enrich when static result is suspicious or malicious (score > clean threshold).
        static_needs_enrichment = (
            verdict.malware_status in {"malicious", "suspicious"}
            or (
                verdict.malware_score is not None
                and verdict.malware_score > settings.risk_scoring_clean_max
            )
        )
        should_enrich_cve = run_lightweight or (run_conditional_enrichment and static_needs_enrichment)
        should_enrich_rep = run_lightweight or (run_conditional_enrichment and static_needs_enrichment)

        # ── Phase 3: CVE lookup (OSV / NVD) ──────────────────────────
        if should_enrich_cve:
            vulnerability_result = await vulnerability_service.lookup_package_vulnerabilities(
                task.ecosystem,
                task.package_name,
                task.package_version,
            )
        else:
            vulnerability_result = vulnerability_service.VulnerabilityLookupResult(
                signals=[], advisory_references=[], evidence=[], metadata={"skipped": True}
            )

        # ── Phase 4: Reputation lookup (npm registry / Libraries.io) ─
        if should_enrich_rep:
            has_cves = len(vulnerability_result.signals) > 0
            try:
                reputation_result = await reputation_service.lookup_package_reputation(
                    task.ecosystem,
                    task.package_name,
                    task.package_version,
                    is_direct_dependency=is_direct_dep,
                    force_librariesio=run_lightweight or is_direct_dep or has_cves,
                )
            except Exception:
                logger.warning(
                    "Reputation lookup failed for %s@%s, proceeding without",
                    task.package_name,
                    task.package_version,
                )
                reputation_result = reputation_service.ReputationLookupResult(
                    signals=[], evidence=[], metadata={"error": "lookup_failed"}
                )
        else:
            reputation_result = reputation_service.ReputationLookupResult(
                signals=[], evidence=[], metadata={"skipped": True}
            )

        # ── Phase 5: Dynamic analysis ─────────────────────────────────
        # Runs unconditionally for "dynamic" mode; for "full" mode runs only
        # if the package is still suspicious/malicious after enrichment.
        run_dynamic = force_dynamic or (
            scan_mode == "full"
            and _should_run_dynamic_analysis(verdict, reputation_result, vulnerability_result)
        )
        if run_dynamic:
            dynamic_result = await dynamic_analysis_service.analyze_package_dynamically(
                task.ecosystem,
                task.package_name,
                task.package_version,
            )
        else:
            skip_reason = "mode_excluded" if scan_mode not in {"full", "dynamic"} else "not_risky"
            dynamic_result = dynamic_analysis_service.build_skipped_dynamic_result(
                skip_reason,
                detail=f"scan_mode={scan_mode}, static_verdict={verdict.malware_status}",
            )

        # For "dynamic" mode: derive a verdict from dynamic findings (no static ran).
        if force_dynamic and not run_static:
            verdict = _derive_verdict_from_dynamic(dynamic_result)

        # ── Phase 6: Build risk assessment and persist ─────────────────
        if run_static and verdict.malware_status == "error":
            risk_assessment = scanner_service.build_package_risk_assessment(
                task.package_name,
                task.package_version,
                task.ecosystem,
                verdict,
                scan_mode=scan_mode,
                dependency_context=dependency_context,
                dynamic_signals=dynamic_result.signals,
                dynamic_evidence=dynamic_result.evidence,
                dynamic_metadata=dynamic_result.metadata,
                vulnerability_signals=vulnerability_result.signals,
                advisory_references=vulnerability_result.advisory_references,
                vulnerability_evidence=vulnerability_result.evidence,
                vulnerability_metadata=vulnerability_result.metadata,
                reputation_signals=reputation_result.signals,
                reputation_evidence=reputation_result.evidence,
                reputation_metadata=reputation_result.metadata,
            )
            await _set_task_failed(
                task_id,
                verdict.error_message or "Classifier returned error",
                risk_assessment=risk_assessment,
                also_scanned=True,
            )
            return

        risk_assessment = scanner_service.build_package_risk_assessment(
            task.package_name,
            task.package_version,
            task.ecosystem,
            verdict,
            scan_mode=scan_mode,
            dependency_context=dependency_context,
            dynamic_signals=dynamic_result.signals,
            dynamic_evidence=dynamic_result.evidence,
            dynamic_metadata=dynamic_result.metadata,
            vulnerability_signals=vulnerability_result.signals,
            advisory_references=vulnerability_result.advisory_references,
            vulnerability_evidence=vulnerability_result.evidence,
            vulnerability_metadata=vulnerability_result.metadata,
            reputation_signals=reputation_result.signals,
            reputation_evidence=reputation_result.evidence,
            reputation_metadata=reputation_result.metadata,
        )
        await _set_task_done(task_id, verdict, risk_assessment=risk_assessment, also_scanned=True)

    except Exception as exc:
        logger.exception("Task %s failed", task_id)
        await _set_task_failed(task_id, str(exc), also_scanned=True)


def _derive_verdict_from_dynamic(
    dynamic_result: dynamic_analysis_service.DynamicAnalysisResult,
) -> scanner_service.ScanVerdict:
    """Map dynamic analysis signals to a ScanVerdict for dynamic-mode scans."""
    metadata = dynamic_result.metadata
    status = str(metadata.get("status", "unknown"))

    if status in {"skipped", "partial"}:
        return scanner_service.ScanVerdict(malware_status="unknown", malware_score=None)

    behavior_score: float | None = None
    ioc_hit = False
    for signal in dynamic_result.signals:
        if signal.name == "dynamic_ioc_hit":
            ioc_hit = True
        elif signal.name == "dynamic_behavior_risk":
            try:
                behavior_score = float(signal.value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                pass

    if ioc_hit or (behavior_score is not None and behavior_score > settings.risk_scoring_suspicious_max):
        return scanner_service.ScanVerdict(
            malware_status="malicious",
            malware_score=behavior_score if behavior_score is not None else 1.0,
        )

    if behavior_score is not None:
        return scanner_service.ScanVerdict(malware_status="clean", malware_score=behavior_score)

    return scanner_service.ScanVerdict(malware_status="unknown", malware_score=None)


DYNAMIC_ANALYSIS_SCORE_THRESHOLD = 0.55


def _should_run_dynamic_analysis(
    verdict: scanner_service.ScanVerdict,
    reputation_result: reputation_service.ReputationLookupResult | None = None,
    vulnerability_result: vulnerability_service.VulnerabilityLookupResult | None = None,
) -> bool:
    if not settings.dynamic_analysis_enabled:
        return False

    has_cves = vulnerability_result is not None and len(vulnerability_result.signals) > 0

    flagged = (
        verdict.malware_status == "malicious"
        or (verdict.malware_score is not None and verdict.malware_score >= settings.dynamic_analysis_priority_threshold)
        or has_cves
    )
    if not flagged:
        return False

    # If the classifier itself produced the flag, reputation cannot override it.
    # The reputation bypass only applies when the flag came from CVEs alone
    # with no significant classifier score.
    score_is_strong = (
        verdict.malware_score is not None
        and verdict.malware_score >= settings.dynamic_analysis_priority_threshold
    )
    if score_is_strong:
        return True

    if reputation_result is not None:
        trust = reputation_result.metadata.get("trust_score", 0.0)
        if isinstance(trust, float) and trust >= 0.8 and not has_cves:
            logger.info(
                "Skipping dynamic analysis for high-trust package with no CVEs "
                "(trust_score=%.2f, malware_score=%.2f)",
                trust,
                verdict.malware_score or 0.0,
            )
            return False

    return True


# ── Result extraction helpers ──────────────────────────────────────────

def _extract_result_risk_fields(risk_assessment: object | None) -> dict[str, object]:
    payload = _serialize_risk_assessment(risk_assessment)
    if not isinstance(payload, dict):
        payload = {}

    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    scoring = metadata.get("scoring")
    if not isinstance(scoring, dict):
        scoring = {}

    dynamic_meta = metadata.get("dynamic")
    if not isinstance(dynamic_meta, dict):
        dynamic_meta = {}

    advisory_references = payload.get("advisory_references")
    if not isinstance(advisory_references, list):
        advisory_references = []

    risk_breakdown = scoring.get("breakdown")
    if not isinstance(risk_breakdown, dict):
        risk_breakdown = None

    return {
        "risk_breakdown": risk_breakdown,
        "advisory_references": [str(item) for item in advisory_references if isinstance(item, str)],
        "risk_allowlisted": bool(payload.get("allowlisted", False)),
        "risk_suppressed": bool(payload.get("suppressed", False)),
        "risk_suppression_reason": payload.get("suppression_reason"),
        "analysis_status": dynamic_meta.get("status") if isinstance(dynamic_meta.get("status"), str) else None,
        "analysis_coverage": dynamic_meta.get("coverage") if isinstance(dynamic_meta.get("coverage"), str) else None,
    }


# ── DB persistence helpers ─────────────────────────────────────────────

async def _is_job_cancelled(job_id: UUID) -> bool:
    async with AsyncSessionLocal() as db:
        stmt = select(ScanJob.status).where(ScanJob.id == job_id)
        result = await db.execute(stmt)
        status_value = result.scalar_one_or_none()
        return status_value == "cancelled"


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
        await db.commit()


async def _set_task_done(
    task_id: UUID,
    verdict: scanner_service.ScanVerdict,
    *,
    risk_assessment: object | None = None,
    also_scanned: bool = False,
) -> None:
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

        await _upsert_result_from_task(
            db,
            task,
            scanner_version=verdict.scanner_version,
            risk_assessment=risk_assessment,
        )
        await _increment_processed_once(db, task.job_id, also_scanned=also_scanned)
        await db.commit()


async def _set_task_failed(
    task_id: UUID,
    error_message: str,
    *,
    risk_assessment: object | None = None,
    also_scanned: bool = False,
) -> None:
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

        await _upsert_result_from_task(
            db,
            task,
            scanner_version=scanner_service.SCANNER_VERSION,
            risk_assessment=risk_assessment,
        )
        await _increment_processed_once(db, task.job_id, also_scanned=also_scanned)
        await db.commit()


def _derive_malware_status(task: ScanTask, risk_assessment: object | None) -> str:
    """Derive the effective malware_status for a scan result.

    When no classifier ran (lightweight / dynamic mode) the task verdict is
    "unknown".  In that case promote to the risk assessment's overall_status
    so the column reflects actual CVE/reputation/dynamic findings.
    """
    base = task.malware_status or "unknown"
    if base != "unknown":
        return base
    if risk_assessment is None:
        return base
    ra_status: object = (
        risk_assessment.overall_status  # type: ignore[union-attr]
        if hasattr(risk_assessment, "overall_status")
        else (risk_assessment.get("overall_status") if isinstance(risk_assessment, dict) else None)
    )
    if ra_status == "clean":
        return "clean"
    if ra_status in {"malicious", "suspicious"}:
        return "malicious"
    return base


async def _upsert_result_from_task(
    db: AsyncSession,
    task: ScanTask,
    *,
    scanner_version: str,
    risk_assessment: object | None = None,
) -> None:
    risk_fields = _extract_result_risk_fields(risk_assessment)
    effective_status = _derive_malware_status(task, risk_assessment)
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
                malware_status=effective_status,
                malware_score=task.malware_score,
                risk_assessment=_serialize_risk_assessment(risk_assessment),
                risk_breakdown=risk_fields["risk_breakdown"],
                advisory_references=risk_fields["advisory_references"],
                risk_allowlisted=bool(risk_fields["risk_allowlisted"]),
                risk_suppressed=bool(risk_fields["risk_suppressed"]),
                risk_suppression_reason=risk_fields["risk_suppression_reason"],
                analysis_status=risk_fields["analysis_status"],
                analysis_coverage=risk_fields["analysis_coverage"],
                scanner_version=scanner_version,
                error_message=task.error_message,
            )
        )
        return

    existing.malware_status = effective_status
    existing.malware_score = task.malware_score
    existing.risk_assessment = _serialize_risk_assessment(risk_assessment)
    existing.risk_breakdown = risk_fields["risk_breakdown"]
    existing.advisory_references = risk_fields["advisory_references"]
    existing.risk_allowlisted = bool(risk_fields["risk_allowlisted"])
    existing.risk_suppressed = bool(risk_fields["risk_suppressed"])
    existing.risk_suppression_reason = risk_fields["risk_suppression_reason"]
    existing.analysis_status = risk_fields["analysis_status"]
    existing.analysis_coverage = risk_fields["analysis_coverage"]
    existing.error_message = task.error_message
    existing.scanner_version = scanner_version
    existing.scan_timestamp = datetime.now(timezone.utc)


def _serialize_risk_assessment(risk_assessment: object | None) -> dict[str, object] | None:
    if risk_assessment is None:
        return None
    model_dump = getattr(risk_assessment, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json")
    if isinstance(risk_assessment, dict):
        return risk_assessment
    raise TypeError(f"Unsupported risk assessment payload: {type(risk_assessment)!r}")


async def _increment_scanned_once(db: AsyncSession, job_id: UUID) -> None:
    stmt = (
        update(ScanJob)
        .where(ScanJob.id == job_id)
        .values(scanned_packages=ScanJob.scanned_packages + 1)
    )
    await db.execute(stmt)


async def _increment_processed_once(db: AsyncSession, job_id: UUID, *, also_scanned: bool = False) -> None:
    now = datetime.now(timezone.utc)
    will_complete = and_(
        ScanJob.status == "running",
        ScanJob.total_packages > 0,
        (ScanJob.processed_packages + 1) >= ScanJob.total_packages,
    )
    new_values: dict = {
        "processed_packages": ScanJob.processed_packages + 1,
        "status": case((will_complete, "completed"), else_=ScanJob.status),
        "completed_at": case((will_complete, now), else_=ScanJob.completed_at),
    }
    if also_scanned:
        new_values["scanned_packages"] = ScanJob.scanned_packages + 1
    stmt = (
        update(ScanJob)
        .where(ScanJob.id == job_id)
        .values(**new_values)
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
    scan_mode: str | None = None,
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
    if scan_mode is not None:
        row.scan_mode = scan_mode
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


# ── Inline (no-DB) pre-PR scan helpers ────────────────────────────────────────

async def _analyze_package_inline(
    package_name: str,
    package_version: str,
    ecosystem: str,
) -> "PackageRiskAssessment":
    """Run the full scan pipeline for a single package without DB persistence.

    Mirrors scan_mode='full' logic: static → conditional CVE/reputation → conditional dynamic.
    Used for synchronous pre-PR security checks.
    """
    from uuid import uuid4

    task_id_str = str(uuid4())

    # Phase 1: Static analysis
    verdict = await scanner_service.analyze_package_static(
        task_id_str, package_name, package_version, ecosystem
    )

    # Phase 2: Enrichment gate (same threshold as _scan_single_package)
    static_needs_enrichment = (
        verdict.malware_status in {"malicious", "suspicious"}
        or (
            verdict.malware_score is not None
            and verdict.malware_score > settings.risk_scoring_clean_max
        )
    )

    # Phase 3: CVE lookup (conditional)
    if static_needs_enrichment:
        try:
            vulnerability_result = await vulnerability_service.lookup_package_vulnerabilities(
                ecosystem, package_name, package_version
            )
        except Exception:
            logger.warning("CVE lookup failed for %s@%s in prescan", package_name, package_version)
            vulnerability_result = vulnerability_service.VulnerabilityLookupResult(
                signals=[], advisory_references=[], evidence=[], metadata={"error": "lookup_failed"}
            )
    else:
        vulnerability_result = vulnerability_service.VulnerabilityLookupResult(
            signals=[], advisory_references=[], evidence=[], metadata={"skipped": True}
        )

    # Phase 4: Reputation lookup (conditional)
    if static_needs_enrichment:
        has_cves = len(vulnerability_result.signals) > 0
        try:
            reputation_result = await reputation_service.lookup_package_reputation(
                ecosystem, package_name, package_version,
                is_direct_dependency=True,
                force_librariesio=has_cves,
            )
        except Exception:
            logger.warning("Reputation lookup failed for %s@%s in prescan", package_name, package_version)
            reputation_result = reputation_service.ReputationLookupResult(
                signals=[], evidence=[], metadata={"error": "lookup_failed"}
            )
    else:
        reputation_result = reputation_service.ReputationLookupResult(
            signals=[], evidence=[], metadata={"skipped": True}
        )

    # Phase 5: Dynamic analysis (conditional)
    run_dynamic = _should_run_dynamic_analysis(verdict, reputation_result, vulnerability_result)
    if run_dynamic:
        try:
            dynamic_result = await dynamic_analysis_service.analyze_package_dynamically(
                ecosystem, package_name, package_version
            )
        except Exception:
            logger.warning("Dynamic analysis failed for %s@%s in prescan", package_name, package_version)
            dynamic_result = dynamic_analysis_service.build_skipped_dynamic_result(
                "error", detail="prescan dynamic analysis failed"
            )
    else:
        dynamic_result = dynamic_analysis_service.build_skipped_dynamic_result(
            "not_risky", detail="prescan: package not risky enough"
        )

    return scanner_service.build_package_risk_assessment(
        package_name, package_version, ecosystem, verdict,
        scan_mode="full",
        dynamic_signals=dynamic_result.signals,
        dynamic_evidence=dynamic_result.evidence,
        dynamic_metadata=dynamic_result.metadata,
        vulnerability_signals=vulnerability_result.signals,
        advisory_references=vulnerability_result.advisory_references,
        vulnerability_evidence=vulnerability_result.evidence,
        vulnerability_metadata=vulnerability_result.metadata,
        reputation_signals=reputation_result.signals,
        reputation_evidence=reputation_result.evidence,
        reputation_metadata=reputation_result.metadata,
    )


async def prescan_packages_full(
    packages: list[tuple[str, str]],
    ecosystem: str,
) -> list[tuple[str, str, "PackageRiskAssessment | BaseException"]]:
    """Run the full scan pipeline on a list of (name, version) pairs without DB persistence.

    Returns a list of (name, version, result_or_exception) tuples.
    Exceptions are captured and returned rather than raised (fail-open).
    """
    results = await asyncio.gather(
        *[_analyze_package_inline(name, version, ecosystem) for name, version in packages],
        return_exceptions=True,
    )
    return [
        (name, version, result)
        for (name, version), result in zip(packages, results)
    ]
