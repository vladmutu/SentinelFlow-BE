"""Task-based background scan orchestration.

`run_scan_job` is intentionally lightweight. It only discovers package work,
persists one `ScanTask` row per package, and enqueues each task to workers.
Per-package execution and state transitions happen in `_scan_single_package`.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID

import httpx
from sqlalchemy import and_, case, desc, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.models.scan import ScanJob, ScanResult, ScanTask
from app.services import (
    dynamic_analysis_service,
    manifest_utils,
    reputation_service,
    scanner_service,
    vulnerability_service,
)

logger = logging.getLogger(__name__)

_TASK_PENDING = "pending"
_TASK_DOWNLOADING = "downloading"
_TASK_ANALYZING = "analyzing"
_TASK_CLASSIFYING = "classifying"
_TASK_DONE = "done"
_TASK_FAILED = "failed"
_TASK_TERMINAL_STATES = {_TASK_DONE, _TASK_FAILED}

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
) -> None:
    """Create DB-backed package tasks and enqueue them for worker execution."""
    async with AsyncSessionLocal() as db:
        try:
            await _set_job_status(db, job_id, "running", started_at=datetime.now(timezone.utc), scan_mode=scan_mode)

            headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {access_token}",
                "X-GitHub-Api-Version": "2022-11-28",
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                if ecosystem == "npm":
                    manifest = await manifest_utils.fetch_npm_manifest(client, owner, repo, headers)
                    tree = await manifest_utils.resolve_npm_dependency_tree(client, manifest)
                    workload = manifest_utils.build_npm_scan_workload(manifest, tree)
                    packages = workload.refs
                    total_dependency_nodes = workload.total_dependency_nodes
                    total_unique_packages = workload.unique_packages
                elif ecosystem == "pypi":
                    manifest = await manifest_utils.fetch_pypi_manifest(client, owner, repo, headers)
                    tree = await manifest_utils.build_pypi_dependency_tree_deep(client, manifest)
                    packages = manifest_utils.flatten_dependencies(tree)
                    total_dependency_nodes = manifest_utils.count_dependency_nodes(tree)
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

            # Create ScanTask records first so we have task.id UUIDs to pass to the coordinator.
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

            for task in tasks:
                await enqueue_scan_task(task.id, scan_mode)

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

        # Remove dead (cancelled / errored) workers so new ones can be spawned.
        alive = [t for t in _scan_worker_tasks if not t.done()]
        _scan_worker_tasks.clear()
        _scan_worker_tasks.extend(alive)

        needed = max(1, settings.scanner_concurrency) - len(_scan_worker_tasks)
        for _ in range(needed):
            worker = asyncio.create_task(_scan_task_worker(len(_scan_worker_tasks)))
            _scan_worker_tasks.append(worker)


async def _scan_task_worker(worker_index: int) -> None:
    assert _scan_task_queue is not None

    while True:
        # Separate the get() from the processing so we never call task_done()
        # for an item we never actually received (e.g. CancelledError during get).
        try:
            task_id, scan_mode = await _scan_task_queue.get()
        except asyncio.CancelledError:
            raise  # Worker is being shut down — do not call task_done()

        try:
            await _scan_single_package(task_id, scan_mode)
        except Exception as exc:
            logger.exception("Worker %s crashed processing task %s: %s", worker_index, task_id, exc)
        finally:
            _scan_task_queue.task_done()


async def _scan_single_package(task_id: UUID, scan_mode: str = "full") -> None:
    """Execute one package task by id with explicit status transitions.

    scan_mode controls which analysis phases run:
      full            — static + vulnerability (OSV/NVD) + dynamic (if malicious) + reputation
      static_only     — static analysis only
      static_dynamic  — static + dynamic (if malicious); no vulnerability / reputation
      dynamic_only    — unconditional dynamic analysis; no static / vulnerability / reputation
    """
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

    if await _try_reuse_recent_scan_result(task_id, task):
        return

    # Phase flags derived from scan_mode
    # full        → static → CVE+libraries.io (if risky) → dynamic (if still risky)
    # static_only → static → CVE+libraries.io (if risky); no dynamic
    # lightweight → CVE for all packages; libraries.io only for direct deps or CVE-positive packages
    # dynamic_only → dynamic only; no static, no CVE, no libraries.io
    STATIC_RISK_ENRICHMENT_THRESHOLD = 0.5

    run_static    = scan_mode in {"full", "static_only"}
    force_dynamic = scan_mode == "dynamic_only"
    run_lightweight = scan_mode == "lightweight"

    try:
        await _set_task_status(task_id, _TASK_ANALYZING)

        # ── Step 1: Static analysis ──────────────────────────────────────────
        if run_static:
            verdict = await scanner_service.analyze_package_static(
                str(task.id),
                task.package_name,
                task.package_version,
                task.ecosystem,
            )
        else:
            verdict = scanner_service.ScanVerdict(malware_status="unknown", malware_score=None)

        await _set_task_status(task_id, _TASK_CLASSIFYING)
        dependency_context = getattr(task, "dependency_context", None)
        dep_ctx = dependency_context if isinstance(dependency_context, dict) else {}
        is_direct_dep = bool(dep_ctx.get("is_direct_dependency", False))

        # ── Step 2: Determine enrichment need ───────────────────────────────
        # For lightweight: always enrich all packages with CVE + libraries.io.
        # For full/static_only: only enrich if static analysis flags the package as risky.
        static_is_risky = (
            verdict.malware_status == "malicious"
            or (verdict.malware_score is not None and verdict.malware_score > STATIC_RISK_ENRICHMENT_THRESHOLD)
        )
        should_enrich = run_lightweight or (run_static and static_is_risky)

        # ── Step 3: CVE lookup (OSV/NVD) ─────────────────────────────────────
        if should_enrich:
            vulnerability_result = await vulnerability_service.lookup_package_vulnerabilities(
                task.ecosystem,
                task.package_name,
                task.package_version,
            )
        else:
            vulnerability_result = vulnerability_service.VulnerabilityLookupResult(
                signals=[], advisory_references=[], evidence=[], metadata={"skipped": True}
            )

        # ── Step 4: Libraries.io / reputation ────────────────────────────────
        # For lightweight mode: Libraries.io is only called when CVEs were found or the
        # package is a direct dependency. This keeps well within the 60 req/min limit
        # since most packages in a healthy project have no CVEs.
        if should_enrich:
            has_cves = len(vulnerability_result.signals) > 0
            try:
                reputation_result = await reputation_service.lookup_package_reputation(
                    task.ecosystem,
                    task.package_name,
                    task.package_version,
                    is_direct_dependency=is_direct_dep,
                    force_librariesio=is_direct_dep or has_cves,
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

        # ── Step 5: Dynamic analysis (full mode only, if still risky) ────────
        run_dynamic = force_dynamic or (
            scan_mode == "full" and _should_run_dynamic_analysis(verdict, reputation_result)
        )
        if run_dynamic:
            dynamic_result = await dynamic_analysis_service.analyze_package_dynamically(
                task.ecosystem,
                task.package_name,
                task.package_version,
            )
        else:
            skip_reason = (
                "mode_excluded" if scan_mode in {"static_only", "lightweight"}
                else "not_malicious"
            )
            dynamic_result = dynamic_analysis_service.build_skipped_dynamic_result(
                skip_reason,
                detail=f"scan_mode={scan_mode}, static_verdict={verdict.malware_status}",
            )

        # For dynamic_only: derive verdict from dynamic findings (no static verdict available)
        if force_dynamic and not run_static:
            verdict = _derive_verdict_from_dynamic(dynamic_result)

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
        await _set_task_done(task_id, verdict, risk_assessment=risk_assessment)

    except Exception as exc:
        logger.exception("Task %s failed", task_id)
        await _set_task_failed(task_id, str(exc))


def _derive_verdict_from_dynamic(
    dynamic_result: dynamic_analysis_service.DynamicAnalysisResult,
) -> scanner_service.ScanVerdict:
    """Map dynamic analysis signals to a ScanVerdict for dynamic_only scans."""
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


def _should_run_dynamic_analysis(
    verdict: scanner_service.ScanVerdict,
    reputation_result: reputation_service.ReputationLookupResult | None = None,
) -> bool:
    if not settings.dynamic_analysis_enabled:
        return False
    if verdict.malware_status != "malicious":
        return False
    # If libraries.io says the package is highly trusted, skip dynamic analysis —
    # a high static score for a well-known package is likely a false positive.
    if reputation_result is not None:
        trust = reputation_result.metadata.get("trust_score", 0.0)
        if isinstance(trust, float) and trust >= 0.8:
            logger.info(
                "Skipping dynamic analysis for high-trust package (trust_score=%.2f)", trust
            )
            return False
    return True



def _augment_cached_risk_assessment(risk_assessment: object | None, *, source_result_id: UUID) -> object | None:
    if not isinstance(risk_assessment, dict):
        return risk_assessment

    payload = dict(risk_assessment)
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    cache_meta = metadata.get("cache")
    if not isinstance(cache_meta, dict):
        cache_meta = {}
    cache_meta.update(
        {
            "reused": True,
            "source_result_id": str(source_result_id),
            "reused_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    metadata["cache"] = cache_meta
    payload["metadata"] = metadata

    evidence = payload.get("evidence")
    if isinstance(evidence, list):
        if "cache:scan_result_reuse" not in evidence:
            payload["evidence"] = [*evidence, "cache:scan_result_reuse"]
    else:
        payload["evidence"] = ["cache:scan_result_reuse"]

    return payload


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


async def _find_recent_cached_result(task: ScanTask) -> ScanResult | None:
    if not settings.scan_result_reuse_enabled:
        return None

    ttl_seconds = max(0, settings.scan_result_reuse_ttl_seconds)
    if ttl_seconds <= 0:
        return None

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=ttl_seconds)
    async with AsyncSessionLocal() as db:
        stmt = (
            select(ScanResult)
            .where(
                ScanResult.package_name == task.package_name,
                ScanResult.package_version == task.package_version,
                ScanResult.ecosystem == task.ecosystem,
                ScanResult.job_id != task.job_id,
                ScanResult.malware_status != "error",
                ScanResult.scan_timestamp >= cutoff,
            )
            .order_by(desc(ScanResult.scan_timestamp))
            .limit(1)
        )
        return (await db.execute(stmt)).scalar_one_or_none()


async def _try_reuse_recent_scan_result(task_id: UUID, task: ScanTask) -> bool:
    cached = await _find_recent_cached_result(task)
    if cached is None:
        return False

    await _set_task_status(task_id, _TASK_DOWNLOADING)
    cached_verdict = scanner_service.ScanVerdict(
        malware_status=cached.malware_status,
        malware_score=cached.malware_score,
        scanner_version=cached.scanner_version,
        error_message=cached.error_message,
    )
    await _set_task_done(
        task_id,
        cached_verdict,
        risk_assessment=_augment_cached_risk_assessment(
            cached.risk_assessment,
            source_result_id=cached.id,
        ),
    )
    return True


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
        if status in {_TASK_DOWNLOADING, _TASK_ANALYZING} and task.started_at is None:
            task.started_at = now
        await db.commit()


async def _set_task_done(
    task_id: UUID,
    verdict: scanner_service.ScanVerdict,
    *,
    risk_assessment: object | None = None,
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
        await _increment_processed_once(db, task.job_id)
        await db.commit()


async def _set_task_failed(
    task_id: UUID,
    error_message: str,
    *,
    risk_assessment: object | None = None,
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
        await _increment_processed_once(db, task.job_id)
        await db.commit()


def _derive_malware_status(task: ScanTask, risk_assessment: object | None) -> str:
    """Derive the effective malware_status for a scan result.

    When no classifier ran (lightweight / dynamic_only mode) the task verdict is
    "unknown". In that case we promote the status to the risk assessment's
    overall_status so that the column reflects actual CVE/reputation findings
    rather than always being "unknown".
    "suspicious" maps to "malicious" because the column only stores four values.
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
