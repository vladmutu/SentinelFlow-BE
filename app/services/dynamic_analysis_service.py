# CHANGED: Replace blocking POST /analyze with async submit+poll loop; 5-second poll interval; 429 handling
"""Dynamic-analysis microservice integration.

Delegates all dynamic analysis to a remote microservice.
Never executes untrusted package code on the API host.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
import time
from urllib.parse import urlparse

import httpx

from app.api.schemas.risk import RiskSignal
from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DynamicAnalysisResult:
    signals: list[RiskSignal]
    evidence: list[str]
    metadata: dict[str, object]


_dynamic_semaphore: asyncio.Semaphore | None = None


async def _get_dynamic_semaphore() -> asyncio.Semaphore:
    global _dynamic_semaphore
    if _dynamic_semaphore is None:
        _dynamic_semaphore = asyncio.Semaphore(max(1, settings.dynamic_analysis_concurrency))
    return _dynamic_semaphore


def build_skipped_dynamic_result(reason: str, *, detail: str | None = None) -> DynamicAnalysisResult:
    """Build an explicit dynamic-analysis skip result for policy/orchestration decisions."""
    return _make_skipped_result(reason, detail=detail)


def _make_skipped_result(reason: str, *, detail: str | None = None) -> DynamicAnalysisResult:
    metadata = {
        "coverage": "none",
        "status": "skipped",
        "reason": reason,
        "detail": detail,
        "executed_on_api_host": False,
        "sandbox_boundary": "remote_only",
        "sandbox_isolation_enforced": True,
    }
    return DynamicAnalysisResult(
        signals=[
            RiskSignal(
                source="dynamic-analysis",
                name="dynamic_analysis_skipped",
                value=True,
                weight=0.0,
                confidence=1.0,
                rationale="Dynamic analysis was not executed; risk score should reflect incomplete coverage",
                metadata=metadata,
            )
        ],
        evidence=[f"dynamic:skipped:{reason}"],
        metadata=metadata,
    )


def _make_partial_result(reason: str, *, detail: str | None = None) -> DynamicAnalysisResult:
    metadata = {
        "coverage": "partial",
        "status": "partial",
        "reason": reason,
        "detail": detail,
        "executed_on_api_host": False,
        "sandbox_boundary": "remote_only",
        "sandbox_isolation_enforced": True,
    }
    return DynamicAnalysisResult(
        signals=[
            RiskSignal(
                source="dynamic-analysis",
                name="dynamic_analysis_partial",
                value=True,
                weight=0.0,
                confidence=1.0,
                rationale="Dynamic analysis started but did not complete full behavioral coverage",
                metadata=metadata,
            )
        ],
        evidence=[f"dynamic:partial:{reason}"],
        metadata=metadata,
    )


def _normalize_remote_response(payload: dict[str, object]) -> DynamicAnalysisResult:
    status = str(payload.get("status") or "unknown")
    coverage = str(payload.get("coverage") or "none")
    risk_score_raw = payload.get("risk_score")
    try:
        risk_score = float(risk_score_raw) if risk_score_raw is not None else None
    except (TypeError, ValueError):
        risk_score = None

    ioc_detail_raw = payload.get("ioc_detail")
    ioc_hit = bool(isinstance(ioc_detail_raw, dict) and ioc_detail_raw.get("dynamic_hit"))

    # Capture all rich data from the microservice so it gets persisted in
    # risk_assessment.metadata.dynamic via the orchestrator's dynamic_metadata.
    metadata: dict[str, object] = {
        "status": status,
        "coverage": coverage,
        "risk_score": risk_score,
        "ioc_hit": ioc_hit,
        "sandbox_provider": payload.get("provider"),
        "sandbox_job_id": payload.get("job_id"),
        "sandbox_timed_out": bool(payload.get("timed_out", False)),
        "vm_evasion_observed": bool(payload.get("vm_evasion_observed", False)),
        "executed_on_api_host": False,
        "sandbox_boundary": "remote_only",
        "sandbox_isolation_enforced": True,
        "syscall_trace": payload.get("syscall_trace"),
        "network_activity": payload.get("network_activity"),
        "filesystem_changes": payload.get("filesystem_changes"),
        "ioc_detail": payload.get("ioc_detail"),
    }

    signals: list[RiskSignal] = []
    evidence: list[str] = []

    if coverage != "full":
        signals.append(
            RiskSignal(
                source="dynamic-analysis",
                name="dynamic_coverage_incomplete",
                value=True,
                weight=0.0,
                confidence=1.0,
                rationale="Sandbox reported incomplete runtime coverage",
                metadata=metadata,
            )
        )
        evidence.append("dynamic:coverage_incomplete")

    if risk_score is not None:
        signals.append(
            RiskSignal(
                source="dynamic-analysis",
                name="dynamic_behavior_risk",
                value=max(0.0, min(risk_score, 1.0)),
                weight=1.0,
                confidence=0.7,
                rationale="Behavioral risk score returned by external sandbox",
                metadata=metadata,
            )
        )
        evidence.append("dynamic:behavior_risk")

    if bool(payload.get("vm_evasion_observed", False)):
        signals.append(
            RiskSignal(
                source="dynamic-analysis",
                name="vm_evasion_observed",
                value=True,
                weight=0.0,
                confidence=0.6,
                rationale="Sandbox telemetry reported VM-evasion behavior (telemetry-only)",
                metadata=metadata,
            )
        )
        evidence.append("dynamic:vm_evasion_observed")

    ioc_detail = payload.get("ioc_detail")
    if isinstance(ioc_detail, dict) and ioc_detail.get("dynamic_hit"):
        signals.append(
            RiskSignal(
                source="dynamic-analysis",
                name="dynamic_ioc_hit",
                value=True,
                weight=0.8,
                confidence=0.85,
                rationale=f"IOC scan verdict: {ioc_detail.get('verdict', 'unknown')}",
                metadata=metadata,
            )
        )
        evidence.append("dynamic:ioc_hit")

    return DynamicAnalysisResult(signals=signals, evidence=evidence, metadata=metadata)


async def analyze_package_dynamically(
    ecosystem: str,
    package_name: str,
    package_version: str,
) -> DynamicAnalysisResult:
    """Delegate dynamic analysis to the remote microservice.

    Submits the job via POST /analyze (returns 202 immediately), then polls
    GET /analyze/{job_id}/status every 5 seconds until the job completes,
    fails, or the timeout expires.

    Never executes the package locally on the API host.
    """
    if not settings.dynamic_analysis_enabled:
        logger.info(
            "Dynamic analysis disabled (DYNAMIC_ANALYSIS_ENABLED=false); skipping %s@%s",
            package_name, package_version,
        )
        return _make_skipped_result("disabled")

    base_url = settings.dynamic_analysis_remote_url.strip()
    if not base_url:
        logger.warning(
            "Dynamic analysis remote URL is empty (DYNAMIC_ANALYSIS_REMOTE_URL not set); skipping %s@%s",
            package_name, package_version,
        )
        return _make_skipped_result("missing_remote_url")

    parsed = urlparse(base_url)
    host = (parsed.hostname or "").lower()
    is_localhost = host in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not is_localhost:
        logger.warning(
            "Dynamic analysis remote URL is not HTTPS and not localhost (scheme=%s, host=%s); skipping %s@%s",
            parsed.scheme or "none",
            host,
            package_name,
            package_version,
        )
        return _make_skipped_result(
            "insecure_remote_url",
            detail=f"scheme={parsed.scheme or 'none'}",
        )

    analyze_url = f"{base_url.rstrip('/')}/analyze"

    request_payload: dict[str, object] = {
        "ecosystem": ecosystem,
        "package_name": package_name,
        "package_version": package_version,
        "sandbox_type": settings.dynamic_analysis_sandbox_type,
    }

    headers: dict[str, str] = {}
    if settings.dynamic_analysis_api_key:
        headers["Authorization"] = f"Bearer {settings.dynamic_analysis_api_key}"

    # Short timeouts are correct now: submit returns in <100 ms, polls return in <50 ms.
    timeout = httpx.Timeout(connect=10.0, read=10.0, write=30.0, pool=5.0)

    _MAX_CONNECT_RETRIES = 2
    _CONNECT_RETRY_DELAY = 5.0

    semaphore = await _get_dynamic_semaphore()

    # ── Step 1: Submit ────────────────────────────────────────────────

    logger.info(
        "Dynamic analysis → POST %s  sending: %s",
        analyze_url,
        request_payload,
    )

    submit_resp: httpx.Response | None = None

    for attempt in range(_MAX_CONNECT_RETRIES + 1):
        try:
            async with semaphore:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    submit_resp = await client.post(
                        analyze_url,
                        json=request_payload,
                        headers=headers or None,
                    )
            break  # success — exit retry loop

        except httpx.ConnectError as exc:
            if attempt < _MAX_CONNECT_RETRIES:
                logger.warning(
                    "Dynamic analysis: ConnectError for %s@%s (attempt %d/%d), retrying in %.0fs — %s",
                    package_name,
                    package_version,
                    attempt + 1,
                    _MAX_CONNECT_RETRIES + 1,
                    _CONNECT_RETRY_DELAY,
                    exc,
                )
                await asyncio.sleep(_CONNECT_RETRY_DELAY)
                continue
            logger.error(
                "Dynamic analysis: cannot connect to %s for %s@%s after %d attempts "
                "— is the MicroVMService running? (%s)",
                analyze_url,
                package_name,
                package_version,
                _MAX_CONNECT_RETRIES + 1,
                exc,
            )
            return _make_partial_result("remote_exception", detail="ConnectError")

        except Exception as exc:
            logger.warning(
                "Dynamic analysis microservice error for %s@%s: %s — %s",
                package_name,
                package_version,
                exc.__class__.__name__,
                exc,
            )
            return _make_partial_result("remote_exception", detail=exc.__class__.__name__)

    if submit_resp is None:
        return _make_partial_result("remote_exception", detail="ConnectError")

    # Handle submit response status codes
    if submit_resp.status_code == 429:
        logger.warning(
            "Dynamic analysis queue full for %s@%s (HTTP 429)",
            package_name, package_version,
        )
        return _make_skipped_result("queue_full")

    if submit_resp.status_code == 503:
        try:
            body = submit_resp.json()
        except Exception:
            body = submit_resp.text
        logger.warning(
            "Dynamic analysis service not ready for %s@%s (503): %s",
            package_name, package_version, body,
        )
        return _make_skipped_result("service_not_ready")

    if submit_resp.is_error:
        try:
            body = submit_resp.json()
        except Exception:
            body = submit_resp.text
        logger.error(
            "Dynamic analysis HTTP error for %s@%s: status=%s  body=%s",
            package_name, package_version, submit_resp.status_code, body,
        )
        return _make_partial_result("remote_http_error", detail=f"status_code={submit_resp.status_code}")

    try:
        submit_body = submit_resp.json()
    except Exception:
        logger.error(
            "Dynamic analysis submit returned non-JSON response for %s@%s",
            package_name, package_version,
        )
        return _make_partial_result("invalid_remote_payload")

    if not isinstance(submit_body, dict):
        logger.error(
            "Dynamic analysis submit returned non-dict payload for %s@%s: %r",
            package_name, package_version, submit_body,
        )
        return _make_partial_result("invalid_remote_payload")

    job_id = submit_body.get("job_id")
    if not isinstance(job_id, str) or not job_id:
        logger.error(
            "Dynamic analysis submit response missing job_id for %s@%s: %r",
            package_name, package_version, submit_body,
        )
        return _make_partial_result("invalid_remote_payload")

    logger.info(
        "Dynamic analysis job submitted for %s@%s: job_id=%s",
        package_name, package_version, job_id,
    )

    # ── Step 2: Poll ──────────────────────────────────────────────────

    poll_url = f"{base_url.rstrip('/')}/analyze/{job_id}/status"
    deadline = time.monotonic() + settings.dynamic_analysis_timeout_seconds

    while time.monotonic() < deadline:
        await asyncio.sleep(5)

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                poll_resp = await client.get(poll_url, headers=headers or None)
        except Exception as exc:
            logger.warning(
                "Dynamic analysis poll error for job %s (%s@%s): %s",
                job_id, package_name, package_version, exc,
            )
            continue

        if poll_resp.is_error:
            logger.warning(
                "Dynamic analysis poll HTTP error for job %s: HTTP %s",
                job_id, poll_resp.status_code,
            )
            continue

        try:
            body = poll_resp.json()
        except Exception:
            logger.warning(
                "Dynamic analysis poll returned non-JSON for job %s", job_id,
            )
            continue

        job_status = body.get("status")
        logger.debug("Dynamic analysis job %s status: %s", job_id, job_status)

        if job_status == "completed":
            result_payload = body.get("result")
            if not isinstance(result_payload, dict):
                logger.error(
                    "Dynamic analysis job %s completed but result is not a dict: %r",
                    job_id, result_payload,
                )
                return _make_partial_result("invalid_remote_payload")
            logger.info(
                "Dynamic analysis ← %s@%s (job=%s): status=%s coverage=%s "
                "risk_score=%s vm_evasion=%s ioc_hit=%s",
                package_name,
                package_version,
                job_id,
                result_payload.get("status"),
                result_payload.get("coverage"),
                result_payload.get("risk_score"),
                result_payload.get("vm_evasion_observed"),
                result_payload.get("ioc_detail", {}).get("dynamic_hit")
                if isinstance(result_payload.get("ioc_detail"), dict) else None,
            )
            return _normalize_remote_response(result_payload)

        if job_status == "failed":
            error_msg = body.get("error")
            logger.warning(
                "Dynamic analysis job %s failed for %s@%s: %s",
                job_id, package_name, package_version, error_msg,
            )
            return _make_partial_result("remote_job_failed", detail=error_msg)

        if job_status == "cancelled":
            logger.info(
                "Dynamic analysis job %s was cancelled for %s@%s",
                job_id, package_name, package_version,
            )
            return _make_skipped_result("cancelled")

        # status is "queued" or "running" — keep polling
        logger.debug(
            "Dynamic analysis job %s is %s for %s@%s, continuing to poll",
            job_id, job_status, package_name, package_version,
        )

    logger.warning(
        "Dynamic analysis timed out after %ss polling job %s for %s@%s",
        settings.dynamic_analysis_timeout_seconds,
        job_id,
        package_name,
        package_version,
    )
    return _make_partial_result("timeout")
