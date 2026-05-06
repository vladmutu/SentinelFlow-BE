"""Dynamic-analysis microservice integration.

This module delegates all dynamic analysis to a remote microservice.
It never executes untrusted package code on the API host.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from pathlib import Path
import logging
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


@dataclass
class _CachedDynamicResult:
    expires_at: datetime
    result: DynamicAnalysisResult


_dynamic_cache_lock = asyncio.Lock()
_dynamic_cache: dict[tuple[str, str, str], _CachedDynamicResult] = {}
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

    metadata = {
        "status": status,
        "coverage": coverage,
        "sandbox_provider": payload.get("provider"),
        "sandbox_job_id": payload.get("job_id"),
        "sandbox_timed_out": bool(payload.get("timed_out", False)),
        "executed_on_api_host": False,
        "sandbox_boundary": "remote_only",
        "sandbox_isolation_enforced": True,
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

    return DynamicAnalysisResult(signals=signals, evidence=evidence, metadata=metadata)


async def analyze_package_dynamically(
    ecosystem: str,
    package_name: str,
    package_version: str,
    artifact_path: Path | None = None,
) -> DynamicAnalysisResult:
    """Delegate dynamic analysis to a remote microservice.

    This function never executes the package locally on the API host.
    Sends only package metadata to the microservice.
    """
    if not settings.dynamic_analysis_enabled:
        return _make_skipped_result("disabled")

    url = settings.dynamic_analysis_url.strip()
    if not url:
        return _make_skipped_result("missing_remote_url")

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    is_localhost = host in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not is_localhost:
        return _make_skipped_result(
            "insecure_remote_url",
            detail=f"scheme={parsed.scheme or 'none'}",
        )

    cache_key = (ecosystem.lower(), package_name.lower(), package_version)
    now = datetime.now(timezone.utc)
    cached = _dynamic_cache.get(cache_key)
    if cached is not None and cached.expires_at > now:
        return cached.result

    request_payload: dict[str, object] = {
        "ecosystem": ecosystem,
        "package_name": package_name,
        "package_version": package_version,
    }

    timeout = httpx.Timeout(max(2, settings.dynamic_analysis_timeout_seconds))

    try:
        semaphore = await _get_dynamic_semaphore()
        async with semaphore:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url, json=request_payload)

        if response.is_error:
            detail = f"status_code={response.status_code}"
            result = _make_partial_result("remote_http_error", detail=detail)
            return result

        payload = response.json()
        if not isinstance(payload, dict):
            result = _make_partial_result("invalid_remote_payload")
        else:
            result = _normalize_remote_response(payload)

        ttl_seconds = max(30, settings.dynamic_analysis_cache_ttl_seconds)
        async with _dynamic_cache_lock:
            _dynamic_cache[cache_key] = _CachedDynamicResult(
                expires_at=now + timedelta(seconds=ttl_seconds),
                result=result,
            )
        return result

    except httpx.TimeoutException:
        return _make_partial_result("timeout")
    except Exception as exc:
        logger.warning(
            "Dynamic analysis microservice error for %s@%s: %s",
            package_name,
            package_version,
            exc.__class__.__name__,
        )
        return _make_partial_result("remote_exception", detail=exc.__class__.__name__)

    return DynamicAnalysisResult(
        signals=[*result.signals, *extra_signals],
        evidence=[*result.evidence, *extra_evidence],
        metadata={**result.metadata, "sandbox_type": "firecracker"},
    )
