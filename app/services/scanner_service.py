"""Static analysis microservice integration.

This module delegates all static analysis (feature extraction, classification)
to a remote microservice and returns verdicts based on the response.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from app.api.schemas.risk import DependencyContext, PackageRiskAssessment, RiskSignal
from app.core.config import settings

logger = logging.getLogger(__name__)

SCANNER_VERSION = "2.0.0"  # Updated for microservice-based architecture


@dataclass(frozen=True)
class ScanVerdict:
    """Result of running static analysis on a single package."""

    malware_status: str  # "clean" | "malicious" | "error"
    malware_score: float | None
    scanner_version: str = SCANNER_VERSION
    error_message: str | None = None
    feature_snapshot: dict[str, float] | None = None


async def analyze_package_static(
    ecosystem: str,
    package_name: str,
    package_version: str,
    artifact_path: Any = "",
) -> ScanVerdict:
    """Delegate static analysis to a remote microservice.

    The microservice at `settings.static_analysis_remote_url` handles:
    - Feature extraction from the artifact (if artifact_path provided)
    - ML classification
    - Returning a ScanVerdict

    Args:
        ecosystem: Package ecosystem (npm, pypi, etc.)
        package_name: Name of the package
        package_version: Version of the package
        artifact_path: Path to artifact (Path or str, optional, microservice may fetch it)

    Returns:
        ScanVerdict with malware classification result
    """
    url = settings.static_analysis_remote_url.strip()
    if not url:
        return ScanVerdict(
            malware_status="error",
            malware_score=None,
            error_message="Static analysis microservice URL not configured",
        )

    request_payload = {
        "ecosystem": ecosystem,
        "package_name": package_name,
        "package_version": package_version,
    }
    if artifact_path:
        request_payload["artifact_path"] = str(artifact_path)

    timeout = httpx.Timeout(max(5, settings.static_analysis_timeout_seconds))

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=request_payload)

        if response.is_error:
            logger.warning(
                "Static analysis microservice error %s for %s@%s",
                response.status_code,
                package_name,
                package_version,
            )
            return ScanVerdict(
                malware_status="error",
                malware_score=None,
                error_message=f"Microservice error: {response.status_code}",
            )

        payload = response.json()
        if not isinstance(payload, dict):
            return ScanVerdict(
                malware_status="error",
                malware_score=None,
                error_message="Invalid microservice response format",
            )

        # Normalize microservice response into ScanVerdict
        malware_status = str(payload.get("malware_status", "error"))
        malware_score_raw = payload.get("malware_score")
        try:
            malware_score = float(malware_score_raw) if malware_score_raw is not None else None
        except (TypeError, ValueError):
            malware_score = None

        feature_snapshot_raw = payload.get("feature_snapshot")
        feature_snapshot = None
        if isinstance(feature_snapshot_raw, dict):
            feature_snapshot = {
                str(k): float(v) for k, v in feature_snapshot_raw.items() 
                if isinstance(v, (int, float))
            }

        return ScanVerdict(
            malware_status=malware_status,
            malware_score=malware_score,
            scanner_version=SCANNER_VERSION,
            error_message=payload.get("error_message"),
            feature_snapshot=feature_snapshot,
        )

    except asyncio.TimeoutError:
        logger.warning("Static analysis microservice timeout for %s@%s", package_name, package_version)
        return ScanVerdict(
            malware_status="error",
            malware_score=None,
            error_message="Static analysis microservice timeout",
        )
    except Exception as exc:
        logger.warning(
            "Static analysis microservice error for %s@%s: %s",
            package_name,
            package_version,
            exc.__class__.__name__,
        )
        return ScanVerdict(
            malware_status="error",
            malware_score=None,
            error_message=f"Static analysis error: {exc.__class__.__name__}",
        )


def _build_guardrail_signal_data(
    error_message: str | None,
) -> tuple[list[RiskSignal], list[str], dict[str, Any] | None]:
    if not error_message:
        return [], [], None

    guardrail_prefixes = {
        "GUARDRAIL_PATH_TRAVERSAL": "path_traversal_blocked",
        "GUARDRAIL_UNSAFE_LINK": "unsafe_link_blocked",
        "GUARDRAIL_ARCHIVE_LIMIT": "archive_limit_blocked",
        "GUARDRAIL_EXTRACTION_TIMEOUT": "extraction_timeout",
    }
    matched = None
    for prefix, name in guardrail_prefixes.items():
        if error_message.startswith(prefix):
            matched = (prefix, name)
            break

    if matched is None:
        return [], [], None

    prefix, guardrail_name = matched
    detail = error_message[len(prefix) :].strip(" :")
    metadata = {
        "guardrail": guardrail_name,
        "detail": detail or None,
        "executed_on_api_host": False,
    }
    signal = RiskSignal(
        source="system-guardrail",
        name=guardrail_name,
        value=True,
        weight=0.0,
        confidence=1.0,
        rationale="Untrusted artifact handling was blocked by backend security guardrails",
        metadata=metadata,
    )
    return [signal], [f"guardrail:{guardrail_name}"], metadata


def _safe_float(value: object, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


def _build_static_signals(
    feature_snapshot: dict[str, float] | None,
) -> tuple[list[RiskSignal], list[str], dict[str, Any]]:
    if not feature_snapshot:
        return [], [], {"context_markers": {}}

    max_entropy = _safe_float(feature_snapshot.get("max_entropy"))
    avg_entropy = _safe_float(feature_snapshot.get("avg_entropy"))
    eval_count = _safe_float(feature_snapshot.get("eval_count"))
    exec_count = _safe_float(feature_snapshot.get("exec_count"))
    base64_count = _safe_float(feature_snapshot.get("base64_count"))
    network_imports = _safe_float(feature_snapshot.get("network_imports"))
    obfuscation_index = _safe_float(feature_snapshot.get("obfuscation_index"))

    likely_minified_bundle = (
        max_entropy >= 5.5
        and avg_entropy >= 4.5
        and eval_count <= 1.0
        and exec_count <= 1.0
        and network_imports <= 2.0
    )
    likely_build_tooling = (
        exec_count > 0.0
        and network_imports == 0.0
        and eval_count == 0.0
        and obfuscation_index < 1.2
    )
    benign_eval_context = (
        eval_count > 0.0
        and exec_count == 0.0
        and network_imports == 0.0
        and max_entropy < 6.0
    )
    benign_subprocess_context = (
        exec_count > 0.0
        and network_imports == 0.0
        and base64_count == 0.0
        and obfuscation_index < 1.5
    )

    context_markers = {
        "likely_minified_bundle": likely_minified_bundle,
        "likely_build_tooling": likely_build_tooling,
        "benign_eval_context": benign_eval_context,
        "benign_subprocess_context": benign_subprocess_context,
    }

    attenuation = 1.0
    if likely_minified_bundle:
        attenuation *= 0.6
    if likely_build_tooling:
        attenuation *= 0.7

    eval_weight = 0.7 * attenuation
    exec_weight = 0.7 * attenuation
    obfuscation_weight = 0.8 * attenuation
    if benign_eval_context:
        eval_weight *= 0.5
    if benign_subprocess_context:
        exec_weight *= 0.5

    signals = [
        RiskSignal(
            source="static-analysis",
            name="entropy_signal",
            value=max_entropy,
            weight=0.6,
            confidence=0.75,
            rationale="High source entropy can indicate packing or obfuscation",
            metadata={"max_entropy": max_entropy, "avg_entropy": avg_entropy},
        ),
        RiskSignal(
            source="static-analysis",
            name="obfuscation_signal",
            value=obfuscation_index,
            weight=obfuscation_weight,
            confidence=0.8,
            rationale="Composite indicator from entropy gaps and base64 token density",
            metadata={"base64_count": base64_count, "attenuation": attenuation},
        ),
        RiskSignal(
            source="static-analysis",
            name="dynamic_code_signal",
            value=eval_count,
            weight=eval_weight,
            confidence=0.7,
            rationale="Counts eval-like runtime code generation patterns",
            metadata={"benign_eval_context": benign_eval_context, "attenuation": attenuation},
        ),
        RiskSignal(
            source="static-analysis",
            name="subprocess_signal",
            value=exec_count,
            weight=exec_weight,
            confidence=0.7,
            rationale="Counts subprocess or command execution indicators",
            metadata={"benign_subprocess_context": benign_subprocess_context, "attenuation": attenuation},
        ),
        RiskSignal(
            source="static-analysis",
            name="network_signal",
            value=network_imports,
            weight=0.6,
            confidence=0.65,
            rationale="Counts package-level network indicator usage",
            metadata={"network_imports": network_imports},
        ),
    ]

    for marker_name, marker_value in context_markers.items():
        signals.append(
            RiskSignal(
                source="static-context",
                name=marker_name,
                value=marker_value,
                weight=0.0,
                confidence=0.8,
                rationale="Context marker used to reduce false positives in common benign package patterns",
                metadata={},
            )
        )

    evidence = [
        f"static_marker:{name}"
        for name, enabled in context_markers.items()
        if enabled
    ]

    return signals, evidence, {"context_markers": context_markers, "attenuation": attenuation}


def _coerce_signal_value_for_scoring(value: object) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def _scale_signal_weights(signals: list[RiskSignal], scale: float) -> list[RiskSignal]:
    if scale == 1.0:
        return signals
    scaled: list[RiskSignal] = []
    for signal in signals:
        scaled.append(
            signal.model_copy(
                update={
                    "weight": round(signal.weight * scale, 6),
                    "metadata": {
                        **signal.metadata,
                        "weight_scale": scale,
                    },
                }
            )
        )
    return scaled


def _parse_allowlist_entries() -> set[str]:
    raw = settings.risk_policy_allowlist.strip()
    if not raw:
        return set()
    return {
        item.strip().lower()
        for item in raw.split(",")
        if item.strip()
    }


def _is_allowlisted(ecosystem: str, package_name: str, package_version: str) -> bool:
    allowlist = _parse_allowlist_entries()
    if not allowlist:
        return False

    identifiers = {
        package_name.lower(),
        f"{package_name.lower()}@{package_version}",
        f"{ecosystem.lower()}:{package_name.lower()}",
        f"{ecosystem.lower()}:{package_name.lower()}@{package_version}",
    }
    return any(identifier in allowlist for identifier in identifiers)


def _has_strong_reputation_signal(reputation_signals: list[RiskSignal]) -> bool:
    for signal in reputation_signals:
        metadata = signal.metadata if isinstance(signal.metadata, dict) else {}
        if metadata.get("trusted") is True:
            return True
        value = _coerce_signal_value_for_scoring(signal.value)
        if signal.name in {"trusted_package", "high_popularity", "verified_maintainer"} and value >= 0.7:
            return True
    return False


def _normalize_signal_value(signal: RiskSignal) -> float:
    """Map heterogeneous signal values into a 0..1 risk contribution."""
    raw = _coerce_signal_value_for_scoring(signal.value)
    raw = max(0.0, raw)

    if signal.name == "vulnerability_detected":
        return min(raw / 10.0, 1.0)
    if signal.name in {"entropy_signal"}:
        return min(raw / 8.0, 1.0)
    if signal.name in {"obfuscation_signal"}:
        return min(raw / 6.0, 1.0)
    if signal.name in {"dynamic_code_signal", "subprocess_signal", "network_signal"}:
        return min(np.log1p(raw) / np.log1p(20.0), 1.0)
    return min(raw, 1.0)


def _aggregate_signal_bucket(signals: list[RiskSignal]) -> float | None:
    weighted_sum = 0.0
    weight_total = 0.0
    for signal in signals:
        weight = max(0.0, float(signal.weight))
        if weight <= 0.0:
            continue
        confidence = min(max(float(signal.confidence), 0.0), 1.0)
        contribution = _normalize_signal_value(signal)
        weighted_sum += contribution * weight * confidence
        weight_total += weight * confidence
    if weight_total == 0.0:
        return None
    return min(max(weighted_sum / weight_total, 0.0), 1.0)


def _aggregate_reputation_risk_bucket(signals: list[RiskSignal]) -> float | None:
    weighted_sum = 0.0
    weight_total = 0.0
    for signal in signals:
        weight = max(0.0, float(signal.weight))
        if weight <= 0.0:
            continue
        confidence = min(max(float(signal.confidence), 0.0), 1.0)
        value = _normalize_signal_value(signal)
        name = signal.name.lower()
        metadata = signal.metadata if isinstance(signal.metadata, dict) else {}

        if metadata.get("trusted") is True or name in {"trusted_package", "high_popularity", "verified_maintainer"}:
            risk_contribution = 1.0 - value
        else:
            risk_contribution = value

        weighted_sum += risk_contribution * weight * confidence
        weight_total += weight * confidence

    if weight_total == 0.0:
        return None
    return min(max(weighted_sum / weight_total, 0.0), 1.0)


def _derive_status_from_score(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score <= settings.risk_scoring_clean_max:
        return "clean"
    if score <= settings.risk_scoring_suspicious_max:
        return "suspicious"
    return "malicious"


def _compute_unified_risk_score(
    *,
    verdict: ScanVerdict,
    static_signals: list[RiskSignal],
    vulnerability_signals: list[RiskSignal],
    reputation_signals: list[RiskSignal],
    dynamic_signals: list[RiskSignal],
) -> tuple[float | None, str, dict[str, Any]]:
    classifier_component = verdict.malware_score if verdict.malware_score is not None else 0.0
    static_component = _aggregate_signal_bucket(
        [signal for signal in static_signals if signal.source == "static-analysis"]
    )
    vulnerability_component = _aggregate_signal_bucket(vulnerability_signals)
    reputation_component = _aggregate_reputation_risk_bucket(reputation_signals)
    dynamic_component = _aggregate_signal_bucket(dynamic_signals)

    components: list[tuple[str, float | None, float]] = [
        ("classifier", classifier_component, settings.risk_scoring_classifier_weight),
        ("static", static_component, settings.risk_scoring_static_weight),
        ("vulnerability", vulnerability_component, settings.risk_scoring_vulnerability_weight),
        ("reputation", reputation_component, settings.risk_scoring_reputation_weight),
        ("dynamic", dynamic_component, settings.risk_scoring_dynamic_weight),
    ]

    numerator = 0.0
    denominator = 0.0
    breakdown: dict[str, Any] = {}
    for name, component_score, factor in components:
        clamped_factor = max(0.0, float(factor))
        breakdown[name] = {
            "score": component_score,
            "weight": clamped_factor,
        }
        if component_score is None or clamped_factor <= 0.0:
            continue
        numerator += component_score * clamped_factor
        denominator += clamped_factor

    unified_score = round(numerator / denominator, 6) if denominator > 0 else None
    derived_status = _derive_status_from_score(unified_score)
    return unified_score, derived_status, {
        "breakdown": breakdown,
        "thresholds": {
            "clean_max": settings.risk_scoring_clean_max,
            "suspicious_max": settings.risk_scoring_suspicious_max,
        },
        "method": "weighted_deterministic_v1",
    }


def _format_score(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.6f}"


def _build_factual_explanation(
    *,
    package_name: str,
    package_version: str,
    ecosystem: str,
    overall_status: str,
    overall_score: float | None,
    allowlisted: bool,
    suppressed: bool,
    suppression_reason: str | None,
    scoring_metadata: dict[str, Any],
    static_signals: list[RiskSignal],
    vulnerability_signals: list[RiskSignal],
    dynamic_signals: list[RiskSignal],
    reputation_signals: list[RiskSignal],
    policy_signals: list[RiskSignal],
    evidence: list[str],
) -> str:
    breakdown = scoring_metadata.get("breakdown") if isinstance(scoring_metadata.get("breakdown"), dict) else {}

    def _bucket_text(bucket: str) -> str:
        part = breakdown.get(bucket) if isinstance(breakdown, dict) else None
        if not isinstance(part, dict):
            return f"{bucket}=n/a"
        return (
            f"{bucket}={_format_score(part.get('score') if isinstance(part.get('score'), (int, float)) else None)}"
            f"(w={_format_score(part.get('weight') if isinstance(part.get('weight'), (int, float)) else None)})"
        )

    advisory_ids = sorted(
        {
            str(signal.metadata.get("advisory_id"))
            for signal in vulnerability_signals
            if isinstance(signal.metadata, dict) and signal.metadata.get("advisory_id")
        }
    )
    advisory_text = ", ".join(advisory_ids[:5]) if advisory_ids else "none"

    static_context_flags = sorted(
        [
            signal.name
            for signal in static_signals
            if signal.source == "static-context" and signal.value is True
        ]
    )
    static_context_text = ", ".join(static_context_flags[:5]) if static_context_flags else "none"

    dynamic_coverage = "none"
    dynamic_status = "not-run"
    for signal in dynamic_signals:
        metadata = signal.metadata if isinstance(signal.metadata, dict) else {}
        coverage = metadata.get("coverage")
        status = metadata.get("status")
        if isinstance(coverage, str):
            dynamic_coverage = coverage
        if isinstance(status, str):
            dynamic_status = status
        if dynamic_coverage != "none" or dynamic_status != "not-run":
            break

    policy_names = sorted({signal.name for signal in policy_signals})
    policy_text = ", ".join(policy_names) if policy_names else "none"

    evidence_text = ", ".join(sorted(set(evidence))[:8]) if evidence else "none"

    lines = [
        (
            f"Risk summary for {ecosystem}:{package_name}@{package_version}: "
            f"status={overall_status}; score={_format_score(overall_score)}."
        ),
        (
            "Scoring factors: "
            f"{_bucket_text('classifier')}; "
            f"{_bucket_text('static')}; "
            f"{_bucket_text('vulnerability')}; "
            f"{_bucket_text('reputation')}; "
            f"{_bucket_text('dynamic')}."
        ),
        (
            "Evidence summary: "
            f"static_context={static_context_text}; "
            f"vulnerability_advisories={advisory_text}; "
            f"dynamic_coverage={dynamic_coverage}; dynamic_status={dynamic_status}; "
            f"policy_signals={policy_text}."
        ),
        (
            "Policy outcome: "
            f"allowlisted={str(allowlisted).lower()}; "
            f"suppressed={str(suppressed).lower()}; "
            f"suppression_reason={suppression_reason or 'none'}."
        ),
        f"Evidence keys: {evidence_text}.",
    ]

    if reputation_signals:
        lines.append(f"Reputation signals observed: {len(reputation_signals)}.")

    return " ".join(lines)


def _build_policy_signals(
    *,
    ecosystem: str,
    package_name: str,
    package_version: str,
    verdict: ScanVerdict,
    base_status: str,
    base_score: float | None,
    vulnerability_signals: list[RiskSignal],
    reputation_signals: list[RiskSignal],
) -> tuple[bool, bool, str | None, list[RiskSignal], list[str], dict[str, Any], float | None, str]:
    policy_signals: list[RiskSignal] = []
    evidence: list[str] = []
    policy_metadata: dict[str, Any] = {
        "min_confidence": settings.risk_policy_min_confidence,
        "suppress_on_low_confidence": settings.risk_policy_suppress_on_low_confidence,
    }

    allowlisted = _is_allowlisted(ecosystem, package_name, package_version)
    suppressed = False
    suppression_reason: str | None = None

    if allowlisted:
        suppressed = True
        suppression_reason = "allowlist_match"
        policy_signals.append(
            RiskSignal(
                source="policy",
                name="allowlist_match",
                value=True,
                weight=0.0,
                confidence=1.0,
                rationale="Package matched explicit allowlist entry",
                metadata={
                    "package": package_name,
                    "version": package_version,
                    "ecosystem": ecosystem,
                },
            )
        )
        evidence.append("policy:allowlist_match")

    confidence_value = verdict.malware_score if verdict.malware_score is not None else 0.0
    has_vulnerability_evidence = len(vulnerability_signals) > 0
    has_reputation_override = _has_strong_reputation_signal(reputation_signals)

    if (
        not suppressed
        and settings.risk_policy_suppress_on_low_confidence
        and confidence_value < settings.risk_policy_min_confidence
        and not has_vulnerability_evidence
    ):
        suppressed = True
        suppression_reason = "low_confidence"
        policy_signals.append(
            RiskSignal(
                source="policy",
                name="low_confidence_suppression",
                value=confidence_value,
                weight=0.0,
                confidence=1.0,
                rationale="Classifier confidence below configured minimum with no vulnerability corroboration",
                metadata={"threshold": settings.risk_policy_min_confidence},
            )
        )
        evidence.append("policy:low_confidence")

    if not suppressed and has_reputation_override and not has_vulnerability_evidence and confidence_value < 0.7:
        suppressed = True
        suppression_reason = "reputation_offset"
        policy_signals.append(
            RiskSignal(
                source="policy",
                name="reputation_offset",
                value=True,
                weight=0.0,
                confidence=0.9,
                rationale="Strong trusted-reputation signals downgraded weak classifier evidence",
                metadata={"confidence_value": confidence_value},
            )
        )
        evidence.append("policy:reputation_offset")

    effective_status = base_status
    effective_score = base_score
    if suppressed and base_status not in {"error", "clean"}:
        effective_status = "clean"
        if effective_score is not None:
            effective_score = min(effective_score, settings.risk_policy_suppressed_score_ceiling)
    if allowlisted:
        effective_score = 0.0

    policy_metadata.update(
        {
            "allowlisted": allowlisted,
            "suppressed": suppressed,
            "suppression_reason": suppression_reason,
            "effective_status": effective_status,
            "effective_score": effective_score,
        }
    )

    return (
        allowlisted,
        suppressed,
        suppression_reason,
        policy_signals,
        evidence,
        policy_metadata,
        effective_score,
        effective_status,
    )


def _extract_features_from_directory(package_dir: Path) -> pd.DataFrame:
    """Placeholder - feature extraction now happens in microservice."""
    raise NotImplementedError("Feature extraction is handled by the static analysis microservice")


def extract_features(artifact_path: Path) -> pd.DataFrame:
    """Placeholder - delegated to microservice."""
    raise NotImplementedError("Feature extraction is handled by the static analysis microservice")


async def analyze_package_static(
    ecosystem: str,
    package_name: str,
    package_version: str,
    artifact_path: Path,
) -> ScanVerdict:
    """Delegate static analysis to a remote microservice.

    The microservice at `settings.static_analysis_remote_url` handles:
    - Feature extraction from the artifact
    - ML classification
    - Returning a ScanVerdict

    This is an async function suitable for use within the orchestrator.
    """
    url = settings.static_analysis_remote_url.strip()
    if not url:
        return ScanVerdict(
            malware_status="error",
            malware_score=None,
            error_message="Static analysis microservice URL not configured",
        )

    request_payload = {
        "ecosystem": ecosystem,
        "package_name": package_name,
        "package_version": package_version,
        "artifact_path": str(artifact_path),
    }

    headers = {}
    timeout = httpx.Timeout(max(5, 60))

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=request_payload, headers=headers or None)

        if response.is_error:
            logger.warning(
                "Static analysis microservice returned error %s for %s@%s",
                response.status_code,
                package_name,
                package_version,
            )
            return ScanVerdict(
                malware_status="error",
                malware_score=None,
                error_message=f"Microservice error: {response.status_code}",
            )

        payload = response.json()
        if not isinstance(payload, dict):
            return ScanVerdict(
                malware_status="error",
                malware_score=None,
                error_message="Invalid microservice response format",
            )

        # Normalize microservice response into ScanVerdict
        malware_status = str(payload.get("malware_status", "error"))
        malware_score_raw = payload.get("malware_score")
        try:
            malware_score = float(malware_score_raw) if malware_score_raw is not None else None
        except (TypeError, ValueError):
            malware_score = None

        feature_snapshot_raw = payload.get("feature_snapshot")
        feature_snapshot = None
        if isinstance(feature_snapshot_raw, dict):
            feature_snapshot = {str(k): float(v) for k, v in feature_snapshot_raw.items() if isinstance(v, (int, float))}

        return ScanVerdict(
            malware_status=malware_status,
            malware_score=malware_score,
            scanner_version=SCANNER_VERSION,
            error_message=payload.get("error_message"),
            feature_snapshot=feature_snapshot,
        )

    except httpx.TimeoutException:
        logger.warning("Static analysis microservice timeout for %s@%s", package_name, package_version)
        return ScanVerdict(
            malware_status="error",
            malware_score=None,
            error_message="Static analysis microservice timeout",
        )
    except Exception as exc:
        logger.warning(
            "Static analysis microservice delegation failed for %s@%s: %s",
            package_name,
            package_version,
            exc.__class__.__name__,
        )
        return ScanVerdict(
            malware_status="error",
            malware_score=None,
            error_message=f"Static analysis error: {exc.__class__.__name__}",
        )


def classify_features(features: pd.DataFrame) -> ScanVerdict:
    """Placeholder - delegated to microservice via analyze_package_static."""
    raise NotImplementedError("Classification is handled by the static analysis microservice")


def classify(artifact_path: Path) -> ScanVerdict:
    """Placeholder - use analyze_package_static instead."""
    raise NotImplementedError("Use analyze_package_static for remote static analysis")


def build_package_risk_assessment(
    package_name: str,
    package_version: str,
    ecosystem: str,
    verdict: ScanVerdict,
    *,
    dependency_context: DependencyContext | dict[str, Any] | None = None,
    vulnerability_signals: list[RiskSignal] | None = None,
    reputation_signals: list[RiskSignal] | None = None,
    dynamic_signals: list[RiskSignal] | None = None,
    advisory_references: list[str] | None = None,
    vulnerability_evidence: list[str] | None = None,
    reputation_evidence: list[str] | None = None,
    dynamic_evidence: list[str] | None = None,
    vulnerability_metadata: dict[str, Any] | None = None,
    reputation_metadata: dict[str, Any] | None = None,
    dynamic_metadata: dict[str, Any] | None = None,
) -> PackageRiskAssessment:
    """Build the canonical package-risk contract from a scan verdict."""

    if dependency_context is not None and not isinstance(dependency_context, DependencyContext):
        dependency_context = DependencyContext.model_validate(dependency_context)

    vuln_signals = vulnerability_signals or []
    rep_signals = reputation_signals or []
    dyn_signals = dynamic_signals or []
    guardrail_signals, guardrail_evidence, guardrail_metadata = _build_guardrail_signal_data(
        verdict.error_message
    )

    classifier_signal = RiskSignal(
        source="classifier",
        name="malware_probability",
        value=verdict.malware_score,
        weight=1.0,
        confidence=1.0 if verdict.malware_score is not None else 0.0,
        rationale="Thresholded ML classifier output from extracted package features",
        metadata={"scanner_version": verdict.scanner_version},
    )
    structured_static_signals, static_evidence, static_metadata = _build_static_signals(
        verdict.feature_snapshot
    )

    static_signals = [
        classifier_signal,
        *_scale_signal_weights(structured_static_signals, settings.risk_policy_static_weight_scale),
    ]

    vuln_signals = _scale_signal_weights(vuln_signals, settings.risk_policy_vulnerability_weight_scale)
    rep_signals = _scale_signal_weights(rep_signals, settings.risk_policy_reputation_weight_scale)

    unified_score, unified_status, scoring_metadata = _compute_unified_risk_score(
        verdict=verdict,
        static_signals=static_signals,
        vulnerability_signals=vuln_signals,
        reputation_signals=rep_signals,
        dynamic_signals=dyn_signals,
    )
    if verdict.malware_status == "error":
        unified_status = "error"

    (
        allowlisted,
        suppressed,
        suppression_reason,
        policy_signals,
        policy_evidence,
        policy_metadata,
        effective_score,
        effective_status,
    ) = _build_policy_signals(
        ecosystem=ecosystem,
        package_name=package_name,
        package_version=package_version,
        verdict=verdict,
        base_status=unified_status,
        base_score=unified_score,
        vulnerability_signals=vuln_signals,
        reputation_signals=rep_signals,
    )
    if guardrail_signals:
        policy_signals = [*policy_signals, *guardrail_signals]
        policy_evidence.extend(guardrail_evidence)

    metadata: dict[str, Any] = {"scanner_version": verdict.scanner_version}
    if verdict.feature_snapshot is not None:
        metadata["feature_snapshot"] = verdict.feature_snapshot
    metadata["static_analysis"] = static_metadata
    if vulnerability_metadata:
        metadata["vulnerability"] = vulnerability_metadata
    if reputation_metadata:
        metadata["reputation"] = reputation_metadata
    if dynamic_metadata:
        metadata["dynamic"] = dynamic_metadata
    metadata["policy"] = policy_metadata
    if guardrail_metadata:
        metadata["guardrail"] = guardrail_metadata
    metadata["scoring"] = scoring_metadata

    evidence: list[str] = []
    if verdict.feature_snapshot is not None:
        evidence.append("extracted_feature_snapshot")
    if verdict.malware_score is not None:
        evidence.append(f"classifier_score={verdict.malware_score}")
    if static_evidence:
        evidence.extend(static_evidence)
    if vulnerability_evidence:
        evidence.extend(vulnerability_evidence)
    if reputation_evidence:
        evidence.extend(reputation_evidence)
    if dynamic_evidence:
        evidence.extend(dynamic_evidence)
    if policy_evidence:
        evidence.extend(policy_evidence)
    if verdict.error_message:
        evidence.append(verdict.error_message)

    explanation = _build_factual_explanation(
        package_name=package_name,
        package_version=package_version,
        ecosystem=ecosystem,
        overall_status=effective_status,
        overall_score=effective_score,
        allowlisted=allowlisted,
        suppressed=suppressed,
        suppression_reason=suppression_reason,
        scoring_metadata=scoring_metadata,
        static_signals=static_signals,
        vulnerability_signals=vuln_signals,
        dynamic_signals=dyn_signals,
        reputation_signals=rep_signals,
        policy_signals=policy_signals,
        evidence=evidence,
    )

    return PackageRiskAssessment(
        package_name=package_name,
        package_version=package_version,
        ecosystem=ecosystem,
        overall_status=effective_status,
        overall_score=effective_score,
        confidence=verdict.malware_score,
        analysis_mode="static-classifier",
        allowlisted=allowlisted,
        suppressed=suppressed,
        suppression_reason=suppression_reason,
        dependency_context=dependency_context,
        static_signals=static_signals,
        dynamic_signals=dyn_signals,
        vulnerability_signals=vuln_signals,
        reputation_signals=rep_signals,
        policy_signals=policy_signals,
        advisory_references=advisory_references or [],
        evidence=evidence,
        explanation=explanation,
        metadata=metadata,
    )
    """Extract the 10-feature vector expected by the trained model.

    The resulting frame has one row and columns matching the model schema
    used in training:
    ``max_entropy, avg_entropy, eval_count, exec_count, base64_count,
    network_imports, entropy_gap, exec_eval_ratio, network_exec_ratio,
    obfuscation_index``.
    """
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        counts = np.fromiter((text.count(chr(i)) for i in range(256)), dtype=float)
        probs = counts[counts > 0] / len(text)
        return float(-(probs * np.log2(probs)).sum())

    def _count_tokens(content: str, tokens: list[str]) -> float:
        lowered = content.lower()
        return float(sum(lowered.count(token.lower()) for token in tokens))

    all_files: list[Path] = []
    for root, _dirs, files in os.walk(package_dir):
        for fname in files:
            all_files.append(Path(root) / fname)

    source_files = [f for f in all_files if f.suffix.lower() in (".js", ".mjs", ".cjs", ".py")]
    json_files = [f for f in all_files if f.suffix.lower() == ".json"]

    entropies: list[float] = []
    eval_count = 0.0
    exec_count = 0.0
    base64_count = 0.0
    network_imports = 0.0

    network_indicators = [
        "http://", "https://", "request(", "fetch(", "axios",
        "urllib", "requests.get", "requests.post", "socket",
        "XMLHttpRequest", "net.connect",
    ]
    eval_indicators = ["eval(", "function(", "function (", "fromcharcode"]
    exec_indicators = [
        "exec(", "subprocess", "child_process",
        "os.system", "os.popen", "spawn(", "execSync",
        "__import__",
    ]
    base64_indicators = [
        "atob(", "btoa(", "base64", "b64decode", "b64encode",
    ]

    for sf in source_files:
        try:
            content = sf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        entropies.append(_shannon_entropy(content))
        eval_count += _count_tokens(content, eval_indicators)
        exec_count += _count_tokens(content, exec_indicators)
        base64_count += _count_tokens(content, base64_indicators)
        network_imports += _count_tokens(content, network_indicators)

    # Include package.json text for script-related and encoded-content signals.
    for jf in json_files:
        try:
            content = jf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        entropies.append(_shannon_entropy(content))
        eval_count += _count_tokens(content, eval_indicators)
        exec_count += _count_tokens(content, exec_indicators)
        base64_count += _count_tokens(content, base64_indicators)
        network_imports += _count_tokens(content, network_indicators)

    max_entropy = float(max(entropies, default=0.0))
    avg_entropy = float(np.mean(entropies) if entropies else 0.0)
    entropy_gap = float(max_entropy - avg_entropy)
    exec_eval_ratio = float((exec_count + 1.0) / (eval_count + 1.0))
    network_exec_ratio = float((network_imports + 1.0) / (exec_count + 1.0))
    obfuscation_index = float(entropy_gap * np.log1p(base64_count))

    features: dict[str, float] = {
        "max_entropy": max_entropy,
        "avg_entropy": avg_entropy,
        "eval_count": float(eval_count),
        "exec_count": float(exec_count),
        "base64_count": float(base64_count),
        "network_imports": float(network_imports),
        "entropy_gap": entropy_gap,
        "exec_eval_ratio": exec_eval_ratio,
        "network_exec_ratio": network_exec_ratio,
        "obfuscation_index": obfuscation_index,
    }

    expected_columns = list(
        getattr(_classifier, "feature_names_in_", MODEL_FEATURE_COLUMNS)
    )
    # Keep only expected model features and preserve exact training order.
    row = {col: float(features.get(col, 0.0)) for col in expected_columns}
    return pd.DataFrame([row], columns=expected_columns)


def _is_safe_extract_target(base_dir: Path, member_name: str) -> bool:
    normalized = member_name.replace("\\", "/")
    if normalized.startswith("/"):
        return False
    if any(part == ".." for part in Path(normalized).parts):
        return False

    target = (base_dir / normalized).resolve()
    base = base_dir.resolve()
    return str(target).startswith(str(base))


def _enforce_archive_limits(file_count: int, total_size: int) -> None:
    if file_count > settings.scanner_artifact_max_files:
        raise ArtifactGuardrailError(
            f"GUARDRAIL_ARCHIVE_LIMIT: too_many_files file_count={file_count}"
        )
    if total_size > settings.scanner_artifact_max_total_bytes:
        raise ArtifactGuardrailError(
            f"GUARDRAIL_ARCHIVE_LIMIT: total_size_exceeded total_size={total_size}"
        )


def _extract_archive(archive_path: Path, dest_dir: Path) -> Path:
    """Extract a .tgz / .tar.gz / .zip / .whl archive and return the root folder."""
    archive_str = str(archive_path)
    start = time.monotonic()

    if tarfile.is_tarfile(archive_str):
        with tarfile.open(archive_str, "r:*") as tf:
            members = tf.getmembers()
            file_count = 0
            total_size = 0
            for member in members:
                if not _is_safe_extract_target(dest_dir, member.name):
                    raise ArtifactGuardrailError(
                        f"GUARDRAIL_PATH_TRAVERSAL: member={member.name}"
                    )
                if member.issym() or member.islnk():
                    raise ArtifactGuardrailError(
                        f"GUARDRAIL_UNSAFE_LINK: member={member.name}"
                    )
                if member.isreg():
                    file_count += 1
                    total_size += int(member.size)
            _enforce_archive_limits(file_count, total_size)

            for member in members:
                tf.extract(member, dest_dir, set_attrs=False, filter="data")

                elapsed = time.monotonic() - start
                if elapsed > max(1, settings.scanner_artifact_extract_timeout_seconds):
                    raise ArtifactGuardrailError(
                        "GUARDRAIL_EXTRACTION_TIMEOUT: tar extraction timed out"
                    )
    elif zipfile.is_zipfile(archive_str):
        with zipfile.ZipFile(archive_str, "r") as zf:
            infos = zf.infolist()
            file_count = 0
            total_size = 0
            for info in infos:
                if not _is_safe_extract_target(dest_dir, info.filename):
                    raise ArtifactGuardrailError(
                        f"GUARDRAIL_PATH_TRAVERSAL: member={info.filename}"
                    )
                # Posix symlink bit in external attrs.
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise ArtifactGuardrailError(
                        f"GUARDRAIL_UNSAFE_LINK: member={info.filename}"
                    )
                if not info.is_dir():
                    file_count += 1
                    total_size += int(info.file_size)
            _enforce_archive_limits(file_count, total_size)

            for info in infos:
                zf.extract(info, dest_dir)

                elapsed = time.monotonic() - start
                if elapsed > max(1, settings.scanner_artifact_extract_timeout_seconds):
                    raise ArtifactGuardrailError(
                        "GUARDRAIL_EXTRACTION_TIMEOUT: zip extraction timed out"
                    )
    else:
        raise ValueError(f"Unsupported archive format: {archive_path.name}")

    # Return the first child directory if there is exactly one (common for tarballs).
    children = list(dest_dir.iterdir())
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest_dir


def extract_features(artifact_path: Path) -> pd.DataFrame:
    """Extract model features for a package artifact.

    This is a blocking function and should be called via ``asyncio.to_thread``
    from async code.
    """
    _ensure_model_loaded()

    if artifact_path.is_file():
        tmp_extract = Path(tempfile.mkdtemp(prefix="sentinel_extract_"))
        try:
            package_dir = _extract_archive(artifact_path, tmp_extract)
            return _extract_features_from_directory(package_dir)
        finally:
            import shutil

            shutil.rmtree(tmp_extract, ignore_errors=True)

    if artifact_path.is_dir():
        return _extract_features_from_directory(artifact_path)

    raise FileNotFoundError(f"Artifact not found: {artifact_path}")


def classify_features(features: pd.DataFrame) -> ScanVerdict:
    """Run classifier inference on an already extracted feature frame."""
    try:
        _ensure_model_loaded()
        probabilities = _classifier.predict_proba(features)[0]
        malware_prob = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])
        status = "malicious" if malware_prob >= _threshold else "clean"
        feature_snapshot: dict[str, float] | None = None
        if not features.empty:
            row = features.iloc[0].to_dict()
            feature_snapshot = {str(key): float(value) for key, value in row.items()}

        return ScanVerdict(
            malware_status=status,
            malware_score=round(malware_prob, 6),
            feature_snapshot=feature_snapshot,
        )
    except Exception as exc:
        logger.exception("Classifier inference error")
        return ScanVerdict(
            malware_status="error",
            malware_score=None,
            error_message=str(exc),
        )


def build_package_risk_assessment(
    package_name: str,
    package_version: str,
    ecosystem: str,
    verdict: ScanVerdict,
    *,
    dependency_context: DependencyContext | dict[str, Any] | None = None,
    vulnerability_signals: list[RiskSignal] | None = None,
    reputation_signals: list[RiskSignal] | None = None,
    dynamic_signals: list[RiskSignal] | None = None,
    advisory_references: list[str] | None = None,
    vulnerability_evidence: list[str] | None = None,
    reputation_evidence: list[str] | None = None,
    dynamic_evidence: list[str] | None = None,
    vulnerability_metadata: dict[str, Any] | None = None,
    reputation_metadata: dict[str, Any] | None = None,
    dynamic_metadata: dict[str, Any] | None = None,
) -> PackageRiskAssessment:
    """Build the canonical package-risk contract from a scan verdict."""

    if dependency_context is not None and not isinstance(dependency_context, DependencyContext):
        dependency_context = DependencyContext.model_validate(dependency_context)

    vuln_signals = vulnerability_signals or []
    rep_signals = reputation_signals or []
    dyn_signals = dynamic_signals or []
    guardrail_signals, guardrail_evidence, guardrail_metadata = _build_guardrail_signal_data(
        verdict.error_message
    )

    classifier_signal = RiskSignal(
        source="classifier",
        name="malware_probability",
        value=verdict.malware_score,
        weight=1.0,
        confidence=1.0 if verdict.malware_score is not None else 0.0,
        rationale="Thresholded ML classifier output from extracted package features",
        metadata={"scanner_version": verdict.scanner_version},
    )
    structured_static_signals, static_evidence, static_metadata = _build_static_signals(
        verdict.feature_snapshot
    )

    static_signals = [
        classifier_signal,
        *_scale_signal_weights(structured_static_signals, settings.risk_policy_static_weight_scale),
    ]

    vuln_signals = _scale_signal_weights(vuln_signals, settings.risk_policy_vulnerability_weight_scale)
    rep_signals = _scale_signal_weights(rep_signals, settings.risk_policy_reputation_weight_scale)

    unified_score, unified_status, scoring_metadata = _compute_unified_risk_score(
        verdict=verdict,
        static_signals=static_signals,
        vulnerability_signals=vuln_signals,
        reputation_signals=rep_signals,
        dynamic_signals=dyn_signals,
    )
    if verdict.malware_status == "error":
        unified_status = "error"

    (
        allowlisted,
        suppressed,
        suppression_reason,
        policy_signals,
        policy_evidence,
        policy_metadata,
        effective_score,
        effective_status,
    ) = _build_policy_signals(
        ecosystem=ecosystem,
        package_name=package_name,
        package_version=package_version,
        verdict=verdict,
        base_status=unified_status,
        base_score=unified_score,
        vulnerability_signals=vuln_signals,
        reputation_signals=rep_signals,
    )
    if guardrail_signals:
        policy_signals = [*policy_signals, *guardrail_signals]
        policy_evidence.extend(guardrail_evidence)

    metadata: dict[str, Any] = {"scanner_version": verdict.scanner_version}
    if verdict.feature_snapshot is not None:
        metadata["feature_snapshot"] = verdict.feature_snapshot
    metadata["static_analysis"] = static_metadata
    if vulnerability_metadata:
        metadata["vulnerability"] = vulnerability_metadata
    if reputation_metadata:
        metadata["reputation"] = reputation_metadata
    if dynamic_metadata:
        metadata["dynamic"] = dynamic_metadata
    metadata["policy"] = policy_metadata
    if guardrail_metadata:
        metadata["guardrail"] = guardrail_metadata
    metadata["scoring"] = scoring_metadata

    evidence: list[str] = []
    if verdict.feature_snapshot is not None:
        evidence.append("extracted_feature_snapshot")
    if verdict.malware_score is not None:
        evidence.append(f"classifier_score={verdict.malware_score}")
    if static_evidence:
        evidence.extend(static_evidence)
    if vulnerability_evidence:
        evidence.extend(vulnerability_evidence)
    if reputation_evidence:
        evidence.extend(reputation_evidence)
    if dynamic_evidence:
        evidence.extend(dynamic_evidence)
    if policy_evidence:
        evidence.extend(policy_evidence)
    if verdict.error_message:
        evidence.append(verdict.error_message)

    explanation = _build_factual_explanation(
        package_name=package_name,
        package_version=package_version,
        ecosystem=ecosystem,
        overall_status=effective_status,
        overall_score=effective_score,
        allowlisted=allowlisted,
        suppressed=suppressed,
        suppression_reason=suppression_reason,
        scoring_metadata=scoring_metadata,
        static_signals=static_signals,
        vulnerability_signals=vuln_signals,
        dynamic_signals=dyn_signals,
        reputation_signals=rep_signals,
        policy_signals=policy_signals,
        evidence=evidence,
    )

    return PackageRiskAssessment(
        package_name=package_name,
        package_version=package_version,
        ecosystem=ecosystem,
        overall_status=effective_status,
        overall_score=effective_score,
        confidence=verdict.malware_score,
        analysis_mode="static-classifier",
        allowlisted=allowlisted,
        suppressed=suppressed,
        suppression_reason=suppression_reason,
        dependency_context=dependency_context,
        static_signals=static_signals,
        dynamic_signals=dyn_signals,
        vulnerability_signals=vuln_signals,
        reputation_signals=rep_signals,
        policy_signals=policy_signals,
        advisory_references=advisory_references or [],
        evidence=evidence,
        explanation=explanation,
        metadata=metadata,
    )


def classify(artifact_path: Path) -> ScanVerdict:
    """Run the ML classifier on a package artifact (archive or directory).

    This is a **blocking** function.  Call via ``asyncio.to_thread`` from
    async code so the event loop isn't stalled.
    """
    try:
        features = extract_features(artifact_path)
        return classify_features(features)

    except Exception as exc:
        logger.exception("Classifier error for %s", artifact_path)
        return ScanVerdict(
            malware_status="error",
            malware_score=None,
            error_message=str(exc),
        )
