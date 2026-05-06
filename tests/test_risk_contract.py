"""Tests for the canonical package-risk contract."""

from __future__ import annotations

from unittest.mock import patch

from app.api.schemas.risk import RiskSignal
from app.api.schemas.risk import PackageRiskAssessment
from app.services.scanner_service import ScanVerdict, build_package_risk_assessment


def test_build_package_risk_assessment_includes_static_classifier_signal() -> None:
    """Risk assessment should expose a stable classifier-backed contract."""

    verdict = ScanVerdict(
        malware_status="malicious",
        malware_score=0.91,
        feature_snapshot={"max_entropy": 7.5, "exec_count": 4.0},
    )

    assessment = build_package_risk_assessment("left-pad", "1.3.0", "npm", verdict)

    assert isinstance(assessment, PackageRiskAssessment)
    assert assessment.package_name == "left-pad"
    assert assessment.package_version == "1.3.0"
    assert assessment.ecosystem == "npm"
    assert assessment.overall_status == "malicious"
    assert assessment.overall_score is not None
    assert assessment.overall_score > 0.7
    assert assessment.static_signals[0].name == "malware_probability"
    assert assessment.metadata["feature_snapshot"]["max_entropy"] == 7.5
    assert assessment.metadata["scoring"]["method"] == "weighted_deterministic_v1"
    assert "classifier_score=0.91" in assessment.evidence
    assert assessment.explanation is not None
    assert "Risk summary for npm:left-pad@1.3.0" in assessment.explanation
    assert "Scoring factors:" in assessment.explanation
    assert "Policy outcome:" in assessment.explanation


def test_build_package_risk_assessment_includes_vulnerability_evidence() -> None:
    """Risk assessment should preserve vulnerability feed evidence and references."""

    verdict = ScanVerdict(malware_status="clean", malware_score=0.12)
    vuln_signals = [
        RiskSignal(
            source="osv",
            name="vulnerability_detected",
            value=9.8,
            confidence=1.0,
            metadata={"advisory_id": "GHSA-xxxx-yyyy"},
        )
    ]

    assessment = build_package_risk_assessment(
        "example",
        "1.2.3",
        "npm",
        verdict,
        vulnerability_signals=vuln_signals,
        advisory_references=["GHSA-xxxx-yyyy", "CVE-2025-12345"],
        vulnerability_evidence=["osv:GHSA-xxxx-yyyy"],
        vulnerability_metadata={"osv_match_count": 1, "nvd_match_count": 0},
    )

    assert len(assessment.vulnerability_signals) == 1
    assert sorted(assessment.advisory_references) == ["CVE-2025-12345", "GHSA-xxxx-yyyy"]
    assert "osv:GHSA-xxxx-yyyy" in assessment.evidence
    assert assessment.metadata["vulnerability"]["osv_match_count"] == 1


def test_build_package_risk_assessment_adds_structured_static_signals() -> None:
    """Static analysis output should be represented as structured signals and markers."""

    verdict = ScanVerdict(
        malware_status="clean",
        malware_score=0.2,
        feature_snapshot={
            "max_entropy": 6.0,
            "avg_entropy": 5.0,
            "eval_count": 0.0,
            "exec_count": 1.0,
            "base64_count": 0.0,
            "network_imports": 0.0,
            "obfuscation_index": 0.2,
        },
    )

    assessment = build_package_risk_assessment("webpack", "5.0.0", "npm", verdict)

    signal_names = [signal.name for signal in assessment.static_signals]
    assert "malware_probability" in signal_names
    assert "entropy_signal" in signal_names
    assert "subprocess_signal" in signal_names
    assert "likely_build_tooling" in signal_names
    assert "static_marker:likely_build_tooling" in assessment.evidence
    assert assessment.metadata["static_analysis"]["context_markers"]["likely_build_tooling"] is True


def test_build_package_risk_assessment_allowlist_suppresses_detection() -> None:
    """Allowlisted packages should be explicitly suppressed with policy evidence."""

    verdict = ScanVerdict(malware_status="malicious", malware_score=0.91)

    with patch("app.services.scanner_service.settings.risk_policy_allowlist", "npm:left-pad@1.3.0"):
        assessment = build_package_risk_assessment("left-pad", "1.3.0", "npm", verdict)

    assert assessment.allowlisted is True
    assert assessment.suppressed is True
    assert assessment.suppression_reason == "allowlist_match"
    assert assessment.overall_status == "clean"
    assert assessment.overall_score == 0.0
    assert "policy:allowlist_match" in assessment.evidence
    assert any(signal.name == "allowlist_match" for signal in assessment.policy_signals)


def test_build_package_risk_assessment_low_confidence_policy_suppresses() -> None:
    """Low-confidence malicious verdicts should be suppressed when no corroborating evidence exists."""

    verdict = ScanVerdict(malware_status="malicious", malware_score=0.21)

    with (
        patch("app.services.scanner_service.settings.risk_policy_allowlist", ""),
        patch("app.services.scanner_service.settings.risk_policy_min_confidence", 0.35),
        patch("app.services.scanner_service.settings.risk_policy_suppress_on_low_confidence", True),
        patch("app.services.scanner_service.settings.risk_policy_suppressed_score_ceiling", 0.2),
    ):
        assessment = build_package_risk_assessment("example", "1.0.0", "npm", verdict)

    assert assessment.allowlisted is False
    assert assessment.suppressed is True
    assert assessment.suppression_reason == "low_confidence"
    assert assessment.overall_status == "clean"
    assert assessment.overall_score is not None
    assert assessment.overall_score <= 0.21
    assert "policy:low_confidence" in assessment.evidence
    assert any(signal.name == "low_confidence_suppression" for signal in assessment.policy_signals)


def test_build_package_risk_assessment_reputation_offset_suppresses() -> None:
    """Trusted reputation signals should downgrade weak classifier-only malicious verdicts."""

    verdict = ScanVerdict(malware_status="malicious", malware_score=0.55)
    reputation_signals = [
        RiskSignal(
            source="reputation",
            name="trusted_package",
            value=0.95,
            confidence=0.9,
            metadata={"trusted": True},
        )
    ]

    with patch("app.services.scanner_service.settings.risk_policy_allowlist", ""):
        assessment = build_package_risk_assessment(
            "requests",
            "2.31.0",
            "pypi",
            verdict,
            reputation_signals=reputation_signals,
        )

    assert assessment.suppressed is True
    assert assessment.suppression_reason == "reputation_offset"
    assert "policy:reputation_offset" in assessment.evidence
    assert any(signal.name == "reputation_offset" for signal in assessment.policy_signals)


def test_build_package_risk_assessment_vulnerability_boosts_unified_score() -> None:
    """High-severity vulnerabilities should elevate the unified risk score deterministically."""

    verdict = ScanVerdict(malware_status="clean", malware_score=0.12)
    vulnerability_signals = [
        RiskSignal(
            source="osv",
            name="vulnerability_detected",
            value=9.8,
            weight=1.0,
            confidence=1.0,
            metadata={"advisory_id": "GHSA-boost"},
        )
    ]

    with (
        patch("app.services.scanner_service.settings.risk_policy_allowlist", ""),
        patch("app.services.scanner_service.settings.risk_policy_min_confidence", 0.0),
        patch("app.services.scanner_service.settings.risk_policy_suppress_on_low_confidence", False),
    ):
        first = build_package_risk_assessment(
            "pkg",
            "1.0.0",
            "npm",
            verdict,
            vulnerability_signals=vulnerability_signals,
        )
        second = build_package_risk_assessment(
            "pkg",
            "1.0.0",
            "npm",
            verdict,
            vulnerability_signals=vulnerability_signals,
        )

    assert first.overall_score is not None
    assert first.overall_score > 0.4
    assert first.overall_score == second.overall_score
    assert first.metadata["scoring"]["breakdown"]["vulnerability"]["score"] is not None
    assert first.explanation == second.explanation
    assert "vulnerability_advisories=GHSA-boost" in first.explanation


def test_build_package_risk_assessment_reputation_can_reduce_unified_score() -> None:
    """Trusted reputation should reduce risk contribution in unified scoring when policy suppression is disabled."""

    verdict = ScanVerdict(malware_status="malicious", malware_score=0.55)
    reputation_signals = [
        RiskSignal(
            source="reputation",
            name="trusted_package",
            value=1.0,
            weight=1.0,
            confidence=1.0,
            metadata={"trusted": True},
        )
    ]

    with (
        patch("app.services.scanner_service.settings.risk_policy_allowlist", ""),
        patch("app.services.scanner_service.settings.risk_policy_suppress_on_low_confidence", False),
        patch("app.services.scanner_service.settings.risk_policy_min_confidence", 0.0),
    ):
        assessment = build_package_risk_assessment(
            "requests",
            "2.31.0",
            "pypi",
            verdict,
            reputation_signals=reputation_signals,
        )

    assert assessment.overall_score is not None
    assert assessment.overall_score < 0.55
    assert assessment.metadata["scoring"]["breakdown"]["reputation"]["score"] == 0.0


def test_build_package_risk_assessment_explanation_mentions_suppression_reason() -> None:
    """Explanation should include explicit suppression reason for auditability."""

    verdict = ScanVerdict(malware_status="malicious", malware_score=0.85)

    with patch("app.services.scanner_service.settings.risk_policy_allowlist", "npm:left-pad@1.3.0"):
        assessment = build_package_risk_assessment("left-pad", "1.3.0", "npm", verdict)

    assert assessment.explanation is not None
    assert "suppression_reason=allowlist_match" in assessment.explanation
    assert "allowlisted=true" in assessment.explanation


def test_build_package_risk_assessment_includes_guardrail_signal_on_extraction_error() -> None:
    """Guardrail extraction errors should surface as explicit policy/telemetry signals."""

    verdict = ScanVerdict(
        malware_status="error",
        malware_score=None,
        error_message="GUARDRAIL_PATH_TRAVERSAL: member=../escape.js",
    )

    assessment = build_package_risk_assessment("pkg", "1.0.0", "npm", verdict)

    assert any(signal.source == "system-guardrail" for signal in assessment.policy_signals)
    assert "guardrail:path_traversal_blocked" in assessment.evidence
    assert assessment.metadata["guardrail"]["guardrail"] == "path_traversal_blocked"