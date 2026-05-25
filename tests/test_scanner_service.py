"""Tests for the scanner service (static analysis microservice wrapper)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.scanner_service import (
    ScanVerdict,
    _build_static_signals,
    analyze_package_static,
    build_package_risk_assessment,
)


def _make_stream_ctx(mock_resp: MagicMock) -> MagicMock:
    """Wrap a mock response in a MagicMock async context manager."""
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


def _make_ndjson_stream_resp(ndjson_lines: list[str]) -> MagicMock:
    """Return a mock streaming response that yields the given NDJSON lines."""
    mock_resp = MagicMock()
    mock_resp.is_error = False
    mock_resp.status_code = 200
    mock_resp.aread = AsyncMock()

    async def _aiter_lines():
        for line in ndjson_lines:
            yield line

    mock_resp.aiter_lines = _aiter_lines
    return mock_resp


# ── analyze_package_static ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_analyze_static_returns_error_when_url_not_configured():
    """Missing microservice URL returns an error verdict without making HTTP calls."""
    with patch("app.services.scanner_service.settings") as mock_settings:
        mock_settings.static_analysis_remote_url = ""
        result = await analyze_package_static("task-001", "lodash", "4.17.21", "npm")

    assert result.malware_status == "error"
    assert result.error_message is not None


@pytest.mark.asyncio
async def test_analyze_static_clean_verdict():
    """Microservice returning benign verdict maps to malware_status='clean'."""
    ndjson_line = json.dumps({
        "package_uuid": "task-001",
        "name": "lodash",
        "version": "4.17.21",
        "ecosystem": "npm",
        "status": "done",
        "verdict": "benign",
        "probability": 0.04,
        "features": {"eval_count": 0.0, "entropy": 3.2},
        "error": None,
    })

    mock_resp = _make_ndjson_stream_resp([ndjson_line])
    mock_client = MagicMock()
    mock_client.stream = MagicMock(return_value=_make_stream_ctx(mock_resp))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.services.scanner_service.settings") as mock_settings,
        patch("app.services.scanner_service.httpx.AsyncClient", return_value=mock_client),
    ):
        mock_settings.static_analysis_remote_url = "http://scanner:8000"
        mock_settings.static_analysis_timeout_seconds = 30
        result = await analyze_package_static("task-001", "lodash", "4.17.21", "npm")

    assert result.malware_status == "clean"
    assert result.malware_score == 0.04
    assert result.feature_snapshot == {"eval_count": 0.0, "entropy": 3.2}


@pytest.mark.asyncio
async def test_analyze_static_malicious_verdict():
    """Microservice returning malicious verdict maps to malware_status='malicious'."""
    ndjson_line = json.dumps({
        "package_uuid": "task-002",
        "name": "evil-pkg",
        "version": "1.0.0",
        "ecosystem": "npm",
        "status": "done",
        "verdict": "malicious",
        "probability": 0.93,
        "features": {},
        "error": None,
    })

    mock_resp = _make_ndjson_stream_resp([ndjson_line])
    mock_client = MagicMock()
    mock_client.stream = MagicMock(return_value=_make_stream_ctx(mock_resp))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.services.scanner_service.settings") as mock_settings,
        patch("app.services.scanner_service.httpx.AsyncClient", return_value=mock_client),
    ):
        mock_settings.static_analysis_remote_url = "http://scanner:8000"
        mock_settings.static_analysis_timeout_seconds = 30
        result = await analyze_package_static("task-002", "evil-pkg", "1.0.0", "npm")

    assert result.malware_status == "malicious"
    assert result.malware_score == 0.93


@pytest.mark.asyncio
async def test_analyze_static_submit_error_returns_error_verdict():
    """HTTP error on job submit maps to an error verdict."""
    mock_resp = MagicMock()
    mock_resp.is_error = True
    mock_resp.status_code = 503
    mock_resp.aread = AsyncMock()

    mock_client = MagicMock()
    mock_client.stream = MagicMock(return_value=_make_stream_ctx(mock_resp))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.services.scanner_service.settings") as mock_settings,
        patch("app.services.scanner_service.httpx.AsyncClient", return_value=mock_client),
    ):
        mock_settings.static_analysis_remote_url = "http://scanner:8000"
        mock_settings.static_analysis_timeout_seconds = 30
        result = await analyze_package_static("task-003", "lodash", "4.17.21", "npm")

    assert result.malware_status == "error"
    assert "503" in (result.error_message or "")


# ── _build_static_signals ─────────────────────────────────────────────


def test_build_static_signals_empty_snapshot_returns_empty():
    """No feature snapshot produces no signals and an empty context_markers dict."""
    signals, evidence, metadata = _build_static_signals(None)

    assert signals == []
    assert evidence == []
    assert metadata == {"context_markers": {}}


def test_build_static_signals_produces_expected_signal_names():
    """Non-empty feature snapshot always produces the five core static signals."""
    snapshot = {
        "max_entropy": 4.0,
        "avg_entropy": 3.5,
        "eval_count": 0.0,
        "exec_count": 0.0,
        "base64_count": 0.0,
        "network_imports": 1.0,
        "obfuscation_index": 0.5,
    }

    signals, _evidence, _metadata = _build_static_signals(snapshot)

    signal_names = [s.name for s in signals]
    assert "entropy_signal" in signal_names
    assert "obfuscation_signal" in signal_names
    assert "dynamic_code_signal" in signal_names
    assert "subprocess_signal" in signal_names
    assert "network_signal" in signal_names


def test_build_static_signals_minified_bundle_context_marker():
    """High entropy with no eval/exec should trigger likely_minified_bundle marker."""
    snapshot = {
        "max_entropy": 6.0,
        "avg_entropy": 5.5,
        "eval_count": 0.0,
        "exec_count": 0.0,
        "base64_count": 0.0,
        "network_imports": 1.0,
        "obfuscation_index": 0.0,
    }

    _signals, _evidence, metadata = _build_static_signals(snapshot)

    assert metadata["context_markers"]["likely_minified_bundle"] is True


# ── build_package_risk_assessment ─────────────────────────────────────


def test_build_risk_assessment_clean_verdict():
    """Clean verdict produces overall_status='clean'."""
    verdict = ScanVerdict(malware_status="clean", malware_score=0.05)

    with patch("app.services.scanner_service.settings") as mock_settings:
        mock_settings.risk_scoring_clean_max = 0.35
        mock_settings.risk_scoring_suspicious_max = 0.65
        mock_settings.risk_scoring_classifier_weight = 1.0
        mock_settings.risk_scoring_static_weight = 0.5
        mock_settings.risk_scoring_vulnerability_weight = 0.4
        mock_settings.risk_scoring_reputation_weight = 0.3
        mock_settings.risk_scoring_dynamic_weight = 0.6
        mock_settings.risk_policy_allowlist = ""
        mock_settings.risk_policy_suppress_on_low_confidence = False
        mock_settings.risk_policy_min_confidence = 0.1
        mock_settings.risk_policy_static_weight_scale = 1.0
        mock_settings.risk_policy_vulnerability_weight_scale = 1.0
        mock_settings.risk_policy_reputation_weight_scale = 1.0
        mock_settings.risk_policy_suppressed_score_ceiling = 0.2
        result = build_package_risk_assessment(
            "lodash", "4.17.21", "npm", verdict
        )

    assert result.overall_status == "clean"
    assert result.overall_score is not None
    assert result.overall_score < 0.5


def test_build_risk_assessment_malicious_verdict():
    """Malicious verdict produces overall_status='malicious'."""
    verdict = ScanVerdict(malware_status="malicious", malware_score=0.95)

    with patch("app.services.scanner_service.settings") as mock_settings:
        mock_settings.risk_scoring_clean_max = 0.35
        mock_settings.risk_scoring_suspicious_max = 0.65
        mock_settings.risk_scoring_classifier_weight = 1.0
        mock_settings.risk_scoring_static_weight = 0.5
        mock_settings.risk_scoring_vulnerability_weight = 0.4
        mock_settings.risk_scoring_reputation_weight = 0.3
        mock_settings.risk_scoring_dynamic_weight = 0.6
        mock_settings.risk_policy_allowlist = ""
        mock_settings.risk_policy_suppress_on_low_confidence = False
        mock_settings.risk_policy_min_confidence = 0.1
        mock_settings.risk_policy_static_weight_scale = 1.0
        mock_settings.risk_policy_vulnerability_weight_scale = 1.0
        mock_settings.risk_policy_reputation_weight_scale = 1.0
        mock_settings.risk_policy_suppressed_score_ceiling = 0.2
        result = build_package_risk_assessment(
            "evil-pkg", "1.0.0", "npm", verdict
        )

    assert result.overall_status == "malicious"


def test_build_risk_assessment_feature_snapshot_in_metadata():
    """feature_snapshot is preserved in the assessment metadata."""
    snapshot = {"eval_count": 2.0, "entropy": 5.8}
    verdict = ScanVerdict(
        malware_status="malicious", malware_score=0.9, feature_snapshot=snapshot
    )

    with patch("app.services.scanner_service.settings") as mock_settings:
        mock_settings.risk_scoring_clean_max = 0.35
        mock_settings.risk_scoring_suspicious_max = 0.65
        mock_settings.risk_scoring_classifier_weight = 1.0
        mock_settings.risk_scoring_static_weight = 0.5
        mock_settings.risk_scoring_vulnerability_weight = 0.4
        mock_settings.risk_scoring_reputation_weight = 0.3
        mock_settings.risk_scoring_dynamic_weight = 0.6
        mock_settings.risk_policy_allowlist = ""
        mock_settings.risk_policy_suppress_on_low_confidence = False
        mock_settings.risk_policy_min_confidence = 0.1
        mock_settings.risk_policy_static_weight_scale = 1.0
        mock_settings.risk_policy_vulnerability_weight_scale = 1.0
        mock_settings.risk_policy_reputation_weight_scale = 1.0
        mock_settings.risk_policy_suppressed_score_ceiling = 0.2
        result = build_package_risk_assessment(
            "evil-pkg", "1.0.0", "npm", verdict
        )

    assert result.metadata.get("feature_snapshot") == snapshot


def test_build_risk_assessment_dynamic_metadata_in_metadata():
    """dynamic_metadata is stored under metadata['dynamic']."""
    verdict = ScanVerdict(malware_status="malicious", malware_score=0.9)
    dynamic_meta = {
        "syscall_trace": ["execve"],
        "network_activity": [{"host": "evil.com"}],
    }

    with patch("app.services.scanner_service.settings") as mock_settings:
        mock_settings.risk_scoring_clean_max = 0.35
        mock_settings.risk_scoring_suspicious_max = 0.65
        mock_settings.risk_scoring_classifier_weight = 1.0
        mock_settings.risk_scoring_static_weight = 0.5
        mock_settings.risk_scoring_vulnerability_weight = 0.4
        mock_settings.risk_scoring_reputation_weight = 0.3
        mock_settings.risk_scoring_dynamic_weight = 0.6
        mock_settings.risk_policy_allowlist = ""
        mock_settings.risk_policy_suppress_on_low_confidence = False
        mock_settings.risk_policy_min_confidence = 0.1
        mock_settings.risk_policy_static_weight_scale = 1.0
        mock_settings.risk_policy_vulnerability_weight_scale = 1.0
        mock_settings.risk_policy_reputation_weight_scale = 1.0
        mock_settings.risk_policy_suppressed_score_ceiling = 0.2
        result = build_package_risk_assessment(
            "evil-pkg", "1.0.0", "npm", verdict, dynamic_metadata=dynamic_meta
        )

    assert result.metadata.get("dynamic") == dynamic_meta


def test_build_risk_assessment_allowlisted_package():
    """Allowlisted package is suppressed with score=0.0 regardless of verdict."""
    verdict = ScanVerdict(malware_status="malicious", malware_score=0.98)

    with patch("app.services.scanner_service.settings") as mock_settings:
        mock_settings.risk_scoring_clean_max = 0.35
        mock_settings.risk_scoring_suspicious_max = 0.65
        mock_settings.risk_scoring_classifier_weight = 1.0
        mock_settings.risk_scoring_static_weight = 0.5
        mock_settings.risk_scoring_vulnerability_weight = 0.4
        mock_settings.risk_scoring_reputation_weight = 0.3
        mock_settings.risk_scoring_dynamic_weight = 0.6
        mock_settings.risk_policy_allowlist = "evil-pkg"
        mock_settings.risk_policy_suppress_on_low_confidence = False
        mock_settings.risk_policy_min_confidence = 0.1
        mock_settings.risk_policy_static_weight_scale = 1.0
        mock_settings.risk_policy_vulnerability_weight_scale = 1.0
        mock_settings.risk_policy_reputation_weight_scale = 1.0
        mock_settings.risk_policy_suppressed_score_ceiling = 0.2
        result = build_package_risk_assessment(
            "evil-pkg", "1.0.0", "npm", verdict
        )

    assert result.allowlisted is True
    assert result.suppressed is True
    assert result.overall_score == 0.0
