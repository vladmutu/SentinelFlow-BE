"""Tests for dynamic-analysis boundary behavior."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import dynamic_analysis_service


@pytest.mark.asyncio
async def test_dynamic_analysis_disabled_returns_explicit_skip() -> None:
    """Disabled dynamic analysis should produce explicit no-coverage telemetry."""

    with patch.object(dynamic_analysis_service.settings, "dynamic_analysis_enabled", False):
        result = await dynamic_analysis_service.analyze_package_dynamically(
            "npm",
            "lodash",
            "4.17.21",
            Path("C:/tmp/lodash.tgz"),
        )

    assert result.metadata["status"] == "skipped"
    assert result.metadata["coverage"] == "none"
    assert result.metadata["executed_on_api_host"] is False
    assert "dynamic:skipped:disabled" in result.evidence


@pytest.mark.asyncio
async def test_dynamic_analysis_timeout_returns_partial_coverage() -> None:
    """Remote timeout should be surfaced as partial dynamic coverage telemetry."""

    with (
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_enabled", True),
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_mode", "remote"),
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_remote_url", "https://sandbox.example/analyze"),
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_timeout_seconds", 5),
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_fail_open", True),
        patch("app.services.dynamic_analysis_service.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=dynamic_analysis_service.httpx.TimeoutException("timeout"))
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        result = await dynamic_analysis_service.analyze_package_dynamically(
            "npm",
            "pkg",
            "1.0.0",
            Path("C:/tmp/pkg.tgz"),
        )

    assert result.metadata["status"] == "partial"
    assert result.metadata["coverage"] == "partial"
    assert result.metadata["reason"] == "timeout"
    assert "dynamic:partial:timeout" in result.evidence


@pytest.mark.asyncio
async def test_dynamic_analysis_remote_success_normalizes_payload() -> None:
    """Remote sandbox response should be normalized into risk signals and telemetry."""

    payload = {
        "status": "completed",
        "coverage": "full",
        "risk_score": 0.62,
        "provider": "sandbox-x",
        "job_id": "job-123",
        "timed_out": False,
        "vm_evasion_observed": True,
    }

    with (
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_enabled", True),
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_mode", "remote"),
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_remote_url", "https://sandbox.example/analyze"),
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_fail_open", True),
        patch("app.services.dynamic_analysis_service.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = payload
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        result = await dynamic_analysis_service.analyze_package_dynamically(
            "pypi",
            "requests",
            "2.31.0",
            Path("C:/tmp/requests.whl"),
        )

    signal_names = {signal.name for signal in result.signals}
    assert "dynamic_behavior_risk" in signal_names
    assert "vm_evasion_observed" in signal_names
    assert result.metadata["status"] == "completed"
    assert result.metadata["coverage"] == "full"
    assert result.metadata["executed_on_api_host"] is False


@pytest.mark.asyncio
async def test_dynamic_analysis_remote_success_uses_cache() -> None:
    """Repeated calls for same package identity should reuse cached dynamic result."""

    dynamic_analysis_service._dynamic_cache.clear()
    payload = {
        "status": "completed",
        "coverage": "full",
        "risk_score": 0.3,
        "provider": "sandbox-x",
        "job_id": "job-777",
        "timed_out": False,
    }

    with (
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_enabled", True),
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_mode", "remote"),
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_remote_url", "https://sandbox.example/analyze"),
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_cache_ttl_seconds", 1800),
        patch("app.services.dynamic_analysis_service.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.is_error = False
        mock_response.json.return_value = payload
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        first = await dynamic_analysis_service.analyze_package_dynamically(
            "npm",
            "lodash",
            "4.17.21",
            Path("C:/tmp/lodash.tgz"),
        )
        second = await dynamic_analysis_service.analyze_package_dynamically(
            "npm",
            "lodash",
            "4.17.21",
            Path("C:/tmp/lodash.tgz"),
        )

    assert first is second
    mock_client.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_dynamic_analysis_rejects_insecure_non_local_remote_url() -> None:
    """Remote sandbox URLs must be isolated (https or localhost-only dev exception)."""

    with (
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_enabled", True),
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_mode", "remote"),
        patch.object(dynamic_analysis_service.settings, "dynamic_analysis_remote_url", "http://sandbox.example/analyze"),
    ):
        result = await dynamic_analysis_service.analyze_package_dynamically(
            "npm",
            "lodash",
            "4.17.21",
            Path("C:/tmp/lodash.tgz"),
        )

    assert result.metadata["status"] == "skipped"
    assert result.metadata["reason"] == "insecure_remote_url"
    assert result.metadata["sandbox_isolation_enforced"] is True
