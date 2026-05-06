"""Tests for reputation service."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timezone

from app.services.reputation_service import (
    _days_since,
    ReputationLookupResult,
)


class TestDaysSince:
    """Tests for ISO date parsing helper."""

    def test_valid_iso_date(self):
        result = _days_since("2020-01-01T00:00:00Z")
        assert result is not None
        assert result > 0

    def test_none_input(self):
        assert _days_since(None) is None

    def test_empty_string(self):
        assert _days_since("") is None

    def test_invalid_date(self):
        assert _days_since("not-a-date") is None


class TestReputationLookup:
    """Tests for the reputation lookup flow."""

    @pytest.mark.asyncio
    async def test_disabled_returns_empty(self):
        """When disabled, should return empty result."""
        with patch("app.services.reputation_service.settings") as mock_settings:
            mock_settings.reputation_lookup_enabled = False
            from app.services.reputation_service import lookup_package_reputation
            result = await lookup_package_reputation("npm", "lodash", "4.17.21")
            assert isinstance(result, ReputationLookupResult)
            assert len(result.signals) == 0
            assert result.metadata.get("lookup_enabled") is False

    @pytest.mark.asyncio
    async def test_trusted_package_signal(self):
        """Packages with high downloads and old age should get trusted signal."""
        from app.services.reputation_service import _fetch_npm_reputation
        import httpx

        mock_client = AsyncMock(spec=httpx.AsyncClient)

        # Mock npm registry response
        registry_response = MagicMock()
        registry_response.is_error = False
        registry_response.json.return_value = {
            "maintainers": [{"name": "user1"}, {"name": "user2"}],
            "repository": {"url": "https://github.com/test/test"},
            "license": "MIT",
            "time": {
                "created": "2015-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
            },
        }

        # Mock downloads response
        downloads_response = MagicMock()
        downloads_response.is_error = False
        downloads_response.json.return_value = {"downloads": 500_000}

        mock_client.get = AsyncMock(side_effect=[registry_response, downloads_response])

        result = await _fetch_npm_reputation(mock_client, "lodash", "4.17.21")

        # Should have trusted_package signal
        signal_names = [s.name for s in result.signals]
        assert "trusted_package" in signal_names

    @pytest.mark.asyncio
    async def test_single_maintainer_signal(self):
        """Packages with one maintainer should get single_maintainer signal."""
        from app.services.reputation_service import _fetch_npm_reputation
        import httpx

        mock_client = AsyncMock(spec=httpx.AsyncClient)

        registry_response = MagicMock()
        registry_response.is_error = False
        registry_response.json.return_value = {
            "maintainers": [{"name": "solo-dev"}],
            "repository": {"url": "https://github.com/test/test"},
            "license": "MIT",
            "time": {"created": "2023-01-01T00:00:00.000Z"},
        }

        downloads_response = MagicMock()
        downloads_response.is_error = False
        downloads_response.json.return_value = {"downloads": 50}

        mock_client.get = AsyncMock(side_effect=[registry_response, downloads_response])

        result = await _fetch_npm_reputation(mock_client, "test-pkg", "1.0.0")

        signal_names = [s.name for s in result.signals]
        assert "single_maintainer" in signal_names

    @pytest.mark.asyncio
    async def test_no_repository_signal(self):
        """Packages without a repository should get no_repository_link signal."""
        from app.services.reputation_service import _fetch_npm_reputation
        import httpx

        mock_client = AsyncMock(spec=httpx.AsyncClient)

        registry_response = MagicMock()
        registry_response.is_error = False
        registry_response.json.return_value = {
            "maintainers": [{"name": "dev1"}, {"name": "dev2"}],
            "license": "MIT",
            "time": {"created": "2023-01-01T00:00:00.000Z"},
        }

        downloads_response = MagicMock()
        downloads_response.is_error = False
        downloads_response.json.return_value = {"downloads": 1000}

        mock_client.get = AsyncMock(side_effect=[registry_response, downloads_response])

        result = await _fetch_npm_reputation(mock_client, "no-repo-pkg", "1.0.0")

        signal_names = [s.name for s in result.signals]
        assert "no_repository_link" in signal_names

    @pytest.mark.asyncio
    async def test_graceful_registry_error(self):
        """Should handle registry errors gracefully."""
        from app.services.reputation_service import _fetch_npm_reputation
        import httpx

        mock_client = AsyncMock(spec=httpx.AsyncClient)

        error_response = MagicMock()
        error_response.is_error = True
        error_response.status_code = 503

        mock_client.get = AsyncMock(return_value=error_response)

        result = await _fetch_npm_reputation(mock_client, "test", "1.0.0")
        assert isinstance(result, ReputationLookupResult)
        assert result.metadata.get("registry_error") == 503
