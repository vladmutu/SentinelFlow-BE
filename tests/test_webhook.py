"""Tests for GitHub webhook handler."""

import hashlib
import hmac
import json

import pytest
from unittest.mock import patch

from app.api.endpoints.webhook import _verify_signature, _detect_manifest_changes


class TestVerifySignature:
    """Tests for HMAC-SHA256 webhook signature verification."""

    def test_skips_verification_with_placeholder_secret(self):
        """Should skip verification when no real secret is configured."""
        with patch("app.api.endpoints.webhook.settings") as mock_settings:
            mock_settings.github_webhook_secret = "placeholder-webhook-secret-change-me"
            assert _verify_signature(b"test", None) is True

    def test_rejects_missing_signature(self):
        """Should reject when signature header is missing and a real secret is set."""
        with patch("app.api.endpoints.webhook.settings") as mock_settings:
            mock_settings.github_webhook_secret = "real-secret-123"
            assert _verify_signature(b"test", None) is False

    def test_rejects_invalid_prefix(self):
        """Should reject signatures without sha256= prefix."""
        with patch("app.api.endpoints.webhook.settings") as mock_settings:
            mock_settings.github_webhook_secret = "real-secret-123"
            assert _verify_signature(b"test", "sha1=abc") is False

    def test_accepts_valid_signature(self):
        """Should accept a valid HMAC-SHA256 signature."""
        secret = "test-webhook-secret"
        body = b'{"action": "push"}'
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        with patch("app.api.endpoints.webhook.settings") as mock_settings:
            mock_settings.github_webhook_secret = secret
            assert _verify_signature(body, f"sha256={expected}") is True

    def test_rejects_invalid_signature(self):
        """Should reject an incorrect signature."""
        with patch("app.api.endpoints.webhook.settings") as mock_settings:
            mock_settings.github_webhook_secret = "test-secret"
            assert _verify_signature(b"test", "sha256=invalid") is False


class TestDetectManifestChanges:
    """Tests for manifest change detection in push events."""

    def test_detects_npm_package_json(self):
        commits = [{"added": ["package.json"], "modified": [], "removed": []}]
        result = _detect_manifest_changes(commits)
        assert "npm" in result

    def test_detects_npm_lockfile(self):
        commits = [{"added": [], "modified": ["package-lock.json"], "removed": []}]
        result = _detect_manifest_changes(commits)
        assert "npm" in result

    def test_detects_pypi_requirements(self):
        commits = [{"added": [], "modified": ["requirements.txt"], "removed": []}]
        result = _detect_manifest_changes(commits)
        assert "pypi" in result

    def test_detects_pypi_pyproject(self):
        commits = [{"added": ["pyproject.toml"], "modified": [], "removed": []}]
        result = _detect_manifest_changes(commits)
        assert "pypi" in result

    def test_ignores_non_manifest_files(self):
        commits = [{"added": ["README.md", "src/index.js"], "modified": [], "removed": []}]
        result = _detect_manifest_changes(commits)
        assert len(result) == 0

    def test_detects_nested_manifest(self):
        commits = [{"added": [], "modified": ["frontend/package.json"], "removed": []}]
        result = _detect_manifest_changes(commits)
        assert "npm" in result

    def test_detects_both_ecosystems(self):
        commits = [
            {"added": ["package.json"], "modified": ["requirements.txt"], "removed": []},
        ]
        result = _detect_manifest_changes(commits)
        assert "npm" in result
        assert "pypi" in result

    def test_handles_empty_commits(self):
        result = _detect_manifest_changes([])
        assert len(result) == 0

    def test_handles_invalid_commit_data(self):
        result = _detect_manifest_changes([{"invalid": True}])
        assert len(result) == 0
