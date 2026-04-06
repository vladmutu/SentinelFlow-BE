"""ML-based malware classifier wrapper.

Loads the pickled model and threshold once at import time and exposes a
synchronous ``classify`` function that can be called from async code via
``asyncio.to_thread``.
"""

from __future__ import annotations

import logging
import os
import tempfile
import zipfile
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.core.config import settings

logger = logging.getLogger(__name__)

SCANNER_VERSION = "1.0.0"

# ── Lazy-loaded globals ────────────────────────────────────────────────
_classifier: Any | None = None
_threshold: float | None = None


def _ensure_model_loaded() -> None:
    """Load the classifier and threshold from disk on first use."""
    global _classifier, _threshold
    if _classifier is not None:
        return

    model_path = Path(settings.scanner_model_path)
    threshold_path = Path(settings.scanner_threshold_path)

    if not model_path.exists():
        raise FileNotFoundError(f"Classifier model not found at {model_path}")
    if not threshold_path.exists():
        raise FileNotFoundError(f"Threshold file not found at {threshold_path}")

    _classifier = joblib.load(model_path)
    _threshold = joblib.load(threshold_path)
    logger.info("Loaded malware classifier from %s (threshold=%.4f)", model_path, _threshold)


@dataclass(frozen=True)
class ScanVerdict:
    """Result of running the ML classifier on a single package artifact."""

    malware_status: str  # "clean" | "malicious" | "error"
    malware_score: float | None
    scanner_version: str = SCANNER_VERSION
    error_message: str | None = None


def _extract_features_from_directory(package_dir: Path) -> np.ndarray:
    """Extract feature vector from an extracted package directory.

    This mirrors the feature-extraction pipeline the model was trained with.
    It walks the package directory, reads source files, and computes the
    features expected by the classifier.
    """
    features: dict[str, float] = {}

    all_files: list[Path] = []
    for root, _dirs, files in os.walk(package_dir):
        for fname in files:
            all_files.append(Path(root) / fname)

    features["file_count"] = float(len(all_files))

    js_files = [f for f in all_files if f.suffix in (".js", ".mjs", ".cjs")]
    py_files = [f for f in all_files if f.suffix == ".py"]
    json_files = [f for f in all_files if f.suffix == ".json"]

    features["js_file_count"] = float(len(js_files))
    features["py_file_count"] = float(len(py_files))
    features["json_file_count"] = float(len(json_files))

    total_size = 0
    total_lines = 0
    source_files = js_files + py_files

    has_install_scripts = 0.0
    has_network_calls = 0.0
    has_obfuscation = 0.0
    has_env_access = 0.0
    has_exec_calls = 0.0
    has_base64 = 0.0
    has_preinstall = 0.0
    has_postinstall = 0.0
    max_line_length = 0.0

    network_indicators = [
        "http://", "https://", "request(", "fetch(", "axios",
        "urllib", "requests.get", "requests.post", "socket",
        "XMLHttpRequest", "net.connect",
    ]
    obfuscation_indicators = [
        "\\x", "\\u00", "fromCharCode", "String.fromCharCode",
        "eval(", "Function(", "charAt", "charCodeAt",
    ]
    exec_indicators = [
        "exec(", "eval(", "subprocess", "child_process",
        "os.system", "os.popen", "spawn(", "execSync",
        "__import__",
    ]
    env_indicators = [
        "process.env", "os.environ", "os.getenv", "getenv",
    ]
    base64_indicators = [
        "atob(", "btoa(", "base64", "b64decode", "b64encode",
    ]

    for sf in source_files:
        try:
            content = sf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        total_size += len(content)
        lines = content.splitlines()
        total_lines += len(lines)

        for line in lines:
            if len(line) > max_line_length:
                max_line_length = float(len(line))

        content_lower = content.lower()

        for ind in network_indicators:
            if ind.lower() in content_lower:
                has_network_calls = 1.0
                break
        for ind in obfuscation_indicators:
            if ind.lower() in content_lower:
                has_obfuscation = 1.0
                break
        for ind in exec_indicators:
            if ind.lower() in content_lower:
                has_exec_calls = 1.0
                break
        for ind in env_indicators:
            if ind.lower() in content_lower:
                has_env_access = 1.0
                break
        for ind in base64_indicators:
            if ind.lower() in content_lower:
                has_base64 = 1.0
                break

    # Check for install scripts in package.json
    for jf in json_files:
        if jf.name == "package.json":
            try:
                import json
                pkg = json.loads(jf.read_text(encoding="utf-8", errors="ignore"))
                scripts = pkg.get("scripts", {})
                if isinstance(scripts, dict):
                    if "preinstall" in scripts:
                        has_preinstall = 1.0
                    if "postinstall" in scripts:
                        has_postinstall = 1.0
                    if "install" in scripts:
                        has_install_scripts = 1.0
            except Exception:
                pass

    # Check for setup.py install hooks in Python packages
    for pf in py_files:
        if pf.name == "setup.py":
            try:
                content = pf.read_text(encoding="utf-8", errors="ignore")
                if "cmdclass" in content:
                    has_install_scripts = 1.0
            except Exception:
                pass

    features["total_source_size"] = float(total_size)
    features["total_source_lines"] = float(total_lines)
    features["avg_line_length"] = float(total_size / max(total_lines, 1))
    features["max_line_length"] = max_line_length
    features["has_install_scripts"] = has_install_scripts
    features["has_preinstall"] = has_preinstall
    features["has_postinstall"] = has_postinstall
    features["has_network_calls"] = has_network_calls
    features["has_obfuscation"] = has_obfuscation
    features["has_exec_calls"] = has_exec_calls
    features["has_env_access"] = has_env_access
    features["has_base64"] = has_base64

    # Build the final feature vector in the order the model expects.
    feature_names = sorted(features.keys())
    vector = np.array([[features[fn] for fn in feature_names]])
    return vector


def _extract_archive(archive_path: Path, dest_dir: Path) -> Path:
    """Extract a .tgz / .tar.gz / .zip / .whl archive and return the root folder."""
    archive_str = str(archive_path)
    if tarfile.is_tarfile(archive_str):
        with tarfile.open(archive_str, "r:*") as tf:
            tf.extractall(dest_dir, filter="data")
    elif zipfile.is_zipfile(archive_str):
        with zipfile.ZipFile(archive_str, "r") as zf:
            zf.extractall(dest_dir)
    else:
        raise ValueError(f"Unsupported archive format: {archive_path.name}")

    # Return the first child directory if there is exactly one (common for tarballs).
    children = list(dest_dir.iterdir())
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest_dir


def classify(artifact_path: Path) -> ScanVerdict:
    """Run the ML classifier on a package artifact (archive or directory).

    This is a **blocking** function.  Call via ``asyncio.to_thread`` from
    async code so the event loop isn't stalled.
    """
    try:
        _ensure_model_loaded()
    except FileNotFoundError as exc:
        return ScanVerdict(
            malware_status="error",
            malware_score=None,
            error_message=str(exc),
        )

    try:
        # If the artifact is an archive, extract it first.
        if artifact_path.is_file():
            tmp_extract = Path(tempfile.mkdtemp(prefix="sentinel_extract_"))
            try:
                package_dir = _extract_archive(artifact_path, tmp_extract)
                features = _extract_features_from_directory(package_dir)
            finally:
                import shutil
                shutil.rmtree(tmp_extract, ignore_errors=True)
        elif artifact_path.is_dir():
            features = _extract_features_from_directory(artifact_path)
        else:
            return ScanVerdict(
                malware_status="error",
                malware_score=None,
                error_message=f"Artifact not found: {artifact_path}",
            )

        probabilities = _classifier.predict_proba(features)[0]
        malware_prob = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])

        status = "malicious" if malware_prob >= _threshold else "clean"

        return ScanVerdict(
            malware_status=status,
            malware_score=round(malware_prob, 6),
        )

    except Exception as exc:
        logger.exception("Classifier error for %s", artifact_path)
        return ScanVerdict(
            malware_status="error",
            malware_score=None,
            error_message=str(exc),
        )
