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
import pandas as pd

from app.core.config import settings

logger = logging.getLogger(__name__)

SCANNER_VERSION = "1.0.0"

# ── Lazy-loaded globals ────────────────────────────────────────────────
_classifier: Any | None = None
_threshold: float | None = None

MODEL_FEATURE_COLUMNS: tuple[str, ...] = (
    "max_entropy",
    "avg_entropy",
    "eval_count",
    "exec_count",
    "base64_count",
    "network_imports",
    "entropy_gap",
    "exec_eval_ratio",
    "network_exec_ratio",
    "obfuscation_index",
)


def _resolve_threshold(artifact: Any) -> float:
    """Normalize threshold artifact loaded from disk into a float.

    Supports either a raw float or a dict such as
    ``{"threshold": 0.42}``.
    """
    if isinstance(artifact, (int, float)):
        return float(artifact)
    if isinstance(artifact, dict) and "threshold" in artifact:
        raw = artifact["threshold"]
        if isinstance(raw, (int, float)):
            return float(raw)
    raise ValueError("Invalid threshold artifact; expected float or {'threshold': float}")


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
    _threshold = _resolve_threshold(joblib.load(threshold_path))
    logger.info("Loaded malware classifier from %s (threshold=%.4f)", model_path, _threshold)


@dataclass(frozen=True)
class ScanVerdict:
    """Result of running the ML classifier on a single package artifact."""

    malware_status: str  # "clean" | "malicious" | "error"
    malware_score: float | None
    scanner_version: str = SCANNER_VERSION
    error_message: str | None = None


def _extract_features_from_directory(package_dir: Path) -> pd.DataFrame:
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
        return ScanVerdict(malware_status=status, malware_score=round(malware_prob, 6))
    except Exception as exc:
        logger.exception("Classifier inference error")
        return ScanVerdict(
            malware_status="error",
            malware_score=None,
            error_message=str(exc),
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
