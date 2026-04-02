"""
Malware Scanner Service

This service integrates a pre-trained Random Forest model to classify software packages
and dependencies as benign or malicious based on static code analysis features.

Features analyzed:
- Abstract Syntax Tree (AST) patterns: eval/exec calls, network imports, dangerous functions
- Shannon Entropy: compression-based indicator of code obfuscation
- Engineered features: entropy gaps, execution ratios, obfuscation indices
"""

import ast
import logging
import re
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
import esprima

logger = logging.getLogger(__name__)

# Constants
NETWORK_MODULE_PREFIXES = ("requests", "socket", "urllib")
MAX_AST_FILE_SIZE = 1_000_000
MAX_ARCHIVE_MEMBERS = 10_000
MAX_SINGLE_MEMBER_BYTES = 50 * 1024 * 1024
MAX_TOTAL_EXTRACTED_BYTES = 500 * 1024 * 1024
MODEL_PATH = Path(__file__).parent.parent.parent / "malware_classifier.pkl"
THRESHOLD_PATH = Path(__file__).parent.parent.parent / "malware_threshold.pkl"
SUPPORTED_ARCHIVE_EXTENSIONS = (".zip", ".whl", ".tar", ".tar.gz", ".tgz")
ZIP_PASSWORD_CANDIDATES = (b"infected",)
WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *{f"com{i}" for i in range(1, 10)},
    *{f"lpt{i}" for i in range(1, 10)},
}


def _init_feature_counts() -> dict[str, int]:
    """Initialize feature counter dictionary."""
    return {
        "eval_count": 0,
        "exec_count": 0,
        "base64_count": 0,
        "network_imports": 0,
        "settimeout_string_count": 0,
        "child_process_count": 0,
        "buffer_count": 0,
    }


def calculate_shannon_entropy(file_bytes: bytes) -> float:
    """
    Compute Shannon entropy in bits/byte for a byte sequence.
    
    Returns a value in [0, 8]. Empty input returns 0.0.
    """
    if not file_bytes:
        return 0.0

    values = np.frombuffer(file_bytes, dtype=np.uint8)
    counts = np.bincount(values, minlength=256)
    probabilities = counts[counts > 0] / values.size
    entropy = float(-np.sum(probabilities * np.log2(probabilities)))

    # Clamp to valid range
    return min(max(entropy, 0.0), 8.0)


class _PythonDangerVisitor(ast.NodeVisitor):
    """AST visitor for detecting dangerous patterns in Python code."""

    def __init__(self) -> None:
        self.counts = _init_feature_counts()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            imported = alias.name
            if imported.startswith(NETWORK_MODULE_PREFIXES):
                self.counts["network_imports"] += 1
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if module.startswith(NETWORK_MODULE_PREFIXES):
            self.counts["network_imports"] += 1
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name):
            if func.id == "eval":
                self.counts["eval_count"] += 1
            elif func.id == "exec":
                self.counts["exec_count"] += 1
            elif func.id == "__import__":
                self.counts["network_imports"] += 1
        elif isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                if func.value.id == "base64" and func.attr == "b64decode":
                    self.counts["base64_count"] += 1

        self.generic_visit(node)


def _merge_counts(target: dict[str, int], source: dict[str, int]) -> None:
    """Merge feature counts from source into target."""
    for key, value in source.items():
        target[key] = target.get(key, 0) + value


def _sanitize_path_component(component: str) -> str:
    """Make an archive path component safe on Windows and POSIX."""
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", component).strip().strip(".")
    if not cleaned or cleaned in {".", ".."}:
        cleaned = "_"

    if cleaned.lower() in WINDOWS_RESERVED_NAMES:
        cleaned = f"_{cleaned}"

    return cleaned


def _safe_member_path(base_dir: Path, member_name: str) -> Path:
    """Return a normalized extraction path rooted inside base_dir."""
    normalized_name = member_name.replace("\\", "/")
    parts = [part for part in normalized_name.split("/") if part not in {"", ".", ".."}]
    sanitized_parts = [_sanitize_path_component(part) for part in parts]

    if not sanitized_parts:
        raise ValueError(f"Unsafe archive member path: {member_name}")

    destination_path = (base_dir.joinpath(*sanitized_parts)).resolve()
    base_resolved = base_dir.resolve()
    try:
        destination_path.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError(f"Blocked path traversal attempt: {member_name}") from exc
    return destination_path


def _safe_read_text(file_path: Path) -> str:
    """Safely read file content with fallback to empty string."""
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _fast_scan_python_text(source: str) -> dict[str, int]:
    """Fast regex-based scan for Python files (fallback for large files)."""
    counts = _init_feature_counts()
    if not source:
        return counts

    counts["eval_count"] = source.count("eval(")
    counts["exec_count"] = source.count("exec(")
    counts["base64_count"] = source.count("base64.b64decode(")

    network_patterns = (
        "import requests",
        "from requests",
        "import socket",
        "from socket",
        "import urllib",
        "from urllib",
    )
    counts["network_imports"] = sum(source.count(pattern) for pattern in network_patterns)
    return counts


def _fast_scan_javascript_text(source: str) -> dict[str, int]:
    """Fast regex-based scan for JavaScript files (fallback for large files)."""
    counts = _init_feature_counts()
    if not source:
        return counts

    counts["eval_count"] = source.count("eval(")

    settimeout_count = source.count("setTimeout(")
    child_process_count = (
        source.count("require('child_process')")
        + source.count('require("child_process")')
    )

    counts["settimeout_string_count"] = settimeout_count
    counts["child_process_count"] = child_process_count
    counts["exec_count"] = settimeout_count + child_process_count
    counts["buffer_count"] = source.count("Buffer")
    return counts


def _is_js_string_literal(node) -> bool:
    """Check if a JavaScript AST node is a string literal."""
    if node is None:
        return False

    node_type = getattr(node, "type", "")
    if node_type == "Literal":
        value = getattr(node, "value", None)
        return isinstance(value, str)
    if node_type == "TemplateLiteral":
        expressions = getattr(node, "expressions", []) or []
        return len(expressions) == 0
    return False


def _walk_js(node, counts: dict[str, int]) -> None:
    """Recursively walk JavaScript AST to detect dangerous patterns."""
    if node is None:
        return

    if isinstance(node, list):
        for item in node:
            _walk_js(item, counts)
        return

    node_type = getattr(node, "type", None)
    if not node_type:
        return

    if node_type == "CallExpression":
        callee = getattr(node, "callee", None)
        args = getattr(node, "arguments", []) or []

        if getattr(callee, "type", "") == "Identifier":
            name = getattr(callee, "name", "")
            if name == "eval":
                counts["eval_count"] += 1
            elif name == "setTimeout" and args and _is_js_string_literal(args[0]):
                counts["settimeout_string_count"] += 1
                counts["exec_count"] += 1
            elif name == "require" and args:
                first_arg = args[0]
                if getattr(first_arg, "type", "") == "Literal" and getattr(
                    first_arg, "value", None
                ) == "child_process":
                    counts["child_process_count"] += 1
                    counts["exec_count"] += 1

    if node_type == "Identifier" and getattr(node, "name", "") == "Buffer":
        counts["buffer_count"] += 1

    for value in vars(node).values():
        if isinstance(value, list):
            for item in value:
                _walk_js(item, counts)
        elif hasattr(value, "type"):
            _walk_js(value, counts)


def analyze_python_file(file_path: Path) -> dict[str, int]:
    """Parse Python file and extract dangerous pattern counts."""
    try:
        if file_path.stat().st_size > MAX_AST_FILE_SIZE:
            source = _safe_read_text(file_path)
            return _fast_scan_python_text(source)
    except OSError:
        return _init_feature_counts()

    try:
        source = _safe_read_text(file_path)
        if not source:
            return _init_feature_counts()
        tree = ast.parse(source)
    except Exception:
        return _init_feature_counts()

    visitor = _PythonDangerVisitor()
    visitor.visit(tree)
    return visitor.counts


def analyze_javascript_file(file_path: Path) -> dict[str, int]:
    """Parse JavaScript file and extract dangerous pattern counts."""
    counts = _init_feature_counts()
    try:
        if file_path.stat().st_size > MAX_AST_FILE_SIZE:
            source = _safe_read_text(file_path)
            return _fast_scan_javascript_text(source)
    except OSError:
        return counts

    try:
        source = _safe_read_text(file_path)
        if not source:
            return counts
    except Exception:
        return counts

    parsed = None
    try:
        parsed = esprima.parseScript(source, tolerant=True)
    except Exception:
        try:
            parsed = esprima.parseModule(source, tolerant=True)
        except Exception:
            return counts

    _walk_js(parsed, counts)
    return counts


def analyze_code_files(file_paths: list[Path]) -> dict[str, int]:
    """Analyze a collection of code files and aggregate features."""
    totals = _init_feature_counts()

    for file_path in file_paths:
        suffix = file_path.suffix.lower()
        if suffix == ".py":
            counts = analyze_python_file(file_path)
            _merge_counts(totals, counts)
        elif suffix == ".js":
            counts = analyze_javascript_file(file_path)
            _merge_counts(totals, counts)

    return totals


def _is_supported_archive(archive_path: Path) -> bool:
    """Check whether the archive extension is supported."""
    archive_name = archive_path.name.lower()
    return archive_name.endswith(SUPPORTED_ARCHIVE_EXTENSIONS)


def _is_tar_archive(archive_path: Path) -> bool:
    """Check whether the archive should be handled as a tar archive."""
    archive_name = archive_path.name.lower()
    return archive_name.endswith((".tar", ".tar.gz", ".tgz"))


def _extract_zip_member(archive: zipfile.ZipFile, member: zipfile.ZipInfo) -> bytes:
    """Read a ZIP member, trying known passwords for encrypted archives."""
    if not (member.flag_bits & 0x1):
        with archive.open(member, "r") as source:
            return source.read()

    for password in ZIP_PASSWORD_CANDIDATES:
        try:
            with archive.open(member, "r", pwd=password) as source:
                return source.read()
        except RuntimeError:
            continue

    raise RuntimeError(f"Encrypted ZIP member could not be extracted: {member.filename}")


def _check_extraction_budget(member_count: int, total_bytes: int) -> None:
    """Abort extraction if the archive exceeds safety budgets."""
    if member_count > MAX_ARCHIVE_MEMBERS:
        raise ValueError(f"Archive contains too many files: {member_count}")
    if total_bytes > MAX_TOTAL_EXTRACTED_BYTES:
        raise ValueError(f"Archive is too large after extraction: {total_bytes} bytes")


def _extract_zip_safely(archive_path: Path, destination_dir: Path) -> None:
    """Extract ZIP/WHL archives with path traversal protection."""
    with zipfile.ZipFile(archive_path, "r") as archive:
        _check_extraction_budget(len(archive.infolist()), sum(info.file_size for info in archive.infolist() if not info.is_dir()))

        for member in archive.infolist():
            destination_path = _safe_member_path(destination_dir, member.filename)

            if member.is_dir():
                destination_path.mkdir(parents=True, exist_ok=True)
                continue

            if member.file_size > MAX_SINGLE_MEMBER_BYTES:
                raise ValueError(f"Archive member is too large: {member.filename}")

            destination_path.parent.mkdir(parents=True, exist_ok=True)
            data = _extract_zip_member(archive, member)
            if len(data) > MAX_SINGLE_MEMBER_BYTES:
                raise ValueError(f"Archive member is too large: {member.filename}")
            destination_path.write_bytes(data)


def _extract_tar_safely(archive_path: Path, destination_dir: Path) -> None:
    """Extract TAR archives with path traversal protection and no links."""
    with tarfile.open(archive_path, "r:*") as archive:
        members = archive.getmembers()
        _check_extraction_budget(len(members), sum(member.size for member in members if member.isfile()))

        for member in archive.getmembers():
            destination_path = _safe_member_path(destination_dir, member.name)

            if member.isdir():
                destination_path.mkdir(parents=True, exist_ok=True)
                continue

            # Skip symlinks and hard links to avoid link traversal attacks.
            if not member.isfile():
                continue

            if member.size > MAX_SINGLE_MEMBER_BYTES:
                raise ValueError(f"Archive member is too large: {member.name}")

            source = archive.extractfile(member)
            if source is None:
                continue

            destination_path.parent.mkdir(parents=True, exist_ok=True)
            data = source.read()
            if len(data) > MAX_SINGLE_MEMBER_BYTES:
                raise ValueError(f"Archive member is too large: {member.name}")
            destination_path.write_bytes(data)


def _extract_archive_safely(archive_path: Path, destination_dir: Path) -> None:
    """Extract supported archives into destination_dir using safe extractors."""
    archive_name = archive_path.name.lower()
    if archive_name.endswith((".zip", ".whl")):
        _extract_zip_safely(archive_path, destination_dir)
        return

    if _is_tar_archive(archive_path):
        _extract_tar_safely(archive_path, destination_dir)
        return

    raise ValueError(f"Unsupported archive format: {archive_path.name}")


def calculate_package_entropy(archive_path: Path) -> tuple[float, float]:
    """
    Calculate Shannon entropy statistics for all files in an extracted package tree.
    
    Returns: (max_entropy, average_entropy)
    """
    entropies = []

    try:
        for file_path in archive_path.rglob("*"):
            if not file_path.is_file():
                continue
            try:
                data = file_path.read_bytes()
                entropies.append(calculate_shannon_entropy(data))
            except Exception:
                continue
    except Exception:
        return 0.0, 0.0

    if entropies:
        return max(entropies), sum(entropies) / len(entropies)
    return 0.0, 0.0


class MalwareScannerService:
    """Service for malware classification using Random Forest model."""

    def __init__(self):
        """Initialize the scanner service by loading the pre-trained model and threshold."""
        self.model = None
        self.optimal_threshold = 0.5
        self._load_model()

    def _load_model(self) -> None:
        """Load pre-trained model and optimal classification threshold."""
        try:
            if MODEL_PATH.exists():
                self.model = joblib.load(str(MODEL_PATH))
                logger.info(f"Loaded malware classifier model from {MODEL_PATH}")
            else:
                logger.warning(f"Model file not found at {MODEL_PATH}")

            if THRESHOLD_PATH.exists():
                threshold_data = joblib.load(str(THRESHOLD_PATH))
                self.optimal_threshold = (
                    threshold_data
                    if isinstance(threshold_data, float)
                    else threshold_data.get("threshold", 0.5)
                )
                logger.info(f"Loaded optimal threshold: {self.optimal_threshold}")
        except Exception as e:
            logger.error(f"Error loading model artifacts: {e}")

    def extract_features_from_directory(
        self, directory_path: Path, archive_path: Optional[Path] = None
    ) -> dict[str, float]:
        """
        Extract both AST and entropy features from a package directory.
        
        Args:
            directory_path: Path to extracted package directory
            archive_path: Optional path to original archive for entropy calculation
            
        Returns:
            Dictionary containing all features for model inference
        """
        # Collect all code files
        code_files = list(directory_path.rglob("*.py")) + list(directory_path.rglob("*.js"))

        # Extract AST-based features
        ast_features = analyze_code_files(code_files)

        # Calculate entropy statistics
        max_entropy = 0.0
        avg_entropy = 0.0
        if directory_path.exists():
            max_entropy, avg_entropy = calculate_package_entropy(directory_path)

        # Engineer additional features (as per training pipeline)
        entropy_gap = max_entropy - avg_entropy
        exec_eval_ratio = (ast_features["exec_count"] + 1) / (ast_features["eval_count"] + 1)
        network_exec_ratio = (ast_features["network_imports"] + 1) / (
            ast_features["exec_count"] + 1
        )
        obfuscation_index = entropy_gap * np.log1p(ast_features["base64_count"])

        return {
            # Raw AST features
            "eval_count": float(ast_features["eval_count"]),
            "exec_count": float(ast_features["exec_count"]),
            "base64_count": float(ast_features["base64_count"]),
            "network_imports": float(ast_features["network_imports"]),
            # Entropy features
            "max_entropy": float(max_entropy),
            "avg_entropy": float(avg_entropy),
            # Engineered features
            "entropy_gap": float(entropy_gap),
            "exec_eval_ratio": float(exec_eval_ratio),
            "network_exec_ratio": float(network_exec_ratio),
            "obfuscation_index": float(obfuscation_index),
        }

    def predict(self, features: dict[str, float]) -> dict[str, float]:
        """
        Classify a package as benign or malicious.
        
        Args:
            features: Dictionary of extracted features
            
        Returns:
            Dictionary with classification, probability, and risk assessment
        """
        if not self.model:
            logger.error("Model not loaded")
            return {
                "classification": "unknown",
                "probability_malicious": 0.0,
                "confidence": 0.0,
                "risk_level": "unknown",
            }

        # Prepare feature vector in correct order (as used during training)
        feature_names = [
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
        ]

        feature_vector = pd.DataFrame(
            [[features.get(name, 0.0) for name in feature_names]],
            columns=feature_names,
        )

        try:
            # Get probability predictions
            probabilities = self.model.predict_proba(feature_vector)[0]
            prob_benign, prob_malicious = probabilities[0], probabilities[1]

            # Classify based on optimal threshold
            is_malicious = prob_malicious >= self.optimal_threshold

            # Determine risk level
            if prob_malicious < 0.3:
                risk_level = "low"
            elif prob_malicious < 0.7:
                risk_level = "medium"
            else:
                risk_level = "high"

            return {
                "classification": "malicious" if is_malicious else "benign",
                "probability_malicious": float(prob_malicious),
                "probability_benign": float(prob_benign),
                "confidence": float(max(prob_benign, prob_malicious)),
                "risk_level": risk_level,
                "threshold_used": self.optimal_threshold,
            }
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {
                "classification": "error",
                "probability_malicious": 0.0,
                "error": str(e),
            }

    def scan_package_archive(self, archive_path: Path) -> dict:
        """
        End-to-end scan of a package archive.
        
        Args:
            archive_path: Path to the package archive (.zip, .tar.gz, .whl)
            
        Returns:
            Complete scan result with classification and feature details
        """
        try:
            # Extract to temporary directory
            with tempfile.TemporaryDirectory(prefix="scan_") as temp_dir:
                temp_path = Path(temp_dir)

                # Validate and extract archive
                if not _is_supported_archive(archive_path):
                    logger.warning(f"Unsupported archive format: {archive_path}")
                    return {
                        "success": False,
                        "error": f"Unsupported format: {archive_path.name}",
                    }

                _extract_archive_safely(archive_path, temp_path)

                # Extract features
                features = self.extract_features_from_directory(temp_path, archive_path)

                # Make prediction
                prediction = self.predict(features)

                return {
                    "success": True,
                    "archive": str(archive_path.name),
                    "features": features,
                    "prediction": prediction,
                }

        except Exception as e:
            logger.error(f"Scan error: {e}")
            return {
                "success": False,
                "error": str(e),
            }


# Global scanner instance
_scanner = None


def get_scanner() -> MalwareScannerService:
    """Get or create the global scanner instance."""
    global _scanner
    if _scanner is None:
        _scanner = MalwareScannerService()
    return _scanner
