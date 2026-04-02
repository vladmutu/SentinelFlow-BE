"""
Pydantic models for scanner API requests and responses.
"""

from typing import Literal

from pydantic import BaseModel, Field


class ScannerFeatures(BaseModel):
    """Extracted features from code analysis."""

    max_entropy: float = Field(..., ge=0, le=8, description="Maximum entropy found")
    avg_entropy: float = Field(..., ge=0, le=8, description="Average entropy found")
    eval_count: float = Field(..., description="Number of eval() calls detected")
    exec_count: float = Field(..., description="Number of exec() calls detected")
    base64_count: float = Field(..., description="Number of base64 operations detected")
    network_imports: float = Field(
        ..., description="Number of network module imports detected"
    )
    entropy_gap: float = Field(..., description="Difference between max and average entropy")
    exec_eval_ratio: float = Field(..., description="Ratio of exec to eval operations")
    network_exec_ratio: float = Field(
        ..., description="Ratio of network imports to exec operations"
    )
    obfuscation_index: float = Field(
        ..., description="Engineered feature indicating code obfuscation"
    )


class ScannerPrediction(BaseModel):
    """Classification result from the malware detection model."""

    classification: str = Field(
        ..., description="Classification: 'benign', 'malicious', or 'unknown'"
    )
    probability_malicious: float = Field(..., ge=0, le=1, description="Probability of malware")
    probability_benign: float = Field(..., ge=0, le=1, description="Probability of benign")
    confidence: float = Field(
        ..., ge=0, le=1, description="Confidence score of the prediction"
    )
    risk_level: str = Field(
        ..., description="Risk assessment: 'low', 'medium', 'high', or 'unknown'"
    )
    threshold_used: float = Field(..., description="Classification threshold used for decision")


class ScanRepositoryRequest(BaseModel):
    """Request to scan a GitHub repository."""

    owner: str | None = Field(default=None, description="Repository owner login")
    repo: str | None = Field(default=None, description="Repository name")
    full_name: str | None = Field(
        default=None,
        description="Repository full name in owner/repo format",
    )
    branch: str = Field(default="main", description="Branch to scan")


class DependencyNode(BaseModel):
    """Recursive dependency tree node for repository graph rendering."""

    name: str = Field(..., description="Package/dependency name")
    version: str = Field(..., description="Package/dependency version")
    children: list["DependencyNode"] = Field(
        default_factory=list,
        description="Nested transitive dependencies",
    )


class RepositoryPackageSummary(BaseModel):
    """Dependency summary for one ecosystem in a repository."""

    ecosystem: Literal["npm", "python"] = Field(..., description="Dependency ecosystem")
    root_name: str = Field(..., description="Project root package name")
    dependency_count: int = Field(..., ge=0, description="Total dependency nodes discovered")
    tree: DependencyNode | None = Field(
        default=None,
        description="Complete dependency tree for graph rendering",
    )


class RepositoryScanResult(BaseModel):
    """Completed repository scan result payload."""

    owner: str = Field(..., description="Repository owner")
    repo: str = Field(..., description="Repository name")
    full_name: str = Field(..., description="Repository full name owner/repo")
    status: Literal["completed", "failed"] = Field(..., description="Final scan status")
    reason: str | None = Field(
        default=None,
        description="Explicit reason for no dependencies, failure, or important scan notes",
    )
    packages: list[RepositoryPackageSummary] = Field(
        default_factory=list,
        description="Per-ecosystem dependency summaries",
    )
    prediction: ScannerPrediction | None = Field(
        default=None,
        description="Repository-level prediction derived from dependency signals",
    )


class RepositoryScanSubmitResponse(BaseModel):
    """Immediate response when requesting repository scan."""

    success: bool = Field(..., description="Whether scan request was accepted")
    scan_id: str = Field(..., description="Stable identifier for status polling")
    status: Literal["queued", "running", "completed", "failed"] = Field(
        ..., description="Current scan state"
    )
    result: RepositoryScanResult | None = Field(
        default=None,
        description="Result when scan already completed synchronously",
    )


class RepositoryScanStatusResponse(BaseModel):
    """Polling response for repository scan status."""

    success: bool = Field(..., description="Whether status lookup succeeded")
    scan_id: str = Field(..., description="Stable scan identifier")
    status: Literal["queued", "running", "completed", "failed"] = Field(
        ..., description="Current scan state"
    )
    result: RepositoryScanResult | None = Field(
        default=None,
        description="Present for completed/failed scans",
    )


DependencyNode.model_rebuild()


class ScanFileRequest(BaseModel):
    """Request to scan files from a payload."""

    package_name: str = Field(..., description="Name of the package or dependency")
    ecosystem: str = Field(..., description="Package ecosystem (npm, pypi, etc.)")


class ScanResponseSuccess(BaseModel):
    """Successful scan response."""

    success: bool = Field(True, description="Indicates successful scan")
    archive_name: str = Field(..., description="Name of scanned archive")
    features: ScannerFeatures = Field(..., description="Extracted code features")
    prediction: ScannerPrediction = Field(..., description="Malware classification result")


class ScanResponseError(BaseModel):
    """Error scan response."""

    success: bool = Field(False, description="Indicates failed scan")
    error: str = Field(..., description="Error message describing what went wrong")


class HealthCheckResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="Status of the scanner service")
    model_loaded: bool = Field(..., description="Whether the ML model is loaded")
    threshold: float = Field(..., description="Active classification threshold")
