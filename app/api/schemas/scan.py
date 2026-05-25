"""Pydantic schemas for the malware-scan workflow."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.api.schemas.risk import PackageRiskAssessment


# ── Requests ───────────────────────────────────────────────────────────
class ScanTriggerRequest(BaseModel):
    """Body sent when the user clicks the *Scan* button."""
    ecosystem: str = Field(
        ...,
        pattern=r"^(npm|pypi)$",
        description="Package ecosystem to scan: 'npm' or 'pypi'",
    )
    selected_packages: list[str] | None = Field(
        default=None,
        description=(
            "Optional package identifiers to scan. Supports package name "
            "(e.g. 'lodash') or exact name@version "
            "(e.g. 'lodash@4.17.21', '@types/node@22.0.0')."
        ),
    )
    scan_mode: str = Field(
        default="full",
        pattern=r"^(full|static_only|lightweight|dynamic_only)$",
        description=(
            "Analysis pipeline to run. "
            "'full': static + CVE/libraries.io (if risky) + dynamic (if still risky). "
            "'static_only': static + CVE/libraries.io (if risky), no dynamic. "
            "'lightweight': CVE + libraries.io lookup only — no static or dynamic. "
            "'dynamic_only': unconditional dynamic analysis only."
        ),
    )


# ── Responses ──────────────────────────────────────────────────────────
class ScanResultResponse(BaseModel):
    """Per-package scan verdict returned to the frontend."""
    id: UUID
    package_name: str
    package_version: str
    ecosystem: str
    malware_status: str
    malware_score: float | None = None
    scanner_version: str
    error_message: str | None = None
    scan_timestamp: datetime
    risk_assessment: PackageRiskAssessment | None = None
    risk_breakdown: dict[str, object] | None = None
    risk_overall_status: str | None = None
    risk_overall_score: float | None = None
    risk_allowlisted: bool = False
    risk_suppressed: bool = False
    risk_suppression_reason: str | None = None
    analysis_status: str | None = None
    analysis_coverage: str | None = None
    advisory_references: list[str] = Field(default_factory=list)
    # Detail fields extracted from risk_assessment.metadata for direct frontend access
    static_features: dict[str, float] | None = None
    dynamic_findings: dict[str, object] | None = None
    analyzed_by: list[str] = Field(default_factory=list)
    # Structured reputation metadata surfaced from risk_assessment.metadata.reputation
    reputation_metadata: dict[str, object] | None = None
    # Per-advisory vulnerability details surfaced from risk_assessment.vulnerability_signals
    vulnerability_details: list[dict[str, object]] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class ScanJobResponse(BaseModel):
    """Full scan-job status, including all per-package results."""
    id: UUID
    owner: str
    repo_name: str
    ecosystem: str
    scan_mode: str = "full"
    status: str
    total_packages: int
    scanned_packages: int
    total_dependency_nodes: int = 0
    total_unique_packages: int = 0
    progress_percent: float = 0.0
    elapsed_seconds: int | None = None
    packages_per_minute: float | None = None
    estimated_seconds_remaining: int | None = None
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    results: list[ScanResultResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class ScanTriggerResponse(BaseModel):
    """Returned immediately after accepting a scan request."""
    job_id: UUID
    status: str = "pending"


class ScanResultMapEntry(BaseModel):
    """Lightweight verdict for a single package used by the graph view."""
    malware_status: str
    malware_score: float | None = None
    scan_timestamp: datetime
    scanner_version: str
    risk_assessment: PackageRiskAssessment | None = None
    risk_breakdown: dict[str, object] | None = None
    risk_overall_status: str | None = None
    risk_overall_score: float | None = None
    risk_allowlisted: bool = False
    risk_suppressed: bool = False
    risk_suppression_reason: str | None = None
    analysis_status: str | None = None
    analysis_coverage: str | None = None
    advisory_references: list[str] = Field(default_factory=list)
    static_features: dict[str, float] | None = None
    dynamic_findings: dict[str, object] | None = None
    analyzed_by: list[str] = Field(default_factory=list)
    reputation_metadata: dict[str, object] | None = None
    vulnerability_details: list[dict[str, object]] = Field(default_factory=list)

    model_config = {"from_attributes": True}


# ── Scan History ───────────────────────────────────────────────────────
class ScanHistorySummary(BaseModel):
    """Lightweight scan job summary for history list views."""
    id: UUID
    repo_name: str = ""
    ecosystem: str
    scan_mode: str
    status: str
    total_packages: int
    processed_packages: int
    scanned_packages: int
    total_dependency_nodes: int = 0
    total_unique_packages: int = 0
    error_message: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    # Aggregated risk distribution for the job's results
    malicious_count: int = 0
    clean_count: int = 0
    error_count: int = 0
    unknown_count: int = 0
    # CVE stats across all packages in the job
    packages_with_cves: int = 0
    total_cve_count: int = 0

    model_config = {"from_attributes": True}


class ScanHistoryResponse(BaseModel):
    """Paginated scan history for a repository."""
    jobs: list[ScanHistorySummary]
    total: int
    page: int
    per_page: int


class ScanJobResultsResponse(BaseModel):
    """Paginated, filterable package results for a specific scan job."""
    job_id: UUID
    total: int
    page: int
    per_page: int
    results: list[ScanResultResponse]
