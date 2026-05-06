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

    model_config = {"from_attributes": True}


class ScanJobResponse(BaseModel):
    """Full scan-job status, including all per-package results."""
    id: UUID
    owner: str
    repo_name: str
    ecosystem: str
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

    model_config = {"from_attributes": True}
