"""Pydantic schemas for the malware-scan workflow."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


# ── Requests ───────────────────────────────────────────────────────────
class ScanTriggerRequest(BaseModel):
    """Body sent when the user clicks the *Scan* button."""
    ecosystem: str = Field(
        ...,
        pattern=r"^(npm|pypi)$",
        description="Package ecosystem to scan: 'npm' or 'pypi'",
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
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    results: list[ScanResultResponse] = []

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

    model_config = {"from_attributes": True}
