"""Pydantic schemas for SBOM generation and CycloneDX export."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SbomLicense(BaseModel):
    """License info for a single component."""

    id: str | None = None
    name: str | None = None
    url: str | None = None


class SbomVulnerability(BaseModel):
    """Vulnerability reference from scan results."""

    id: str
    source: str | None = None
    severity: float | None = None
    description: str | None = None


class SbomComponent(BaseModel):
    """A single component (dependency) in the SBOM."""

    name: str
    version: str
    ecosystem: str = Field(..., pattern=r"^(npm|pypi)$")
    purl: str
    licenses: list[SbomLicense] = Field(default_factory=list)
    vulnerabilities: list[SbomVulnerability] = Field(default_factory=list)
    risk_status: str | None = None
    risk_score: float | None = None
    is_direct: bool = False
    sha256: str | None = None


class SbomToolInfo(BaseModel):
    """Tool metadata for SBOM generation."""

    vendor: str = "SentinelFlow"
    name: str = "SentinelFlow-BE"
    version: str = "1.0.0"


class SbomMetadata(BaseModel):
    """Metadata block for the SBOM document."""

    timestamp: datetime
    tool: SbomToolInfo = Field(default_factory=SbomToolInfo)
    repository_owner: str
    repository_name: str
    ecosystem: str = Field(..., pattern=r"^(npm|pypi)$")
    component_count: int = 0


class SbomDocument(BaseModel):
    """Internal SBOM document structure."""

    schema_version: str = "1.0.0"
    metadata: SbomMetadata
    components: list[SbomComponent] = Field(default_factory=list)


class CycloneDxComponent(BaseModel):
    """CycloneDX component representation."""

    type: str = "library"
    name: str
    version: str
    purl: str
    licenses: list[dict[str, Any]] = Field(default_factory=list)


class CycloneDxVulnerability(BaseModel):
    """CycloneDX vulnerability representation."""

    id: str
    source: dict[str, str] | None = None
    ratings: list[dict[str, Any]] = Field(default_factory=list)
    description: str | None = None
    affects: list[dict[str, Any]] = Field(default_factory=list)


class CycloneDxDocument(BaseModel):
    """Full CycloneDX 1.5 BOM envelope."""

    bomFormat: str = "CycloneDX"
    specVersion: str = "1.5"
    version: int = 1
    metadata: dict[str, Any] = Field(default_factory=dict)
    components: list[dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
