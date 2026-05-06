"""Pydantic schemas for dependency version compatibility checks."""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.api.schemas.dependency import DependencySpec


class CompatibilityCheckRequest(BaseModel):
    """Request body for checking dependency version compatibility."""

    ecosystem: str = Field(
        ...,
        pattern=r"^(npm|pypi)$",
        description="Package ecosystem: 'npm' or 'pypi'.",
    )
    dependencies: list[DependencySpec] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Dependencies to check compatibility for.",
    )


class CompatibilityCheckResult(BaseModel):
    """Result for a single dependency compatibility check."""

    name: str
    requested_version: str
    existing_constraint: str | None = None
    compatible: bool = True
    reason: str | None = None
    suggestion: str | None = None
    exists_in_manifest: bool = False


class CompatibilityCheckResponse(BaseModel):
    """Response for dependency version compatibility check."""

    ecosystem: str
    compatible: bool = True
    checks: list[CompatibilityCheckResult] = Field(default_factory=list)
