"""Canonical risk-assessment schema used by scan results and explanations."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DependencyContext(BaseModel):
    """How a package version was resolved during dependency analysis."""

    source: str | None = None
    resolution_kind: str | None = None
    is_direct_dependency: bool | None = None
    transitive_depth: int | None = None
    requested_spec: str | None = None
    resolved_version: str | None = None
    lockfile_version: str | None = None


class RiskSignal(BaseModel):
    """One structured signal contributing to a package-risk assessment."""

    source: str = Field(..., description="Origin of the signal, such as classifier or policy")
    name: str
    value: str | int | float | bool | None = None
    weight: float = 1.0
    confidence: float = 0.0
    rationale: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PackageRiskAssessment(BaseModel):
    """Canonical package-risk payload persisted with scan results."""

    schema_version: str = "2026-04-20"
    package_name: str
    package_version: str
    ecosystem: str = Field(..., pattern=r"^(npm|pypi)$")
    overall_status: str
    overall_score: float | None = None
    confidence: float | None = None
    analysis_mode: str = "static-classifier"
    allowlisted: bool = False
    suppressed: bool = False
    suppression_reason: str | None = None
    dependency_context: DependencyContext | None = None
    static_signals: list[RiskSignal] = Field(default_factory=list)
    dynamic_signals: list[RiskSignal] = Field(default_factory=list)
    vulnerability_signals: list[RiskSignal] = Field(default_factory=list)
    reputation_signals: list[RiskSignal] = Field(default_factory=list)
    policy_signals: list[RiskSignal] = Field(default_factory=list)
    advisory_references: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    explanation: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"from_attributes": True}