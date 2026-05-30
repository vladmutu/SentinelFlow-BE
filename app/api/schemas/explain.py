"""Pydantic schemas for the AI package explainability endpoint."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ExplainPackageRequest(BaseModel):
    """All analysis data for one package, sent by the frontend for LLM explanation."""

    package_name: str
    package_version: str
    ecosystem: str | None = None
    malware_status: str | None = None
    malware_score: float | None = None
    risk_status: str | None = None
    risk_score: float | None = None
    static_features: dict[str, float] | None = None
    vulnerability_details: list[dict[str, Any]] = Field(default_factory=list)
    dynamic_findings: dict[str, Any] | None = None
    reputation_metadata: dict[str, Any] | None = None


class ExplainPackageResponse(BaseModel):
    """Plain-English explanation returned to the frontend."""

    explanation: str
    model: str
    package_name: str
    package_version: str
