"""Pydantic schemas for the AI package explainability endpoint."""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID


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
    vulnerability_details: list[dict[str, Any]] | None = None
    dynamic_findings: dict[str, Any] | None = None
    reputation_metadata: dict[str, Any] | None = None
    session_id: UUID | None = None


class ExplainPackageResponse(BaseModel):
    """Plain-English explanation returned to the frontend (non-streaming fallback)."""

    explanation: str
    model: str
    package_name: str
    package_version: str


class ChatMessage(BaseModel):
    """A single turn in the agent chat conversation."""

    role: Literal["user", "assistant"]
    content: str


class AgentChatRequest(BaseModel):
    """Request body for the free-form agent chat endpoint.

    Stateless mode: omit session_id; pass full conversation in messages.
    Persistent mode: provide session_id; messages should contain only the
    latest user message — history is loaded from the database automatically.
    """

    messages: list[ChatMessage]
    session_id: UUID | None = None
    scan_context: dict[str, Any] | None = None
