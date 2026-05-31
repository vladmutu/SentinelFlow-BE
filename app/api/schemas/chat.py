"""Pydantic schemas for chat session management."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class CreateSessionRequest(BaseModel):
    owner: str
    repo_name: str
    title: str | None = None


class SessionSummary(BaseModel):
    id: UUID
    owner: str
    repo_name: str
    title: str | None
    created_at: datetime
    updated_at: datetime
    message_count: int

    model_config = {"from_attributes": True}


class MessageOut(BaseModel):
    id: UUID
    role: str
    content: str
    created_at: datetime

    model_config = {"from_attributes": True}


class SessionDetail(SessionSummary):
    messages: list[MessageOut]
