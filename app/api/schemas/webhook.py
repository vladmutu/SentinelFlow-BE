"""Pydantic schemas for GitHub webhook events."""

from __future__ import annotations

from pydantic import BaseModel, Field


class WebhookResponse(BaseModel):
    """Acknowledgement returned to GitHub after processing a webhook."""

    status: str = "ok"
    message: str = ""
    scan_triggered: bool = False
    job_id: str | None = None


class WebhookCommitFile(BaseModel):
    """Simplified representation of a file changed in a commit."""

    filename: str


class WebhookCommit(BaseModel):
    """Simplified representation of a single commit in a push event."""

    id: str
    message: str = ""
    added: list[str] = Field(default_factory=list)
    modified: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)


class WebhookRepository(BaseModel):
    """Simplified repository info from a webhook event."""

    id: int
    name: str
    full_name: str
    owner: dict | None = None
    default_branch: str = "main"


class WebhookInstallation(BaseModel):
    """GitHub App installation context."""

    id: int
    account: dict | None = None


class WebhookPushEvent(BaseModel):
    """Typed subset of the GitHub push event payload."""

    ref: str = ""
    before: str = ""
    after: str = ""
    repository: WebhookRepository | None = None
    installation: WebhookInstallation | None = None
    commits: list[WebhookCommit] = Field(default_factory=list)
    head_commit: WebhookCommit | None = None
