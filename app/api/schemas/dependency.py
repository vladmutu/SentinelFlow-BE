"""Schemas for dependency change pull-request operations."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class DependencySpec(BaseModel):
    """Single dependency specification to add or update."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=214,
        pattern=r"^(?:@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$",
        description="NPM package name, including optional @scope prefix.",
    )
    version: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9*^~<>=|.,+_\- ]+$",
        description="NPM semver or range expression.",
    )

    @field_validator("name", "version")
    @classmethod
    def _strip_values(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Value must not be empty")
        return cleaned


class AddDependencyRequest(BaseModel):
    """Request body for creating a dependency update pull request."""

    ecosystem: str = Field(
        ...,
        pattern=r"^(npm|pypi)$",
        description="Dependency ecosystem to update: 'npm' or 'pypi'.",
    )
    dependencies: list[DependencySpec] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Dependencies to add or update in package.json.",
    )
    updated_package_lock_json: str | None = Field(
        default=None,
        min_length=2,
        description=(
            "Optional complete package-lock.json content. If omitted and server-side lockfile "
            "generation is enabled, the backend will generate the lockfile before committing. "
            "Only used for ecosystem='npm'."
        ),
    )
    generate_lockfile_server_side: bool = Field(
        default=False,
        description="If true, backend generates package-lock.json using npm (npm only).",
    )
    idempotency_key: str | None = Field(
        default=None,
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._\-:]+$",
        description="Client-provided key to deduplicate retried dependency PR requests.",
    )
    branch_name: str | None = Field(
        default=None,
        max_length=120,
        description="Optional preferred branch name. Collisions are auto-suffixed.",
    )
    pr_title: str | None = Field(default=None, max_length=200)
    pr_body: str | None = Field(default=None, max_length=10000)


class AddDependencyResponse(BaseModel):
    """Response returned after opening a pull request."""

    pr_url: str
    pr_number: int
    branch_name: str
    status: str = "pending_review"
    message: str = "Dependency update pull request created"


class TyposquatSignal(BaseModel):
    """Typosquatting risk hints for a candidate package name."""

    is_suspected: bool = False
    confidence: float = 0.0
    levenshtein_distance: int | None = None
    edit_distance: int | None = None
    normalized_conflict: bool = False
    reasons: list[str] = Field(default_factory=list)


class PackageSearchResult(BaseModel):
    """Single package candidate returned by registry search proxy."""

    ecosystem: str = Field(..., pattern=r"^(npm|pypi)$")
    name: str
    version: str | None = None
    description: str | None = None
    homepage: str | None = None
    registry_url: str | None = None
    score: float | None = None
    monthly_downloads: int | None = None
    typosquat: TyposquatSignal


class PackageSearchResponse(BaseModel):
    """Response model for package search proxy endpoint."""

    ecosystem: str = Field(..., pattern=r"^(npm|pypi)$")
    query: str
    total: int
    results: list[PackageSearchResult]
    did_you_mean: str | None = None


class PackageVersionsResponse(BaseModel):
    """Response model for package version lookup proxy endpoint."""

    ecosystem: str = Field(..., pattern=r"^(npm|pypi)$")
    package_name: str
    latest_version: str | None = None
    versions: list[str]
