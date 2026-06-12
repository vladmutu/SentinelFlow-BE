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
    run_prescan: bool = Field(
        default=True,
        description=(
            "If true (default), the backend runs the full security scan before opening the PR "
            "and blocks on confirmed malicious packages. Set to false when the client has already "
            "scanned the packages via /dependencies/prescan to avoid a second long scan."
        ),
    )
    scan_summary_markdown: str | None = Field(
        default=None,
        max_length=20000,
        description=(
            "Pre-built markdown scan summary (from /dependencies/prescan) to embed in the PR body. "
            "Only used when run_prescan is false."
        ),
    )


class PackagePrescanResult(BaseModel):
    """Security scan result for a single package, returned inline with the PR response."""

    package_name: str
    package_version: str
    overall_status: str
    overall_score: float | None = None
    advisory_references: list[str] = Field(default_factory=list)
    cve_count: int = 0
    static_features: dict[str, float] | None = None
    dynamic_status: str | None = None
    dynamic_risk_score: float | None = None
    vm_evasion_observed: bool | None = None
    ioc_hit: bool | None = None


class AddDependencyResponse(BaseModel):
    """Response returned after opening a pull request."""

    pr_url: str
    pr_number: int
    branch_name: str
    status: str = "pending_review"
    message: str = "Dependency update pull request created"
    typosquat_warnings: list[dict] = Field(
        default_factory=list,
        description="Typosquatting warnings for dependencies that passed but raised concerns.",
    )
    prescan_results: list[PackagePrescanResult] = Field(
        default_factory=list,
        description="Full-pipeline security scan results for each dependency, run before PR creation.",
    )


class PrescanResponse(BaseModel):
    """Response for the standalone pre-PR security scan (no PR is created)."""

    prescan_results: list[PackagePrescanResult] = Field(
        default_factory=list,
        description="Full-pipeline security scan results for each requested dependency.",
    )
    typosquat_warnings: list[dict] = Field(
        default_factory=list,
        description="Typosquatting warnings for dependencies that passed but raised concerns.",
    )
    scan_summary_markdown: str = Field(
        default="",
        description="Markdown summary of the scan, suitable for embedding in a future PR body.",
    )


class TyposquatSignal(BaseModel):
    """Typosquatting risk hints for a candidate package name."""

    is_suspected: bool = False
    confidence: float = 0.0
    levenshtein_distance: int | None = None
    edit_distance: int | None = None
    normalized_conflict: bool = False
    reasons: list[str] = Field(default_factory=list)
    matched_popular_package: str | None = None


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
    query_distance: int | None = Field(
        default=None,
        description=(
            "Levenshtein distance between this package name and the user's search query. "
            "Low values (0-2) indicate a close match; high values suggest an unrelated result."
        ),
    )
    license: str | None = None
    keywords: list[str] = Field(default_factory=list)
    latest_version: str | None = None
    package_age_days: int | None = None
    maintainer_count: int | None = None
    has_repository: bool | None = None
    direct_dependencies_count: int | None = None
    stars: int | None = None
    forks: int | None = None
    contributors_count: int | None = None
    dependents_count: int | None = None
    source_rank: int | None = None


class PackageSearchResponse(BaseModel):
    """Response model for package search proxy endpoint."""

    ecosystem: str = Field(..., pattern=r"^(npm|pypi)$")
    query: str
    page: int = 1
    limit: int = 8
    total: int
    results: list[PackageSearchResult]
    did_you_mean: str | None = None


class PackageVersionsResponse(BaseModel):
    """Response model for package version lookup proxy endpoint."""

    ecosystem: str = Field(..., pattern=r"^(npm|pypi)$")
    package_name: str
    latest_version: str | None = None
    versions: list[str]


class PackageDetailsResponse(BaseModel):
    """Rich metadata for a single npm or PyPI package."""

    name: str
    version: str
    ecosystem: str
    description: str | None = None
    license: str | None = None
    homepage: str | None = None
    registry_url: str | None = None
    keywords: list[str] = Field(default_factory=list)
    latest_version: str | None = None
    package_age_days: int | None = None
    monthly_downloads: int | None = None
    maintainer_count: int | None = None
    has_repository: bool | None = None
    direct_dependencies_count: int | None = None
    stars: int | None = None
    forks: int | None = None
    contributors_count: int | None = None
    dependents_count: int | None = None
    source_rank: int | None = None
