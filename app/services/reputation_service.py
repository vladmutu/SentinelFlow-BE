"""Package reputation and trust signal lookups.

Fetches real-world trust indicators from npm registry, PyPI JSON API,
and Libraries.io to produce ``RiskSignal`` objects consumed by the
unified risk scoring engine in ``scanner_service``.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx

from app.api.schemas.risk import RiskSignal
from app.core.config import settings

logger = logging.getLogger(__name__)

_NPM_REGISTRY = "https://registry.npmjs.org"
_PYPI_JSON_API = "https://pypi.org/pypi"
_LIBRARIES_IO_API = "https://libraries.io/api"
_NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-month"
_PYPISTATS_RECENT_API = "https://pypistats.org/api/packages"

# Trust thresholds
_NPM_HIGH_DOWNLOADS_THRESHOLD = 100_000  # monthly
_PYPI_HIGH_DOWNLOADS_THRESHOLD = 50_000  # monthly
_TOP_POPULARITY_THRESHOLD = 1_000_000  # monthly
_LOW_ADOPTION_THRESHOLD = 100  # weekly
_OLD_PACKAGE_DAYS = 730  # 2 years
_YOUNG_PACKAGE_DAYS = 180  # 6 months


@dataclass(frozen=True)
class ReputationLookupResult:
    """Normalized reputation evidence for one package version."""

    signals: list[RiskSignal]
    evidence: list[str]
    metadata: dict[str, object]


@dataclass
class _CachedReputation:
    expires_at: datetime
    result: ReputationLookupResult


_cache_lock = asyncio.Lock()
_cache: dict[tuple[str, str, str], _CachedReputation] = {}


def _days_since(iso_date: str | None) -> int | None:
    """Parse an ISO date string and return days elapsed, or None."""
    if not iso_date or not isinstance(iso_date, str):
        return None
    try:
        parsed = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - parsed
        return max(0, delta.days)
    except (ValueError, TypeError):
        return None


async def _fetch_npm_reputation(
    client: httpx.AsyncClient,
    package_name: str,
    package_version: str,
) -> ReputationLookupResult:
    """Fetch reputation signals from npm registry and downloads API."""
    signals: list[RiskSignal] = []
    evidence: list[str] = []
    metadata: dict[str, object] = {"source": "npm"}

    encoded_name = package_name.replace("/", "%2F")

    # Fetch package metadata
    try:
        resp = await client.get(f"{_NPM_REGISTRY}/{encoded_name}")
        if resp.is_error:
            metadata["registry_error"] = resp.status_code
            return ReputationLookupResult(signals=signals, evidence=evidence, metadata=metadata)
        pkg_data = resp.json()
    except (httpx.RequestError, ValueError) as exc:
        metadata["registry_error"] = str(exc)
        return ReputationLookupResult(signals=signals, evidence=evidence, metadata=metadata)

    # Extract metadata
    maintainers = pkg_data.get("maintainers", [])
    maintainer_count = len(maintainers) if isinstance(maintainers, list) else 0
    repository = pkg_data.get("repository")
    has_repo = isinstance(repository, (str, dict)) and bool(repository)
    license_info = pkg_data.get("license")
    has_license = isinstance(license_info, (str, dict)) and bool(license_info)

    # Package age
    time_data = pkg_data.get("time", {})
    created_date = time_data.get("created") if isinstance(time_data, dict) else None
    package_age_days = _days_since(created_date)

    # Check for recent maintainer changes (via time stamps on latest versions)
    modified_date = time_data.get("modified") if isinstance(time_data, dict) else None

    metadata.update({
        "maintainer_count": maintainer_count,
        "has_repository": has_repo,
        "has_license": has_license,
        "package_age_days": package_age_days,
    })

    # Fetch monthly downloads
    monthly_downloads: int | None = None
    try:
        downloads_resp = await client.get(
            f"{_NPM_DOWNLOADS_API}/{quote(package_name, safe='')}"
        )
        if not downloads_resp.is_error:
            dl_data = downloads_resp.json()
            if isinstance(dl_data, dict):
                raw_dl = dl_data.get("downloads")
                if isinstance(raw_dl, int):
                    monthly_downloads = raw_dl
    except (httpx.RequestError, ValueError):
        pass

    metadata["monthly_downloads"] = monthly_downloads

    # --- Generate signals ---

    # Trusted package: high downloads + old age
    is_trusted = (
        monthly_downloads is not None
        and monthly_downloads >= _NPM_HIGH_DOWNLOADS_THRESHOLD
        and package_age_days is not None
        and package_age_days >= _OLD_PACKAGE_DAYS
    )
    if is_trusted:
        signals.append(RiskSignal(
            source="reputation",
            name="trusted_package",
            value=True,
            weight=0.8,
            confidence=0.9,
            rationale="Package has high download count and is well-established",
            metadata={"trusted": True, "monthly_downloads": monthly_downloads, "age_days": package_age_days},
        ))
        evidence.append("reputation:trusted_package")

    # High popularity
    if monthly_downloads is not None and monthly_downloads >= _TOP_POPULARITY_THRESHOLD:
        signals.append(RiskSignal(
            source="reputation",
            name="high_popularity",
            value=min(monthly_downloads / _TOP_POPULARITY_THRESHOLD, 1.0),
            weight=0.6,
            confidence=0.95,
            rationale="Package is in the top tier of downloads for its ecosystem",
            metadata={"trusted": True, "monthly_downloads": monthly_downloads},
        ))
        evidence.append("reputation:high_popularity")

    # Low adoption warning
    if (
        monthly_downloads is not None
        and monthly_downloads < _LOW_ADOPTION_THRESHOLD * 4
        and package_age_days is not None
        and package_age_days < _YOUNG_PACKAGE_DAYS
    ):
        signals.append(RiskSignal(
            source="reputation",
            name="low_adoption",
            value=True,
            weight=0.5,
            confidence=0.7,
            rationale="Package has very low downloads and is relatively new",
            metadata={"monthly_downloads": monthly_downloads, "age_days": package_age_days},
        ))
        evidence.append("reputation:low_adoption")

    # Single maintainer
    if maintainer_count == 1:
        signals.append(RiskSignal(
            source="reputation",
            name="single_maintainer",
            value=True,
            weight=0.3,
            confidence=0.9,
            rationale="Package has only one maintainer, increasing bus factor risk",
            metadata={"maintainer_count": maintainer_count},
        ))
        evidence.append("reputation:single_maintainer")

    # No repository link
    if not has_repo:
        signals.append(RiskSignal(
            source="reputation",
            name="no_repository_link",
            value=True,
            weight=0.4,
            confidence=0.85,
            rationale="Package lacks a source code repository link",
            metadata={},
        ))
        evidence.append("reputation:no_repository_link")

    return ReputationLookupResult(signals=signals, evidence=evidence, metadata=metadata)


async def _fetch_pypi_reputation(
    client: httpx.AsyncClient,
    package_name: str,
    package_version: str,
) -> ReputationLookupResult:
    """Fetch reputation signals from PyPI JSON API and pypistats."""
    signals: list[RiskSignal] = []
    evidence: list[str] = []
    metadata: dict[str, object] = {"source": "pypi"}

    # Fetch package metadata from PyPI
    try:
        resp = await client.get(f"{_PYPI_JSON_API}/{quote(package_name, safe='')}/json")
        if resp.is_error:
            metadata["registry_error"] = resp.status_code
            return ReputationLookupResult(signals=signals, evidence=evidence, metadata=metadata)
        pkg_data = resp.json()
    except (httpx.RequestError, ValueError) as exc:
        metadata["registry_error"] = str(exc)
        return ReputationLookupResult(signals=signals, evidence=evidence, metadata=metadata)

    info = pkg_data.get("info", {}) if isinstance(pkg_data, dict) else {}
    if not isinstance(info, dict):
        info = {}

    # Extract metadata
    author = info.get("author")
    maintainer = info.get("maintainer")
    maintainer_email = info.get("maintainer_email")
    has_maintainer = bool(maintainer) or bool(maintainer_email)
    has_author = bool(author)
    license_info = info.get("license")
    has_license = isinstance(license_info, str) and bool(license_info.strip())
    home_page = info.get("home_page")
    project_urls = info.get("project_urls")
    has_repo = bool(home_page) or (
        isinstance(project_urls, dict)
        and any(
            key.lower() in {"source", "repository", "github", "code", "source code"}
            for key in project_urls
        )
    )
    classifiers = info.get("classifiers", [])
    if not isinstance(classifiers, list):
        classifiers = []

    # Determine package age from releases
    releases = pkg_data.get("releases", {})
    first_release_date: str | None = None
    if isinstance(releases, dict):
        for _version, files in releases.items():
            if not isinstance(files, list) or not files:
                continue
            for file_info in files:
                if not isinstance(file_info, dict):
                    continue
                upload_time = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
                if isinstance(upload_time, str):
                    if first_release_date is None or upload_time < first_release_date:
                        first_release_date = upload_time

    package_age_days = _days_since(first_release_date)

    metadata.update({
        "has_author": has_author,
        "has_maintainer": has_maintainer,
        "has_repository": has_repo,
        "has_license": has_license,
        "package_age_days": package_age_days,
        "classifier_count": len(classifiers),
    })

    # Fetch monthly downloads from pypistats
    monthly_downloads: int | None = None
    try:
        dl_resp = await client.get(
            f"{_PYPISTATS_RECENT_API}/{quote(package_name, safe='')}/recent"
        )
        if not dl_resp.is_error:
            dl_data = dl_resp.json()
            if isinstance(dl_data, dict):
                data = dl_data.get("data")
                if isinstance(data, dict):
                    raw_dl = data.get("last_month")
                    if isinstance(raw_dl, int):
                        monthly_downloads = raw_dl
    except (httpx.RequestError, ValueError):
        pass

    metadata["monthly_downloads"] = monthly_downloads

    # --- Generate signals ---

    # Trusted package
    is_trusted = (
        monthly_downloads is not None
        and monthly_downloads >= _PYPI_HIGH_DOWNLOADS_THRESHOLD
        and package_age_days is not None
        and package_age_days >= _OLD_PACKAGE_DAYS
    )
    if is_trusted:
        signals.append(RiskSignal(
            source="reputation",
            name="trusted_package",
            value=True,
            weight=0.8,
            confidence=0.9,
            rationale="Package has high download count and is well-established",
            metadata={"trusted": True, "monthly_downloads": monthly_downloads, "age_days": package_age_days},
        ))
        evidence.append("reputation:trusted_package")

    # High popularity
    if monthly_downloads is not None and monthly_downloads >= _TOP_POPULARITY_THRESHOLD:
        signals.append(RiskSignal(
            source="reputation",
            name="high_popularity",
            value=min(monthly_downloads / _TOP_POPULARITY_THRESHOLD, 1.0),
            weight=0.6,
            confidence=0.95,
            rationale="Package is in the top tier of downloads for its ecosystem",
            metadata={"trusted": True, "monthly_downloads": monthly_downloads},
        ))
        evidence.append("reputation:high_popularity")

    # Low adoption
    if (
        monthly_downloads is not None
        and monthly_downloads < _LOW_ADOPTION_THRESHOLD * 4
        and package_age_days is not None
        and package_age_days < _YOUNG_PACKAGE_DAYS
    ):
        signals.append(RiskSignal(
            source="reputation",
            name="low_adoption",
            value=True,
            weight=0.5,
            confidence=0.7,
            rationale="Package has very low downloads and is relatively new",
            metadata={"monthly_downloads": monthly_downloads, "age_days": package_age_days},
        ))
        evidence.append("reputation:low_adoption")

    # No repository link
    if not has_repo:
        signals.append(RiskSignal(
            source="reputation",
            name="no_repository_link",
            value=True,
            weight=0.4,
            confidence=0.85,
            rationale="Package lacks a source code repository link",
            metadata={},
        ))
        evidence.append("reputation:no_repository_link")

    return ReputationLookupResult(signals=signals, evidence=evidence, metadata=metadata)


async def _enrich_from_librariesio(
    client: httpx.AsyncClient,
    ecosystem: str,
    package_name: str,
    result: ReputationLookupResult,
) -> ReputationLookupResult:
    """Optionally enrich reputation signals with Libraries.io SourceRank data."""
    if not settings.librariesio_api_key:
        return result

    platform = "npm" if ecosystem == "npm" else "pypi"
    params: dict[str, str] = {"api_key": settings.librariesio_api_key}

    try:
        resp = await client.get(
            f"{_LIBRARIES_IO_API}/{platform}/{quote(package_name, safe='')}",
            params=params,
        )
        if resp.is_error:
            return result

        data = resp.json()
        if not isinstance(data, dict):
            return result
    except (httpx.RequestError, ValueError):
        return result

    source_rank = data.get("rank")
    dependents_count = data.get("dependents_count")
    stars = data.get("stars")
    forks = data.get("forks")
    contributors_count = data.get("contributions_count")

    extra_signals: list[RiskSignal] = []
    extra_evidence: list[str] = []
    extra_metadata: dict[str, object] = {
        "libraries_io_rank": source_rank,
        "dependents_count": dependents_count,
        "stars": stars,
        "forks": forks,
        "contributors_count": contributors_count,
    }

    # High source rank → trusted
    if isinstance(source_rank, (int, float)) and source_rank >= 20:
        extra_signals.append(RiskSignal(
            source="reputation",
            name="high_source_rank",
            value=min(float(source_rank) / 30.0, 1.0),
            weight=0.5,
            confidence=0.8,
            rationale="Libraries.io SourceRank indicates a well-maintained project",
            metadata={"trusted": True, "source_rank": source_rank},
        ))
        extra_evidence.append("reputation:high_source_rank")

    # High dependents count → community trust
    if isinstance(dependents_count, int) and dependents_count >= 100:
        extra_signals.append(RiskSignal(
            source="reputation",
            name="high_dependents",
            value=min(dependents_count / 1000.0, 1.0),
            weight=0.4,
            confidence=0.85,
            rationale="Many other packages depend on this package",
            metadata={"trusted": True, "dependents_count": dependents_count},
        ))
        extra_evidence.append("reputation:high_dependents")

    return ReputationLookupResult(
        signals=[*result.signals, *extra_signals],
        evidence=[*result.evidence, *extra_evidence],
        metadata={**result.metadata, **extra_metadata},
    )


async def lookup_package_reputation(
    ecosystem: str,
    package_name: str,
    package_version: str,
) -> ReputationLookupResult:
    """Lookup reputation evidence for a concrete package version.

    Results are cached by ``ecosystem/name/version`` for a configurable TTL.
    """
    if not settings.reputation_lookup_enabled:
        return ReputationLookupResult(
            signals=[],
            evidence=[],
            metadata={"lookup_enabled": False},
        )

    cache_key = (ecosystem.lower(), package_name.lower(), package_version)
    now = datetime.now(timezone.utc)

    cached = _cache.get(cache_key)
    if cached is not None and cached.expires_at > now:
        return cached.result

    async with _cache_lock:
        cached = _cache.get(cache_key)
        if cached is not None and cached.expires_at > now:
            return cached.result

        timeout = httpx.Timeout(max(2, settings.reputation_lookup_timeout_seconds))
        async with httpx.AsyncClient(timeout=timeout) as client:
            if ecosystem.lower() == "npm":
                result = await _fetch_npm_reputation(client, package_name, package_version)
            elif ecosystem.lower() == "pypi":
                result = await _fetch_pypi_reputation(client, package_name, package_version)
            else:
                result = ReputationLookupResult(
                    signals=[], evidence=[], metadata={"error": f"unsupported ecosystem: {ecosystem}"}
                )

            # Enrich with Libraries.io data
            try:
                result = await _enrich_from_librariesio(client, ecosystem, package_name, result)
            except Exception:
                logger.warning(
                    "Libraries.io enrichment failed for %s@%s",
                    package_name,
                    package_version,
                )

        ttl = timedelta(seconds=max(60, settings.reputation_cache_ttl_seconds))
        _cache[cache_key] = _CachedReputation(expires_at=now + ttl, result=result)
        return result
