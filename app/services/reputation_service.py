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
from app.services.typosquat_guard import _POPULAR_NPM, _POPULAR_PYPI

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

# Impersonation thresholds: a real react-dom has 30M+ monthly downloads;
# anything far below this for an exact popular-name match signals squatting.
_IMPERSONATION_THRESHOLD_NPM = 10_000  # monthly
_IMPERSONATION_THRESHOLD_PYPI = 5_000  # monthly


def is_popular_name(ecosystem: str, package_name: str) -> bool:
    """Return True if ``package_name`` exactly matches a known popular package.

    Such packages are always Libraries.io-enriched (impersonation vetting) and are
    given first claim on the per-scan Libraries.io budget by the orchestrator.
    """
    popular = _POPULAR_NPM if ecosystem.lower() == "npm" else _POPULAR_PYPI
    return package_name.lower() in popular


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

_librariesio_last_called: float = 0.0
_LIBRARIESIO_MIN_INTERVAL = 1.0  # seconds — 60 req/min


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

    # Popular-name impersonation: exact match to a well-known package but anomalously low downloads
    if (
        package_name.lower() in _POPULAR_NPM
        and monthly_downloads is not None
        and monthly_downloads < _IMPERSONATION_THRESHOLD_NPM
    ):
        signals.append(RiskSignal(
            source="reputation",
            name="popular_name_impersonation",
            value=0.95,
            weight=0.7,
            confidence=0.9,
            rationale=(
                f"Package name exactly matches well-known package '{package_name}' "
                f"but has only {monthly_downloads:,} monthly downloads — "
                "consistent with name-squatting / impersonation"
            ),
            metadata={"monthly_downloads": monthly_downloads, "known_popular_name": package_name.lower()},
        ))
        evidence.append("reputation:popular_name_impersonation")

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

    # Popular-name impersonation: exact match to a well-known package but anomalously low downloads
    if (
        package_name.lower() in _POPULAR_PYPI
        and monthly_downloads is not None
        and monthly_downloads < _IMPERSONATION_THRESHOLD_PYPI
    ):
        signals.append(RiskSignal(
            source="reputation",
            name="popular_name_impersonation",
            value=0.95,
            weight=0.7,
            confidence=0.9,
            rationale=(
                f"Package name exactly matches well-known package '{package_name}' "
                f"but has only {monthly_downloads:,} monthly downloads — "
                "consistent with name-squatting / impersonation"
            ),
            metadata={"monthly_downloads": monthly_downloads, "known_popular_name": package_name.lower()},
        ))
        evidence.append("reputation:popular_name_impersonation")

    return ReputationLookupResult(signals=signals, evidence=evidence, metadata=metadata)


async def _enrich_from_librariesio(
    client: httpx.AsyncClient,
    ecosystem: str,
    package_name: str,
    result: ReputationLookupResult,
) -> ReputationLookupResult:
    """Optionally enrich reputation signals with Libraries.io SourceRank data."""
    global _librariesio_last_called
    if not settings.librariesio_api_key:
        return result

    loop_time = asyncio.get_event_loop().time()
    elapsed = loop_time - _librariesio_last_called
    if _librariesio_last_called > 0 and elapsed < _LIBRARIESIO_MIN_INTERVAL:
        await asyncio.sleep(_LIBRARIESIO_MIN_INTERVAL - elapsed)
    _librariesio_last_called = asyncio.get_event_loop().time()

    platform = "npm" if ecosystem == "npm" else "pypi"
    params: dict[str, str] = {"api_key": settings.librariesio_api_key}

    try:
        resp = await client.get(
            f"{_LIBRARIES_IO_API}/{platform}/{quote(package_name, safe='')}",
            params=params,
        )
        if resp.is_error:
            error_key = "libraries_io_not_found" if resp.status_code == 404 else "libraries_io_error"
            result.metadata[error_key] = resp.status_code
            return result

        data = resp.json()
        if not isinstance(data, dict):
            result.metadata["libraries_io_error"] = "invalid_response"
            return result
    except (httpx.RequestError, ValueError) as exc:
        result.metadata["libraries_io_error"] = type(exc).__name__
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
            value=min(float(source_rank) / 20.0, 1.0),
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
            value=min(dependents_count / 100.0, 1.0),
            weight=0.4,
            confidence=0.85,
            rationale="Many other packages depend on this package",
            metadata={"trusted": True, "dependents_count": dependents_count},
        ))
        extra_evidence.append("reputation:high_dependents")

    # Composite trust score: 60% downloads, 40% GitHub stars
    monthly_downloads = result.metadata.get("monthly_downloads") or 0
    downloads_component = min(float(monthly_downloads) / 1_000_000.0, 1.0)
    stars_component = min(float(stars or 0) / 5_000.0, 1.0)
    extra_metadata["trust_score"] = round(0.6 * downloads_component + 0.4 * stars_component, 4)

    return ReputationLookupResult(
        signals=[*result.signals, *extra_signals],
        evidence=[*result.evidence, *extra_evidence],
        metadata={**result.metadata, **extra_metadata},
    )


async def lookup_package_reputation(
    ecosystem: str,
    package_name: str,
    package_version: str,
    *,
    is_direct_dependency: bool = False,
    force_librariesio: bool = False,
) -> ReputationLookupResult:
    """Lookup reputation evidence for a concrete package version.

    Results are cached by ``ecosystem/name/version`` for a configurable TTL.
    Libraries.io enrichment (and its trust_score) is only performed for
    direct (top-level) dependencies to stay within the 60 req/min quota.
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

            # Enrich with Libraries.io data. The 60 req/min quota is managed by the
            # *caller* (the orchestrator allocates a per-scan budget via force_librariesio),
            # so depth alone no longer triggers enrichment. Popular-name exact matches are
            # always enriched regardless of depth — impersonators need vetting.
            popular_name = is_popular_name(ecosystem, package_name)
            if force_librariesio or popular_name:
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


async def fetch_package_details(
    ecosystem: str,
    name: str,
    version: str | None,
) -> dict:
    """Fetch rich metadata for a single package for the details view.

    Raises FileNotFoundError if the package does not exist on the registry.
    Never raises for network or parse errors — affected fields are returned as None.
    """
    eco = ecosystem.lower()
    timeout = httpx.Timeout(max(2, settings.reputation_lookup_timeout_seconds))

    async with httpx.AsyncClient(timeout=timeout) as client:
        if eco == "npm":
            return await _fetch_npm_details(client, name, version)
        if eco == "pypi":
            return await _fetch_pypi_details(client, name, version)
        raise ValueError(f"Unsupported ecosystem: {ecosystem}")


async def enrich_search_results(results: list[dict], ecosystem: str) -> None:
    """Enrich search result dicts in-place with rich metadata fetched concurrently."""
    if not results:
        return
    eco = ecosystem.lower()
    sem = asyncio.Semaphore(4)
    timeout = httpx.Timeout(max(2, settings.reputation_lookup_timeout_seconds))

    async def _enrich_one(client: httpx.AsyncClient, result: dict) -> None:
        async with sem:
            try:
                if eco == "npm":
                    details = await _fetch_npm_details(client, result["name"], None)
                elif eco == "pypi":
                    details = await _fetch_pypi_details(client, result["name"], None)
                else:
                    return
                for field in (
                    "license", "keywords", "latest_version", "package_age_days",
                    "maintainer_count", "has_repository", "direct_dependencies_count",
                    "stars", "forks", "contributors_count", "dependents_count", "source_rank",
                ):
                    if result.get(field) is None:
                        result[field] = details.get(field)
            except Exception:
                pass

    async with httpx.AsyncClient(timeout=timeout) as client:
        await asyncio.gather(*(_enrich_one(client, r) for r in results))


async def _fetch_npm_details(
    client: httpx.AsyncClient,
    name: str,
    version: str | None,
) -> dict:
    encoded_name = name.replace("/", "%2F")

    # Full package document
    try:
        resp = await client.get(f"{_NPM_REGISTRY}/{encoded_name}")
        if resp.status_code == 404:
            raise FileNotFoundError(name)
        if resp.is_error:
            return _empty_details(name, version or "unknown", "npm", f"https://www.npmjs.com/package/{name}")
        pkg = resp.json()
    except FileNotFoundError:
        raise
    except (httpx.RequestError, ValueError):
        return _empty_details(name, version or "unknown", "npm", f"https://www.npmjs.com/package/{name}")

    dist_tags = pkg.get("dist-tags") or {}
    latest_version = dist_tags.get("latest") if isinstance(dist_tags, dict) else None
    resolved_version = version or latest_version or "unknown"

    description = pkg.get("description") if isinstance(pkg.get("description"), str) else None

    raw_kw = pkg.get("keywords")
    keywords: list[str] = raw_kw if isinstance(raw_kw, list) else []

    license_raw = pkg.get("license")
    license_str = (
        license_raw if isinstance(license_raw, str)
        else license_raw.get("type") if isinstance(license_raw, dict)
        else None
    )

    homepage = pkg.get("homepage") if isinstance(pkg.get("homepage"), str) else None

    maintainers = pkg.get("maintainers", [])
    maintainer_count = len(maintainers) if isinstance(maintainers, list) else None

    repository = pkg.get("repository")
    has_repository = isinstance(repository, (str, dict)) and bool(repository)

    time_data = pkg.get("time") or {}
    created_date = time_data.get("created") if isinstance(time_data, dict) else None
    package_age_days = _days_since(created_date)

    # Version-specific doc for direct dep count
    direct_dependencies_count: int | None = None
    try:
        ver_resp = await client.get(f"{_NPM_REGISTRY}/{encoded_name}/{resolved_version}")
        if not ver_resp.is_error:
            ver_data = ver_resp.json()
            deps = ver_data.get("dependencies")
            direct_dependencies_count = len(deps) if isinstance(deps, dict) else None
    except (httpx.RequestError, ValueError):
        pass

    # Monthly downloads
    monthly_downloads: int | None = None
    try:
        dl_resp = await client.get(f"{_NPM_DOWNLOADS_API}/{quote(name, safe='')}")
        if not dl_resp.is_error:
            dl_data = dl_resp.json()
            raw_dl = dl_data.get("downloads") if isinstance(dl_data, dict) else None
            if isinstance(raw_dl, int):
                monthly_downloads = raw_dl
    except (httpx.RequestError, ValueError):
        pass

    interim = ReputationLookupResult(
        signals=[],
        evidence=[],
        metadata={
            "package_age_days": package_age_days,
            "monthly_downloads": monthly_downloads,
        },
    )
    try:
        enriched = await _enrich_from_librariesio(client, "npm", name, interim)
    except Exception:
        enriched = interim

    return {
        "name": name,
        "version": resolved_version,
        "ecosystem": "npm",
        "description": description,
        "license": license_str,
        "homepage": homepage,
        "registry_url": f"https://www.npmjs.com/package/{name}",
        "keywords": keywords,
        "latest_version": latest_version,
        "package_age_days": enriched.metadata.get("package_age_days"),
        "monthly_downloads": enriched.metadata.get("monthly_downloads"),
        "maintainer_count": maintainer_count,
        "has_repository": has_repository,
        "direct_dependencies_count": direct_dependencies_count,
        "stars": enriched.metadata.get("stars"),
        "forks": enriched.metadata.get("forks"),
        "contributors_count": enriched.metadata.get("contributors_count"),
        "dependents_count": enriched.metadata.get("dependents_count"),
        "source_rank": enriched.metadata.get("libraries_io_rank"),
    }


async def _fetch_pypi_details(
    client: httpx.AsyncClient,
    name: str,
    version: str | None,
) -> dict:
    # Full package JSON
    try:
        resp = await client.get(f"{_PYPI_JSON_API}/{quote(name, safe='')}/json")
        if resp.status_code == 404:
            raise FileNotFoundError(name)
        if resp.is_error:
            return _empty_details(name, version or "unknown", "pypi", f"https://pypi.org/project/{name}/")
        pkg = resp.json()
    except FileNotFoundError:
        raise
    except (httpx.RequestError, ValueError):
        return _empty_details(name, version or "unknown", "pypi", f"https://pypi.org/project/{name}/")

    info = pkg.get("info") or {}
    if not isinstance(info, dict):
        info = {}

    latest_version = info.get("version") if isinstance(info.get("version"), str) else None
    resolved_version = version or latest_version or "unknown"

    description = info.get("summary") if isinstance(info.get("summary"), str) else None
    license_str = info.get("license") if isinstance(info.get("license"), str) else None
    homepage = info.get("home_page") if isinstance(info.get("home_page"), str) else None

    raw_kw = info.get("keywords") or ""
    keywords: list[str] = [k.strip() for k in raw_kw.split(",") if k.strip()] if isinstance(raw_kw, str) else []

    home_page = info.get("home_page")
    project_urls = info.get("project_urls")
    has_repository = bool(home_page) or (
        isinstance(project_urls, dict)
        and any(
            k.lower() in {"source", "repository", "github", "code", "source code"}
            for k in project_urls
        )
    )

    requires_dist = info.get("requires_dist")
    direct_dependencies_count = len(requires_dist) if isinstance(requires_dist, list) else None

    # Package age from earliest release
    releases = pkg.get("releases") or {}
    first_release_date: str | None = None
    if isinstance(releases, dict):
        for _ver, files in releases.items():
            if not isinstance(files, list):
                continue
            for f in files:
                if not isinstance(f, dict):
                    continue
                upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                if isinstance(upload_time, str):
                    if first_release_date is None or upload_time < first_release_date:
                        first_release_date = upload_time
    package_age_days = _days_since(first_release_date)

    # Monthly downloads
    monthly_downloads: int | None = None
    try:
        dl_resp = await client.get(f"{_PYPISTATS_RECENT_API}/{quote(name, safe='')}/recent")
        if not dl_resp.is_error:
            dl_data = dl_resp.json()
            data = dl_data.get("data") if isinstance(dl_data, dict) else None
            raw_dl = data.get("last_month") if isinstance(data, dict) else None
            if isinstance(raw_dl, int):
                monthly_downloads = raw_dl
    except (httpx.RequestError, ValueError):
        pass

    interim = ReputationLookupResult(
        signals=[],
        evidence=[],
        metadata={
            "package_age_days": package_age_days,
            "monthly_downloads": monthly_downloads,
        },
    )
    try:
        enriched = await _enrich_from_librariesio(client, "pypi", name, interim)
    except Exception:
        enriched = interim

    return {
        "name": name,
        "version": resolved_version,
        "ecosystem": "pypi",
        "description": description,
        "license": license_str,
        "homepage": homepage,
        "registry_url": f"https://pypi.org/project/{name}/",
        "keywords": keywords,
        "latest_version": latest_version,
        "package_age_days": enriched.metadata.get("package_age_days"),
        "monthly_downloads": enriched.metadata.get("monthly_downloads"),
        "maintainer_count": None,
        "has_repository": has_repository,
        "direct_dependencies_count": direct_dependencies_count,
        "stars": enriched.metadata.get("stars"),
        "forks": enriched.metadata.get("forks"),
        "contributors_count": enriched.metadata.get("contributors_count"),
        "dependents_count": enriched.metadata.get("dependents_count"),
        "source_rank": enriched.metadata.get("libraries_io_rank"),
    }


def _empty_details(name: str, version: str, ecosystem: str, registry_url: str) -> dict:
    return {
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "description": None,
        "license": None,
        "homepage": None,
        "registry_url": registry_url,
        "keywords": [],
        "latest_version": None,
        "package_age_days": None,
        "monthly_downloads": None,
        "maintainer_count": None,
        "has_repository": None,
        "direct_dependencies_count": None,
        "stars": None,
        "forks": None,
        "contributors_count": None,
        "dependents_count": None,
        "source_rank": None,
    }
