"""Download package artifacts from npm and PyPI registries."""

from __future__ import annotations

import logging
import re
import asyncio
import difflib
from html import unescape
from pathlib import Path
from urllib.parse import quote, urljoin
from datetime import datetime, timezone, timedelta

import httpx
from app.core.config import settings

logger = logging.getLogger(__name__)

_NPM_REGISTRY = "https://registry.npmjs.org"
_PYPI_JSON_API = "https://pypi.org/pypi"
_PYPI_SEARCH_URL = "https://pypi.org/search/"
_PYPI_SIMPLE_URL = "https://pypi.org/simple/"
_LIBRARIES_IO_SEARCH_URL = "https://libraries.io/api/search"
_NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-month"
_PYPISTATS_RECENT_API = "https://pypistats.org/api/packages"

# Reusable timeout for registry requests.
_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

_PYPI_RESULT_RE = re.compile(
    r'<a\b(?=[^>]*\bclass="[^"]*\bpackage-snippet\b[^"]*")(?=[^>]*\bhref="([^"]+)")[^>]*>(.*?)</a>',
    re.DOTALL,
)
_PYPI_NAME_RE = re.compile(r'package-snippet__name">([^<]+)<')
_PYPI_VERSION_RE = re.compile(r'package-snippet__version">([^<]+)<')
_PYPI_DESC_RE = re.compile(r'package-snippet__description">(.*?)</p>', re.DOTALL)
_PYPI_SIMPLE_ANCHOR_RE = re.compile(r"<a[^>]*>([^<]+)</a>", re.IGNORECASE)

_POPULAR_PYPI_PACKAGES = {
    "requests",
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "pytest",
    "fastapi",
    "flask",
    "django",
    "httpx",
    "sqlalchemy",
    "pydantic",
    "uvicorn",
    "beautifulsoup4",
    "scikit-learn",
    "tensorflow",
    "torch",
    "pillow",
    "aiohttp",
    "setuptools",
}

_POPULAR_NPM_PACKAGES = {
    "react",
    "react-dom",
    "next",
    "express",
    "lodash",
    "axios",
    "typescript",
    "vite",
    "webpack",
    "jest",
    "eslint",
    "prettier",
}

_SIMPLE_INDEX_TTL = timedelta(minutes=30)
_simple_index_cache_lock = asyncio.Lock()
_simple_index_cached_names: list[str] | None = None
_simple_index_cached_at: datetime | None = None

_librariesio_package_cache_lock = asyncio.Lock()
_librariesio_package_cache: dict[str, tuple[datetime, dict]] = {}
_LIBRARIESIO_PACKAGE_TTL = timedelta(minutes=60)

_DOWNLOADS_CACHE_TTL = timedelta(hours=6)
_downloads_cache_lock = asyncio.Lock()
_npm_downloads_cache: dict[str, tuple[datetime, int | None]] = {}
_pypi_downloads_cache: dict[str, tuple[datetime, int | None]] = {}
_DOWNLOAD_ENRICH_CONCURRENCY = 8
_DOWNLOAD_REQUEST_TIMEOUT = httpx.Timeout(4.0, connect=2.0)


async def _get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    attempts: int = 3,
    base_delay_seconds: float = 0.15,
    timeout: httpx.Timeout | None = None,
) -> httpx.Response:
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            resp = await client.get(url, params=params, headers=headers, timeout=timeout)
            if resp.status_code in {429, 500, 502, 503, 504} and attempt < attempts:
                await asyncio.sleep(base_delay_seconds * attempt)
                continue
            return resp
        except httpx.RequestError as exc:
            last_exc = exc
            if attempt >= attempts:
                raise
            await asyncio.sleep(base_delay_seconds * attempt)

    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Unreachable retry state")


def _normalize_pkg_name(name: str) -> str:
    return re.sub(r"[-_.]", "", name.strip().lower())


def _levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        curr = [i]
        for j, ch_b in enumerate(b, start=1):
            insert_cost = curr[j - 1] + 1
            delete_cost = prev[j] + 1
            replace_cost = prev[j - 1] + (0 if ch_a == ch_b else 1)
            curr.append(min(insert_cost, delete_cost, replace_cost))
        prev = curr
    return prev[-1]


def _is_single_transposition(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    mismatches = [idx for idx, (x, y) in enumerate(zip(a, b)) if x != y]
    if len(mismatches) != 2:
        return False
    i, j = mismatches
    return a[i] == b[j] and a[j] == b[i]


def _typosquat_signal(candidate_name: str, query: str) -> dict:
    cand = candidate_name.strip().lower()
    qry = query.strip().lower()
    normalized_cand = _normalize_pkg_name(cand)
    normalized_qry = _normalize_pkg_name(qry)

    if not qry:
        return {
            "is_suspected": False,
            "confidence": 0.0,
            "levenshtein_distance": None,
            "edit_distance": None,
            "normalized_conflict": False,
            "reasons": [],
        }

    distance = _levenshtein_distance(cand, qry)
    normalized_conflict = normalized_cand == normalized_qry and cand != qry

    reasons: list[str] = []
    confidence = 0.0

    if normalized_conflict:
        reasons.append("same normalized name with separator variation")
        confidence = max(confidence, 0.95)

    if _is_single_transposition(cand, qry):
        reasons.append("single character transposition from query")
        confidence = max(confidence, 0.85)

    if distance == 1 and cand != qry:
        reasons.append("one edit away from query")
        confidence = max(confidence, 0.8)
    elif distance == 2 and cand != qry:
        reasons.append("two edits away from query")
        confidence = max(confidence, 0.55)

    return {
        "is_suspected": bool(reasons),
        "confidence": round(confidence, 2),
        "levenshtein_distance": distance,
        "edit_distance": distance,
        "normalized_conflict": normalized_conflict,
        "reasons": reasons,
    }


def _text_from_html_fragment(fragment: str) -> str:
    cleaned = re.sub(r"<[^>]+>", "", fragment)
    return unescape(cleaned).strip()


def _cached_download_value(
    cache: dict[str, tuple[datetime, int | None]],
    key: str,
) -> int | None | object:
    entry = cache.get(key)
    if entry is None:
        return _MISSING

    cached_at, value = entry
    if datetime.now(timezone.utc) - cached_at <= _DOWNLOADS_CACHE_TTL:
        return value
    return _MISSING


_MISSING = object()


def _coerce_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


async def _load_npm_monthly_downloads(
    name: str,
    *,
    client: httpx.AsyncClient,
) -> int | None:
    normalized_name = name.strip().lower()
    if not normalized_name:
        return None

    cached = _cached_download_value(_npm_downloads_cache, normalized_name)
    if cached is not _MISSING:
        return cached

    async with _downloads_cache_lock:
        cached = _cached_download_value(_npm_downloads_cache, normalized_name)
        if cached is not _MISSING:
            return cached

        try:
            encoded_name = quote(name.strip(), safe="")
            resp = await _get_with_retry(
                client,
                f"{_NPM_DOWNLOADS_API}/{encoded_name}",
                attempts=1,
                timeout=_DOWNLOAD_REQUEST_TIMEOUT,
            )
            if resp.status_code in {404, 429}:
                value: int | None = None
            else:
                resp.raise_for_status()
                payload = resp.json()
                value = _coerce_int(payload.get("downloads")) if isinstance(payload, dict) else None
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError):
            value = None

        _npm_downloads_cache[normalized_name] = (datetime.now(timezone.utc), value)
        return value


async def _load_pypi_monthly_downloads(
    name: str,
    *,
    client: httpx.AsyncClient,
) -> int | None:
    normalized_name = name.strip().lower()
    if not normalized_name:
        return None

    cached = _cached_download_value(_pypi_downloads_cache, normalized_name)
    if cached is not _MISSING:
        return cached

    async with _downloads_cache_lock:
        cached = _cached_download_value(_pypi_downloads_cache, normalized_name)
        if cached is not _MISSING:
            return cached

        try:
            encoded_name = quote(name.strip(), safe="")
            resp = await _get_with_retry(
                client,
                f"{_PYPISTATS_RECENT_API}/{encoded_name}/recent",
                attempts=1,
                timeout=_DOWNLOAD_REQUEST_TIMEOUT,
            )
            if resp.status_code in {404, 429}:
                value: int | None = None
            else:
                resp.raise_for_status()
                payload = resp.json()
                if isinstance(payload, dict):
                    data = payload.get("data")
                    value = _coerce_int(data.get("last_month")) if isinstance(data, dict) else None
                else:
                    value = None
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError):
            value = None

        _pypi_downloads_cache[normalized_name] = (datetime.now(timezone.utc), value)
        return value


async def _enrich_monthly_downloads(
    results: list[dict],
    *,
    ecosystem: str,
    client: httpx.AsyncClient,
) -> None:
    if not results:
        return

    sem = asyncio.Semaphore(_DOWNLOAD_ENRICH_CONCURRENCY)

    async def _enrich_one(result: dict) -> None:
        name = result.get("name")
        if not isinstance(name, str) or not name:
            return

        async with sem:
            if ecosystem == "npm":
                downloads = await _load_npm_monthly_downloads(name, client=client)
            else:
                downloads = await _load_pypi_monthly_downloads(name, client=client)
        result["monthly_downloads"] = downloads

    await asyncio.gather(*(_enrich_one(result) for result in results), return_exceptions=True)


async def _load_pypi_simple_names(client: httpx.AsyncClient) -> list[str]:
    global _simple_index_cached_names
    global _simple_index_cached_at

    now = datetime.now(timezone.utc)
    if (
        _simple_index_cached_names is not None
        and _simple_index_cached_at is not None
        and now - _simple_index_cached_at <= _SIMPLE_INDEX_TTL
    ):
        return _simple_index_cached_names

    async with _simple_index_cache_lock:
        now = datetime.now(timezone.utc)
        if (
            _simple_index_cached_names is not None
            and _simple_index_cached_at is not None
            and now - _simple_index_cached_at <= _SIMPLE_INDEX_TTL
        ):
            return _simple_index_cached_names

        resp = await _get_with_retry(client, _PYPI_SIMPLE_URL)
        resp.raise_for_status()

        names: list[str] = []
        for raw_name in _PYPI_SIMPLE_ANCHOR_RE.findall(resp.text):
            decoded = unescape(raw_name).strip()
            if decoded:
                names.append(decoded)

        _simple_index_cached_names = names
        _simple_index_cached_at = datetime.now(timezone.utc)
        return names


def suggest_package_name(ecosystem: str, query: str, results: list[dict]) -> str | None:
    cleaned = query.strip().lower()
    if len(cleaned) < 3:
        return None

    if ecosystem not in {"pypi", "npm"}:
        return None

    if ecosystem == "pypi":
        candidates = {name.lower(): name for name in _POPULAR_PYPI_PACKAGES}
    else:
        candidates = {name.lower(): name for name in _POPULAR_NPM_PACKAGES}

    for result in results:
        name = result.get("name")
        if not isinstance(name, str) or not name:
            continue

        # Avoid suggesting suspicious typo-squatted names as corrections.
        typosquat = result.get("typosquat")
        if isinstance(typosquat, dict) and typosquat.get("is_suspected") is True:
            continue

        candidates[name.lower()] = name

    if not candidates:
        return None

    matched = difflib.get_close_matches(cleaned, list(candidates.keys()), n=1, cutoff=0.75)
    if not matched:
        return None

    suggestion = candidates[matched[0]]
    if suggestion.lower() == cleaned:
        return None
    return suggestion


async def _build_pypi_exact_result(
    query: str,
    *,
    client: httpx.AsyncClient,
) -> dict | None:
    """Try exact package resolution via PyPI JSON API as fallback for empty HTML search."""
    resp = await _get_with_retry(client, f"{_PYPI_JSON_API}/{query}/json")
    if resp.status_code == 404:
        return None
    resp.raise_for_status()

    payload = resp.json()
    info = payload.get("info") if isinstance(payload, dict) else {}
    if not isinstance(info, dict):
        return None

    name = info.get("name")
    if not isinstance(name, str) or not name:
        return None

    return {
        "ecosystem": "pypi",
        "name": name,
        "version": info.get("version"),
        "description": info.get("summary"),
        "homepage": info.get("home_page") or info.get("project_url"),
        "registry_url": f"https://pypi.org/project/{name}/",
        "score": None,
        "monthly_downloads": None,
        "typosquat": _typosquat_signal(name, query),
    }


async def _load_librariesio_pypi_package(
    name: str,
    *,
    client: httpx.AsyncClient,
) -> dict | None:
    normalized_name = name.strip().lower()
    if not normalized_name:
        return None

    now = datetime.now(timezone.utc)
    cached = _librariesio_package_cache.get(normalized_name)
    if cached is not None:
        cached_at, cached_payload = cached
        if now - cached_at <= _LIBRARIESIO_PACKAGE_TTL:
            return cached_payload

    async with _librariesio_package_cache_lock:
        now = datetime.now(timezone.utc)
        cached = _librariesio_package_cache.get(normalized_name)
        if cached is not None:
            cached_at, cached_payload = cached
            if now - cached_at <= _LIBRARIESIO_PACKAGE_TTL:
                return cached_payload

        params: dict[str, str] = {}
        if settings.librariesio_api_key:
            params["api_key"] = settings.librariesio_api_key

        try:
            resp = await _get_with_retry(
                client,
                f"https://libraries.io/api/pypi/{normalized_name}",
                params=params or None,
            )
            if resp.status_code in {401, 403, 404, 429}:
                return None
            resp.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError):
            return None

        payload = resp.json()
        if not isinstance(payload, dict):
            return None

        _librariesio_package_cache[normalized_name] = (now, payload)
        return payload


async def _search_librariesio_pypi_packages(
    query: str,
    *,
    client: httpx.AsyncClient,
) -> list[dict]:
    params: dict[str, str | int] = {
        "q": query,
        "platforms": "PyPI",
    }
    if settings.librariesio_api_key:
        params["api_key"] = settings.librariesio_api_key

    try:
        resp = await _get_with_retry(client, _LIBRARIES_IO_SEARCH_URL, params=params)
        if resp.status_code in {401, 403, 429}:
            return []
        resp.raise_for_status()
    except (httpx.RequestError, httpx.HTTPStatusError):
        return []

    payload = resp.json()
    if not isinstance(payload, list):
        return []

    results: list[dict] = []
    for item in payload:
        if not isinstance(item, dict):
            continue

        name = item.get("name")
        if not isinstance(name, str) or not name:
            continue

        version = item.get("latest_release_number") or item.get("latest_stable_release_number")
        if not isinstance(version, str) or not version:
            version = None

        results.append(
            {
                "ecosystem": "pypi",
                "name": name,
                "version": version,
                "description": item.get("description"),
                "homepage": item.get("homepage"),
                "registry_url": f"https://pypi.org/project/{name}/",
                "score": item.get("rank"),
                "monthly_downloads": None,
                "typosquat": _typosquat_signal(name, query),
            }
        )

    return results


async def _enrich_pypi_results_with_librariesio(
    results: list[dict],
    *,
    client: httpx.AsyncClient,
) -> None:
    if not results:
        return

    for result in results:
        name = result.get("name")
        if not isinstance(name, str) or not name:
            continue

        info = await _load_librariesio_pypi_package(name, client=client)
        if info is None:
            continue

        latest_release = info.get("latest_release_number")
        if not result.get("version") and isinstance(latest_release, str) and latest_release:
            result["version"] = latest_release

        if not result.get("description"):
            description = info.get("description")
            if isinstance(description, str) and description:
                result["description"] = description

        if not result.get("homepage"):
            homepage = info.get("homepage")
            if isinstance(homepage, str) and homepage:
                result["homepage"] = homepage


async def search_npm_packages(
    query: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> list[dict]:
    """Search npm packages and return normalized candidates with typo signals."""
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=_TIMEOUT)

    try:
        resp = await _get_with_retry(
            client,
            f"{_NPM_REGISTRY}/-/v1/search",
            params={"text": query},
        )
        resp.raise_for_status()
        payload = resp.json()
        objects = payload.get("objects", [])
        if not isinstance(objects, list):
            return []

        results: list[dict] = []
        for item in objects:
            if not isinstance(item, dict):
                continue
            package = item.get("package", {})
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            if not isinstance(name, str) or not name:
                continue
            links = package.get("links") if isinstance(package.get("links"), dict) else {}
            score_obj = item.get("score") if isinstance(item.get("score"), dict) else {}
            results.append(
                {
                    "ecosystem": "npm",
                    "name": name,
                    "version": package.get("version"),
                    "description": package.get("description"),
                    "homepage": links.get("homepage"),
                    "registry_url": links.get("npm") or f"https://www.npmjs.com/package/{name}",
                    "score": score_obj.get("final"),
                    "monthly_downloads": None,
                    "typosquat": _typosquat_signal(name, query),
                }
            )

        await _enrich_monthly_downloads(results, ecosystem="npm", client=client)

        return results
    finally:
        if own_client:
            await client.aclose()


async def search_pypi_packages(
    query: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> list[dict]:
    """Search PyPI packages via the public search endpoint and parse top hits."""
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=_TIMEOUT)

    try:
        results = await _search_librariesio_pypi_packages(query, client=client)

        if not results:
            resp = await _get_with_retry(
                client,
                _PYPI_SEARCH_URL,
                params={"q": query},
                headers={"Accept": "text/html"},
            )
            resp.raise_for_status()

            html = resp.text
            matches = _PYPI_RESULT_RE.findall(html)
            results = []
            for href, card_html in matches:
                name_match = _PYPI_NAME_RE.search(card_html)
                if not name_match:
                    continue

                name = unescape(name_match.group(1)).strip()
                if not name:
                    continue

                version_match = _PYPI_VERSION_RE.search(card_html)
                desc_match = _PYPI_DESC_RE.search(card_html)
                version = unescape(version_match.group(1)).strip() if version_match else None
                description = _text_from_html_fragment(desc_match.group(1)) if desc_match else None
                project_url = urljoin("https://pypi.org", href)

                results.append(
                    {
                        "ecosystem": "pypi",
                        "name": name,
                        "version": version,
                        "description": description,
                        "homepage": None,
                        "registry_url": project_url,
                        "score": None,
                        "monthly_downloads": None,
                        "typosquat": _typosquat_signal(name, query),
                    }
                )

            if not results:
                try:
                    exact_match = await _build_pypi_exact_result(query, client=client)
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code != 404:
                        raise
                    exact_match = None
                if exact_match is not None:
                    results.append(exact_match)

            if not results:
                try:
                    all_names = await _load_pypi_simple_names(client)
                except httpx.HTTPStatusError:
                    all_names = []

                lowered_query = query.strip().lower()
                contains_matches = [name for name in all_names if lowered_query in name.lower()]

                for name in contains_matches:
                    results.append(
                        {
                            "ecosystem": "pypi",
                            "name": name,
                            "version": None,
                            "description": None,
                            "homepage": None,
                            "registry_url": f"https://pypi.org/project/{name}/",
                            "score": None,
                            "monthly_downloads": None,
                            "typosquat": _typosquat_signal(name, query),
                        }
                    )

            if results:
                await _enrich_pypi_results_with_librariesio(results, client=client)

        await _enrich_monthly_downloads(results, ecosystem="pypi", client=client)

        return results
    finally:
        if own_client:
            await client.aclose()


async def list_npm_package_versions(
    name: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict:
    """Return available npm versions for a package."""
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=_TIMEOUT)

    try:
        encoded_name = name.replace("/", "%2F")
        resp = await _get_with_retry(client, f"{_NPM_REGISTRY}/{encoded_name}")
        if resp.status_code == 404:
            raise FileNotFoundError(f"npm package not found: {name}")
        resp.raise_for_status()

        payload = resp.json()
        versions_map = payload.get("versions", {})
        if not isinstance(versions_map, dict):
            versions_map = {}

        versions = [version for version in versions_map.keys() if isinstance(version, str) and version]
        latest_version = None
        dist_tags = payload.get("dist-tags", {})
        if isinstance(dist_tags, dict):
            latest = dist_tags.get("latest")
            if isinstance(latest, str) and latest:
                latest_version = latest

        return {
            "ecosystem": "npm",
            "package_name": payload.get("name") or name,
            "latest_version": latest_version,
            "versions": versions,
        }
    finally:
        if own_client:
            await client.aclose()


async def list_pypi_package_versions(
    name: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict:
    """Return available PyPI versions for a package."""
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=_TIMEOUT)

    try:
        resp = await _get_with_retry(client, f"{_PYPI_JSON_API}/{name}/json")
        if resp.status_code == 404:
            raise FileNotFoundError(f"PyPI package not found: {name}")
        resp.raise_for_status()

        payload = resp.json()
        releases = payload.get("releases", {})
        if not isinstance(releases, dict):
            releases = {}

        versions = [version for version, files in releases.items() if isinstance(version, str) and version and isinstance(files, list) and files]
        latest_version = None
        info = payload.get("info", {})
        if isinstance(info, dict):
            current = info.get("version")
            if isinstance(current, str) and current:
                latest_version = current

        return {
            "ecosystem": "pypi",
            "package_name": payload.get("info", {}).get("name") if isinstance(payload.get("info", {}), dict) else name,
            "latest_version": latest_version,
            "versions": versions,
        }
    finally:
        if own_client:
            await client.aclose()


async def fetch_npm_package(
    name: str,
    version: str,
    dest_dir: Path,
    *,
    client: httpx.AsyncClient | None = None,
) -> Path:
    """Download an npm tarball and return the path to the saved ``.tgz`` file.

    Handles scoped packages (``@scope/pkg``).
    """
    # npm registry expects scoped names to be URL-encoded: @scope%2Fpkg
    encoded_name = name.replace("/", "%2F")

    # The tarball filename drops the scope prefix.
    simple_name = name.split("/")[-1] if "/" in name else name
    tarball_url = f"{_NPM_REGISTRY}/{encoded_name}/-/{simple_name}-{version}.tgz"

    dest_file = dest_dir / f"{simple_name}-{version}.tgz"

    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=_TIMEOUT)

    try:
        resp = await client.get(tarball_url)
        if resp.status_code == 404:
            raise FileNotFoundError(
                f"npm tarball not found: {name}@{version} ({tarball_url})"
            )
        resp.raise_for_status()
        dest_file.write_bytes(resp.content)
        logger.debug("Downloaded npm package %s@%s → %s", name, version, dest_file)
        return dest_file
    finally:
        if own_client:
            await client.aclose()


async def fetch_pypi_package(
    name: str,
    version: str,
    dest_dir: Path,
    *,
    client: httpx.AsyncClient | None = None,
) -> Path:
    """Download a PyPI sdist/wheel and return the path to the saved archive.

    Prefers sdist (``.tar.gz``) over wheel (``.whl``) when available.
    """
    json_url = f"{_PYPI_JSON_API}/{name}/{version}/json"

    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=_TIMEOUT)

    try:
        meta_resp = await client.get(json_url)
        if meta_resp.status_code == 404:
            raise FileNotFoundError(
                f"PyPI package not found: {name}=={version}"
            )
        meta_resp.raise_for_status()
        data = meta_resp.json()

        urls = data.get("urls", [])
        if not urls:
            raise FileNotFoundError(
                f"No downloadable files for {name}=={version}"
            )

        # Prefer sdist, fall back to first available wheel / any file.
        sdist = next(
            (u for u in urls if u.get("packagetype") == "sdist"), None
        )
        chosen = sdist or urls[0]
        download_url: str = chosen["url"]
        filename: str = chosen["filename"]

        resp = await client.get(download_url)
        resp.raise_for_status()

        dest_file = dest_dir / filename
        dest_file.write_bytes(resp.content)
        logger.debug("Downloaded PyPI package %s==%s → %s", name, version, dest_file)
        return dest_file
    finally:
        if own_client:
            await client.aclose()
