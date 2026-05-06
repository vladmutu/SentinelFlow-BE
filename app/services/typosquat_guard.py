"""Typosquatting validation guard for the dependency-add workflow.

Validates package names before creating pull requests to prevent
typosquatting attacks.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from app.api.schemas.dependency import DependencySpec
from app.core.config import settings
from app.services.package_fetcher import _typosquat_signal, _normalize_pkg_name

logger = logging.getLogger(__name__)

_NPM_REGISTRY = "https://registry.npmjs.org"
_PYPI_JSON_API = "https://pypi.org/pypi"
_NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-month"
_PYPISTATS_RECENT_API = "https://pypistats.org/api/packages"

# Well-known popular packages to check against
_POPULAR_NPM = {
    "react", "react-dom", "next", "express", "lodash", "axios", "typescript",
    "vite", "webpack", "jest", "eslint", "prettier", "moment", "underscore",
    "jquery", "vue", "angular", "svelte", "socket.io", "mongoose", "sequelize",
    "redux", "mobx", "rxjs", "chalk", "commander", "inquirer", "yargs", "glob",
    "fs-extra", "debug", "dotenv", "cors", "body-parser", "uuid", "crypto-js",
    "bcrypt", "jsonwebtoken", "passport", "nodemon", "concurrently", "cross-env",
}

_POPULAR_PYPI = {
    "requests", "numpy", "pandas", "scipy", "matplotlib", "pytest", "fastapi",
    "flask", "django", "httpx", "sqlalchemy", "pydantic", "uvicorn", "celery",
    "beautifulsoup4", "scikit-learn", "tensorflow", "torch", "pillow", "aiohttp",
    "setuptools", "pip", "wheel", "boto3", "aws-cli", "docker", "redis",
    "psycopg2", "pymongo", "cryptography", "paramiko", "fabric", "gunicorn",
    "alembic", "jinja2", "click", "rich", "typer", "black", "flake8", "mypy",
}


@dataclass(frozen=True)
class TyposquatValidation:
    """Validation result for a single package."""

    package_name: str
    package_version: str
    risk_level: str  # "safe", "warning", "blocked"
    exists_on_registry: bool
    typosquat_analysis: dict
    monthly_downloads: int | None
    package_age_days: int | None
    similar_popular_package: str | None
    reasons: list[str]


async def _check_npm_exists(
    client: httpx.AsyncClient,
    name: str,
) -> tuple[bool, int | None, int | None]:
    """Check if an npm package exists and get basic metadata."""
    try:
        encoded = name.replace("/", "%2F")
        resp = await client.get(f"{_NPM_REGISTRY}/{encoded}")
        if resp.is_error:
            return False, None, None

        data = resp.json()
        if not isinstance(data, dict):
            return False, None, None

        # Monthly downloads
        downloads: int | None = None
        try:
            dl_resp = await client.get(
                f"{_NPM_DOWNLOADS_API}/{quote(name, safe='')}"
            )
            if not dl_resp.is_error:
                dl_data = dl_resp.json()
                if isinstance(dl_data, dict):
                    raw = dl_data.get("downloads")
                    if isinstance(raw, int):
                        downloads = raw
        except (httpx.RequestError, ValueError):
            pass

        # Package age
        time_data = data.get("time", {})
        created = time_data.get("created") if isinstance(time_data, dict) else None
        age_days: int | None = None
        if isinstance(created, str):
            try:
                parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = max(0, (datetime.now(timezone.utc) - parsed).days)
            except (ValueError, TypeError):
                pass

        return True, downloads, age_days

    except (httpx.RequestError, ValueError):
        return False, None, None


async def _check_pypi_exists(
    client: httpx.AsyncClient,
    name: str,
) -> tuple[bool, int | None, int | None]:
    """Check if a PyPI package exists and get basic metadata."""
    try:
        resp = await client.get(f"{_PYPI_JSON_API}/{quote(name, safe='')}/json")
        if resp.is_error:
            return False, None, None

        data = resp.json()
        if not isinstance(data, dict):
            return False, None, None

        # Monthly downloads
        downloads: int | None = None
        try:
            dl_resp = await client.get(
                f"{_PYPISTATS_RECENT_API}/{quote(name, safe='')}/recent"
            )
            if not dl_resp.is_error:
                dl_data = dl_resp.json()
                if isinstance(dl_data, dict):
                    recent_data = dl_data.get("data")
                    if isinstance(recent_data, dict):
                        raw = recent_data.get("last_month")
                        if isinstance(raw, int):
                            downloads = raw
        except (httpx.RequestError, ValueError):
            pass

        # Package age from releases
        releases = data.get("releases", {})
        first_upload: str | None = None
        if isinstance(releases, dict):
            for _ver, files in releases.items():
                if not isinstance(files, list):
                    continue
                for f in files:
                    if isinstance(f, dict):
                        ts = f.get("upload_time_iso_8601") or f.get("upload_time")
                        if isinstance(ts, str):
                            if first_upload is None or ts < first_upload:
                                first_upload = ts

        age_days: int | None = None
        if first_upload:
            try:
                parsed = datetime.fromisoformat(first_upload.replace("Z", "+00:00"))
                age_days = max(0, (datetime.now(timezone.utc) - parsed).days)
            except (ValueError, TypeError):
                pass

        return True, downloads, age_days

    except (httpx.RequestError, ValueError):
        return False, None, None


def _find_similar_popular_package(ecosystem: str, name: str) -> str | None:
    """Find a popular package that is suspiciously similar to the given name."""
    popular = _POPULAR_NPM if ecosystem == "npm" else _POPULAR_PYPI
    normalized_name = _normalize_pkg_name(name)

    for popular_name in popular:
        if popular_name.lower() == name.lower():
            return None  # Exact match — it's the real package

        normalized_popular = _normalize_pkg_name(popular_name)
        if normalized_name == normalized_popular:
            return popular_name

        # Check Levenshtein distance
        signal = _typosquat_signal(name, popular_name)
        if signal.get("is_suspected") and signal.get("confidence", 0) >= 0.5:
            return popular_name

    return None


async def validate_packages(
    ecosystem: str,
    dependencies: list[DependencySpec],
) -> list[TyposquatValidation]:
    """Validate a list of dependency specs for typosquatting risk.

    Returns one TyposquatValidation result per dependency.
    """
    if not settings.typosquat_check_enabled:
        return [
            TyposquatValidation(
                package_name=dep.name,
                package_version=dep.version,
                risk_level="safe",
                exists_on_registry=True,
                typosquat_analysis={},
                monthly_downloads=None,
                package_age_days=None,
                similar_popular_package=None,
                reasons=["typosquat_check_disabled"],
            )
            for dep in dependencies
        ]

    results: list[TyposquatValidation] = []
    timeout = httpx.Timeout(15.0, connect=5.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        for dep in dependencies:
            similar_popular = _find_similar_popular_package(ecosystem, dep.name)

            # Check if package exists
            if ecosystem == "npm":
                exists, downloads, age_days = await _check_npm_exists(client, dep.name)
            else:
                exists, downloads, age_days = await _check_pypi_exists(client, dep.name)

            # Run typosquat analysis against the similar package (if any)
            typosquat_analysis = {}
            if similar_popular:
                typosquat_analysis = _typosquat_signal(dep.name, similar_popular)

            # Determine risk level
            reasons: list[str] = []
            risk_level = "safe"

            if not exists:
                risk_level = "blocked"
                reasons.append(f"Package '{dep.name}' does not exist on {ecosystem} registry")

            elif similar_popular:
                confidence = typosquat_analysis.get("confidence", 0.0)

                # Check if it's a very new package close to a popular name
                is_very_new = age_days is not None and age_days < 7
                is_low_downloads = downloads is not None and downloads < 100

                if confidence >= settings.typosquat_block_threshold:
                    risk_level = "blocked"
                    reasons.append(
                        f"Package name is suspiciously similar to popular package '{similar_popular}' "
                        f"(confidence: {confidence:.0%})"
                    )
                elif confidence >= 0.5:
                    if is_very_new and is_low_downloads:
                        risk_level = "blocked"
                        reasons.append(
                            f"New package (created {age_days} days ago) with very low downloads "
                            f"and similar to '{similar_popular}'"
                        )
                    else:
                        risk_level = "warning"
                        reasons.append(
                            f"Package name is somewhat similar to popular package '{similar_popular}' "
                            f"(confidence: {confidence:.0%})"
                        )
                elif is_very_new and is_low_downloads:
                    risk_level = "warning"
                    reasons.append(
                        f"Very new package ({age_days} days old) with low downloads, "
                        f"name somewhat resembles '{similar_popular}'"
                    )

            results.append(TyposquatValidation(
                package_name=dep.name,
                package_version=dep.version,
                risk_level=risk_level,
                exists_on_registry=exists,
                typosquat_analysis=typosquat_analysis,
                monthly_downloads=downloads,
                package_age_days=age_days,
                similar_popular_package=similar_popular,
                reasons=reasons,
            ))

    return results
