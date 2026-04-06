"""Download package artifacts from npm and PyPI registries."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

_NPM_REGISTRY = "https://registry.npmjs.org"
_PYPI_JSON_API = "https://pypi.org/pypi"

# Reusable timeout for registry requests.
_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


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
