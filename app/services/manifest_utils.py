"""Shared helpers for fetching and flattening dependency manifests.

These utilities are shared between the dependency-tree endpoint
(``repos.py``) and the scan orchestrator so manifest-fetching logic
is not duplicated.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass

import httpx
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PackageRef:
    """Identity of a single dependency in a tree."""
    name: str
    version: str


def decode_github_content(payload: dict) -> str:
    """Decode Base64-encoded file content returned by the GitHub Contents API."""
    encoded = payload.get("content")
    if not isinstance(encoded, str):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unexpected GitHub content response",
        )
    sanitized = encoded.replace("\n", "")
    return base64.b64decode(sanitized).decode("utf-8")


# ── GitHub manifest fetching ───────────────────────────────────────────

async def fetch_npm_manifest(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    headers: dict[str, str],
) -> dict:
    """Fetch ``package-lock.json`` (preferred) or ``package.json`` from GitHub.

    Returns the parsed JSON dict.  Raises HTTPException on failure.
    """
    lockfile_resp = await client.get(
        f"https://api.github.com/repos/{owner}/{repo}/contents/package-lock.json",
        headers=headers,
    )

    if lockfile_resp.status_code == status.HTTP_404_NOT_FOUND:
        pkg_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/package.json",
            headers=headers,
        )
        if pkg_resp.status_code == status.HTTP_404_NOT_FOUND:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No NPM manifest files found.",
            )
        if pkg_resp.is_error:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"GitHub API error while fetching package.json: {pkg_resp.status_code}",
            )
        content = decode_github_content(pkg_resp.json())
        return json.loads(content)

    if lockfile_resp.is_error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub API error while fetching package-lock.json: {lockfile_resp.status_code}",
        )

    content = decode_github_content(lockfile_resp.json())
    return json.loads(content)


async def fetch_pypi_manifest(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    headers: dict[str, str],
) -> dict:
    """Fetch ``requirements.txt`` from GitHub and return a synthetic manifest.

    Returns ``{"dependencies": {"pkg": "version", …}}``.
    """
    resp = await client.get(
        f"https://api.github.com/repos/{owner}/{repo}/contents/requirements.txt",
        headers=headers,
    )
    if resp.status_code == status.HTTP_404_NOT_FOUND:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No requirements.txt found.",
        )
    if resp.is_error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub API error while fetching requirements.txt: {resp.status_code}",
        )

    content = decode_github_content(resp.json())
    deps: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle ==, >=, ~= etc.
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
            if sep in line:
                pkg, ver = line.split(sep, 1)
                # Strip extras like [extra]
                pkg = pkg.split("[")[0].strip()
                deps[pkg] = ver.strip()
                break
        else:
            pkg = line.split("[")[0].strip()
            deps[pkg] = "latest"
    return {"dependencies": deps}


# ── Tree flattening ───────────────────────────────────────────────────

def _walk_tree(node: dict, seen: set[str]) -> None:
    """Recursively collect unique (name, version) pairs from a tree node."""
    name = node.get("name", "")
    version = node.get("version", "unknown")
    key = f"{name}@{version}"
    if key in seen:
        return
    seen.add(key)
    for child in node.get("children", []):
        _walk_tree(child, seen)


def flatten_dependencies(tree: dict) -> list[PackageRef]:
    """Walk a dependency tree and return unique ``PackageRef``s (excluding the root)."""
    refs: list[PackageRef] = []
    seen: set[str] = set()

    # Skip the root node itself – it's the project, not a dependency.
    for child in tree.get("children", []):
        _collect(child, seen, refs)

    return refs


def _collect(node: dict, seen: set[str], out: list[PackageRef]) -> None:
    name = node.get("name", "")
    version = node.get("version", "unknown")
    key = f"{name}@{version}"
    if key not in seen and name:
        seen.add(key)
        out.append(PackageRef(name=name, version=version))
    for child in node.get("children", []):
        _collect(child, seen, out)


def flatten_pypi_manifest(manifest: dict) -> list[PackageRef]:
    """Flatten a synthetic PyPI manifest (from ``fetch_pypi_manifest``) into ``PackageRef``s."""
    deps = manifest.get("dependencies", {})
    return [PackageRef(name=n, version=v) for n, v in deps.items() if n]
