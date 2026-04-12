"""Shared helpers for fetching and flattening dependency manifests.

These utilities are shared between the dependency-tree endpoint
(``repos.py``) and the scan orchestrator so manifest-fetching logic
is not duplicated.
"""

from __future__ import annotations

import base64
import asyncio
import json
import logging
import re
from dataclasses import dataclass

import httpx
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PackageRef:
    """Identity of a single dependency in a tree."""
    name: str
    version: str


@dataclass(frozen=True)
class NpmScanWorkload:
    """Precomputed npm workload used by scan orchestration.

    Attributes:
        total_dependency_nodes: Total dependency nodes in the lockfile/tree
            excluding project root.
        unique_packages: Unique package identities (name@version) to scan.
        refs: Concrete package references scheduled for scan.
    """

    total_dependency_nodes: int
    unique_packages: int
    refs: list[PackageRef]


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


def count_dependency_nodes(tree: dict) -> int:
    """Count dependency nodes in a dependency tree, excluding the root node."""
    total = 0
    stack = list(tree.get("children", []))
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        total += 1
        children = node.get("children", [])
        if isinstance(children, list):
            stack.extend(children)
    return total


def _collect(node: dict, seen: set[str], out: list[PackageRef]) -> None:
    """Recursively flatten one tree node into unique package references.

    Args:
        node: Dependency tree node.
        seen: Set of ``name@version`` keys already emitted.
        out: Output list of collected package references.
    """
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


def build_npm_scan_workload(manifest: dict, tree: dict) -> NpmScanWorkload:
    """Build npm scan workload metrics from lockfile-first data.

    If a v2+ lockfile ``packages`` map is present, metrics and scan refs are
    computed directly from that map because it is the most complete dependency
    source for scanning. Otherwise it falls back to the normalized tree.
    """
    packages = manifest.get("packages")
    if isinstance(packages, dict) and packages:
        total_dependency_nodes = 0
        refs: list[PackageRef] = []
        seen: set[str] = set()

        for pkg_path, entry in packages.items():
            if pkg_path == "":
                continue
            if not isinstance(entry, dict):
                continue
            total_dependency_nodes += 1

            name = entry.get("name")
            version = entry.get("version")

            if not isinstance(name, str) or not name:
                tail = pkg_path.rsplit("/node_modules/", 1)[-1]
                name = tail or None
            if not isinstance(version, str) or not version:
                continue
            if not isinstance(name, str) or not name:
                continue

            key = f"{name}@{version}"
            if key in seen:
                continue
            seen.add(key)
            refs.append(PackageRef(name=name, version=version))

        return NpmScanWorkload(
            total_dependency_nodes=total_dependency_nodes,
            unique_packages=len(refs),
            refs=refs,
        )

    refs = flatten_dependencies(tree)
    return NpmScanWorkload(
        total_dependency_nodes=count_dependency_nodes(tree),
        unique_packages=len(refs),
        refs=refs,
    )


def build_pypi_dependency_tree(manifest: dict) -> dict:
    """Build a shallow dependency tree for a PyPI repository.

    The GitHub ``requirements.txt`` format does not expose nested dependency
    relationships, so the backend represents direct requirements as children of
    a project root node. This keeps the tree compatible with the existing graph
    view and the scan-result highlighting logic.
    """
    project_name = manifest.get("name") or "project"
    project_version = manifest.get("version") or "0.0.0"

    deps = manifest.get("dependencies", {})
    if not isinstance(deps, dict):
        deps = {}

    children = [
        {"name": name, "version": version or "unknown", "children": []}
        for name, version in deps.items()
        if name
    ]

    return {
        "name": str(project_name),
        "version": str(project_version),
        "children": children,
    }


_REQUIRES_DIST_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)")


def _parse_requires_dist_entry(entry: str) -> str | None:
    """Extract a dependency package name from a single ``requires_dist`` entry."""
    if not isinstance(entry, str):
        return None
    match = _REQUIRES_DIST_NAME_RE.match(entry)
    if not match:
        return None
    return match.group(1)


async def _fetch_pypi_package_metadata(
    client: httpx.AsyncClient,
    package_name: str,
    version_hint: str,
) -> tuple[str, str, list[str]]:
    """Fetch package metadata from PyPI and return name, resolved version and child names.

    Tries ``/name/version/json`` for exact version hints first, then falls back to
    ``/name/json`` (latest release metadata).
    """
    normalized_hint = (version_hint or "").strip()
    try_version_first = bool(normalized_hint) and normalized_hint not in {"latest", "*"}

    urls_to_try: list[str] = []
    if try_version_first:
        urls_to_try.append(f"https://pypi.org/pypi/{package_name}/{normalized_hint}/json")
    urls_to_try.append(f"https://pypi.org/pypi/{package_name}/json")

    payload: dict | None = None
    for url in urls_to_try:
        try:
            resp = await client.get(url)
        except httpx.RequestError as exc:
            logger.warning(
                "PyPI metadata request failed for %s (%s): %s",
                package_name,
                url,
                exc.__class__.__name__,
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"PyPI request failed for {package_name}",
            ) from exc
        if resp.status_code == status.HTTP_404_NOT_FOUND:
            continue
        if resp.is_error:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"PyPI API error while fetching metadata for {package_name}: {resp.status_code}",
            )
        body = resp.json()
        if isinstance(body, dict):
            payload = body
            break

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"PyPI package metadata not found for {package_name}",
        )

    info = payload.get("info", {})
    if not isinstance(info, dict):
        info = {}

    resolved_name = info.get("name")
    if not isinstance(resolved_name, str) or not resolved_name:
        resolved_name = package_name

    resolved_version = info.get("version")
    if not isinstance(resolved_version, str) or not resolved_version:
        resolved_version = normalized_hint or "unknown"

    requires_dist = info.get("requires_dist")
    if not isinstance(requires_dist, list):
        requires_dist = []

    child_names: list[str] = []
    for dep in requires_dist:
        parsed_name = _parse_requires_dist_entry(dep)
        if parsed_name:
            child_names.append(parsed_name)

    return resolved_name, resolved_version, child_names


async def build_pypi_dependency_tree_deep(
    client: httpx.AsyncClient,
    manifest: dict,
    *,
    max_depth: int = 5,
    max_children: int = 25,
    max_concurrency: int = 8,
) -> dict:
    """Build a recursive PyPI dependency tree using metadata from PyPI JSON API."""
    project_name = manifest.get("name") or "project"
    project_version = manifest.get("version") or "0.0.0"

    deps = manifest.get("dependencies", {})
    if not isinstance(deps, dict):
        deps = {}

    metadata_cache: dict[tuple[str, str], tuple[str, str, list[str]]] = {}
    expanded_nodes: set[str] = set()
    fetch_semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def _resolve_node(
        pkg_name: str,
        version_hint: str,
        depth: int,
        lineage: set[str],
    ) -> dict:
        normalized_name = pkg_name.lower()
        node = {
            "name": pkg_name,
            "version": version_hint or "unknown",
            "children": [],
        }

        if depth >= max_depth or normalized_name in lineage:
            return node

        cache_key = (normalized_name, version_hint or "latest")
        if cache_key in metadata_cache:
            resolved_name, resolved_version, child_names = metadata_cache[cache_key]
        else:
            try:
                async with fetch_semaphore:
                    resolved_name, resolved_version, child_names = await _fetch_pypi_package_metadata(
                        client=client,
                        package_name=pkg_name,
                        version_hint=version_hint,
                    )
            except HTTPException:
                return node
            metadata_cache[cache_key] = (resolved_name, resolved_version, child_names)

        node["name"] = resolved_name
        node["version"] = resolved_version

        resolved_key = f"{resolved_name.lower()}@{resolved_version}"
        if resolved_key in expanded_nodes:
            return node
        expanded_nodes.add(resolved_key)

        next_lineage = set(lineage)
        next_lineage.add(resolved_name.lower())

        deduped_child_names = list(dict.fromkeys(child_names))[:max_children]
        children = await asyncio.gather(
            *[
                _resolve_node(
                    pkg_name=child_name,
                    version_hint="latest",
                    depth=depth + 1,
                    lineage=next_lineage,
                )
                for child_name in deduped_child_names
            ]
        )
        node["children"] = children
        return node

    children = await asyncio.gather(
        *[
            _resolve_node(dep_name, str(dep_version) if dep_version else "latest", 0, set())
            for dep_name, dep_version in deps.items()
            if dep_name
        ]
    )

    return {
        "name": str(project_name),
        "version": str(project_version),
        "children": children,
    }
