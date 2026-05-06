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
from dataclasses import asdict, dataclass

import httpx
from fastapi import HTTPException, status

from app.services import package_fetcher

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PackageRef:
    """Identity of a single dependency in a tree."""
    name: str
    version: str
    resolution: dict | None = None


@dataclass(frozen=True)
class DependencyResolution:
    """Provenance and version-resolution metadata for a dependency node."""

    source: str
    resolution_kind: str
    is_direct_dependency: bool
    transitive_depth: int
    requested_spec: str | None = None
    resolved_version: str | None = None
    resolved_artifact: bool = False
    is_exact_version: bool | None = None
    is_version_range: bool | None = None


_EXACT_NPM_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
_PYPI_SPEC_RE = re.compile(r"^(==|!=|~=|>=|<=|>|<)\s*(.+)$")
_PYPI_SPEC_TOKEN_RE = re.compile(r"(==|!=|~=|>=|<=|>|<)\s*([^,\s;]+)")


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


def _resolution_payload(resolution: DependencyResolution | None) -> dict | None:
    if resolution is None:
        return None
    return asdict(resolution)


def _is_exact_npm_version(spec: str | None) -> bool:
    if not spec:
        return False
    return bool(_EXACT_NPM_VERSION_RE.match(spec.strip()))


def _normalize_npm_spec(spec: str | None) -> str | None:
    if spec is None:
        return None
    cleaned = spec.strip()
    return cleaned or None


def _coerce_manifest_dependency_spec(value: object) -> str | None:
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    if isinstance(value, dict):
        raw = value.get("requested_spec") or value.get("version")
        if isinstance(raw, str):
            cleaned = raw.strip()
            return cleaned or None
    return None


def _make_node(
    name: str,
    version: str,
    *,
    resolution: DependencyResolution | None = None,
    children: list[dict] | None = None,
) -> dict:
    return {
        "name": name,
        "version": version,
        "children": children or [],
        "resolution": _resolution_payload(resolution),
    }


def _latest_version_from_registry(versions: list[str], *, is_pypi: bool) -> str | None:
    cleaned = [version for version in versions if isinstance(version, str) and version]
    if not cleaned:
        return None

    def _sort_key(value: str) -> tuple:
        parts = re.split(r"[.+-]", value)
        numeric_parts: list[int] = []
        for part in parts:
            if part.isdigit():
                numeric_parts.append(int(part))
            else:
                break
        if len(numeric_parts) < 3:
            numeric_parts.extend([0] * (3 - len(numeric_parts)))
        return tuple(numeric_parts + [value])

    return max(cleaned, key=_sort_key)


def _resolve_npm_version_spec(
    package_name: str,
    requested_spec: str | None,
    *,
    versions: list[str] | None = None,
) -> tuple[str, DependencyResolution]:
    spec = _normalize_npm_spec(requested_spec)
    if spec is None or spec in {"latest", "*"}:
        resolved_version = _select_matching_version(versions or [], spec, ecosystem="npm")
        resolved_version = resolved_version or spec or "unknown"
        return resolved_version, DependencyResolution(
            source="npm-manifest",
            resolution_kind="unresolved-intent" if spec is None else "floating-range",
            is_direct_dependency=True,
            transitive_depth=1,
            requested_spec=spec,
            resolved_version=resolved_version,
            resolved_artifact=resolved_version != "unknown",
            is_exact_version=False,
            is_version_range=spec is not None,
        )

    if _is_exact_npm_version(spec):
        return spec, DependencyResolution(
            source="npm-manifest",
            resolution_kind="exact",
            is_direct_dependency=True,
            transitive_depth=1,
            requested_spec=spec,
            resolved_version=spec,
            resolved_artifact=True,
            is_exact_version=True,
            is_version_range=False,
        )

    resolved_version = _select_matching_version(versions or [], spec, ecosystem="npm") or spec
    return resolved_version, DependencyResolution(
        source="npm-manifest",
        resolution_kind="resolved-range",
        is_direct_dependency=True,
        transitive_depth=1,
        requested_spec=spec,
        resolved_version=resolved_version,
        resolved_artifact=resolved_version is not None,
        is_exact_version=False,
        is_version_range=True,
    )


def _resolve_pypi_version_spec(
    package_name: str,
    requested_spec: str | None,
    *,
    versions: list[str] | None = None,
) -> tuple[str, DependencyResolution]:
    spec = _normalize_npm_spec(requested_spec)
    if spec is None or spec in {"latest", "*"}:
        resolved_version = _select_matching_version(versions or [], spec, ecosystem="pypi")
        resolved_version = resolved_version or spec or "unknown"
        return resolved_version, DependencyResolution(
            source="pypi-manifest",
            resolution_kind="unresolved-intent" if spec is None else "floating-range",
            is_direct_dependency=True,
            transitive_depth=1,
            requested_spec=spec,
            resolved_version=resolved_version,
            resolved_artifact=resolved_version != "unknown",
            is_exact_version=False,
            is_version_range=spec is not None,
        )

    match = _PYPI_SPEC_RE.match(spec)
    if match and match.group(1) == "==":
        exact_version = match.group(2).strip()
        return exact_version, DependencyResolution(
            source="pypi-manifest",
            resolution_kind="exact",
            is_direct_dependency=True,
            transitive_depth=1,
            requested_spec=spec,
            resolved_version=exact_version,
            resolved_artifact=True,
            is_exact_version=True,
            is_version_range=False,
        )

    resolved_version = _select_matching_version(versions or [], spec, ecosystem="pypi") or spec
    return resolved_version, DependencyResolution(
        source="pypi-manifest",
        resolution_kind="resolved-range",
        is_direct_dependency=True,
        transitive_depth=1,
        requested_spec=spec,
        resolved_version=resolved_version,
        resolved_artifact=resolved_version is not None,
        is_exact_version=False,
        is_version_range=True,
    )


def _parse_requirement_spec(raw_line: str) -> tuple[str, str | None]:
    line = raw_line.split(";", 1)[0].strip()
    if not line:
        return "", None

    line = line.split("[", 1)[0].strip()
    for separator in ("==", ">=", "<=", "~=", "!=", ">", "<"):
        if separator in line:
            pkg, spec = line.split(separator, 1)
            return pkg.strip(), f"{separator}{spec.strip()}"

    return line.strip(), "latest"


def _version_key(value: str) -> tuple[int, int, int, int, int, str]:
    """Create a coarse ordering key for semver-like and PEP 440-ish versions."""
    cleaned = value.strip().lstrip("v")
    main, _, suffix = cleaned.partition("-")
    parts = [part for part in main.split(".") if part != ""]
    numbers: list[int] = []
    for part in parts[:4]:
        if part.isdigit():
            numbers.append(int(part))
        else:
            digits = re.match(r"(\d+)", part)
            numbers.append(int(digits.group(1)) if digits else 0)
    while len(numbers) < 4:
        numbers.append(0)
    prerelease_rank = 0 if suffix else 1
    return numbers[0], numbers[1], numbers[2], numbers[3], prerelease_rank, cleaned


def _compare_version_values(left: str, right: str) -> int:
    left_key = _version_key(left)
    right_key = _version_key(right)
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def _max_version(versions: list[str]) -> str | None:
    cleaned = [version for version in versions if isinstance(version, str) and version]
    if not cleaned:
        return None
    return max(cleaned, key=_version_key)


def _npm_compatible_upper_bound(version: str) -> str:
    major, minor, patch, *_ = _version_key(version)
    if major > 0:
        return f"{major + 1}.0.0"
    if minor > 0:
        return f"0.{minor + 1}.0"
    return f"0.0.{patch + 1}"


def _npm_matches_spec(version: str, spec: str) -> bool:
    spec = spec.strip()
    if not spec or spec in {"*", "latest"}:
        return True
    if _is_exact_npm_version(spec):
        return _compare_version_values(version, spec) == 0
    if spec.startswith("^"):
        base = spec[1:].strip()
        if not _is_exact_npm_version(base):
            return False
        return _compare_version_values(version, base) >= 0 and _compare_version_values(version, _npm_compatible_upper_bound(base)) < 0
    if spec.startswith("~"):
        base = spec[1:].strip()
        if not _is_exact_npm_version(base):
            return False
        major, minor, patch, *_ = _version_key(base)
        upper = f"{major}.{minor + 1}.0"
        return _compare_version_values(version, base) >= 0 and _compare_version_values(version, upper) < 0

    comparator_groups = [group for group in re.split(r"[ ,]+", spec) if group]
    if comparator_groups and all(group[:2] in {">=", "<=", "!=", "=="} or group[:1] in {">", "<", "="} for group in comparator_groups):
        for token in comparator_groups:
            op = token[:2] if token[:2] in {">=", "<=", "!=", "=="} else token[:1]
            operand = token[len(op):].strip()
            if not operand:
                continue
            cmp_result = _compare_version_values(version, operand)
            if op == "==" or op == "=":
                if cmp_result != 0:
                    return False
            elif op == "!=":
                if cmp_result == 0:
                    return False
            elif op == ">=":
                if cmp_result < 0:
                    return False
            elif op == "<=":
                if cmp_result > 0:
                    return False
            elif op == ">":
                if cmp_result <= 0:
                    return False
            elif op == "<":
                if cmp_result >= 0:
                    return False
        return True

    return _compare_version_values(version, spec) == 0


def _pypi_compatible_upper_bound(version: str) -> str:
    major, minor, patch, *_ = _version_key(version)
    if minor > 0 or patch > 0:
        return f"{major}.{minor + 1}.0"
    return f"{major + 1}.0.0"


def _pypi_matches_spec(version: str, spec: str) -> bool:
    spec = spec.strip()
    if not spec or spec in {"*", "latest"}:
        return True
    if spec.startswith("=="):
        return _compare_version_values(version, spec[2:].strip()) == 0

    parts = [part.strip() for part in spec.split(",") if part.strip()]
    if not parts:
        parts = [spec]

    for part in parts:
        match = _PYPI_SPEC_RE.match(part)
        if not match:
            if _compare_version_values(version, part) != 0:
                return False
            continue

        op, operand = match.group(1), match.group(2).strip()
        cmp_result = _compare_version_values(version, operand)
        if op == "==" and cmp_result != 0:
            return False
        if op == "!=" and cmp_result == 0:
            return False
        if op == ">=" and cmp_result < 0:
            return False
        if op == "<=" and cmp_result > 0:
            return False
        if op == ">" and cmp_result <= 0:
            return False
        if op == "<" and cmp_result >= 0:
            return False
        if op == "~=":
            upper_bound = _pypi_compatible_upper_bound(operand)
            if cmp_result < 0 or _compare_version_values(version, upper_bound) >= 0:
                return False
    return True


def _select_matching_version(versions: list[str], spec: str | None, *, ecosystem: str) -> str | None:
    if not versions:
        return None

    cleaned_spec = _normalize_npm_spec(spec)
    if cleaned_spec is None:
        return _max_version(versions)

    if ecosystem == "npm":
        candidates = [version for version in versions if _npm_matches_spec(version, cleaned_spec)]
    else:
        candidates = [version for version in versions if _pypi_matches_spec(version, cleaned_spec)]

    return _max_version(candidates)


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
        pkg, spec = _parse_requirement_spec(line)
        if not pkg:
            continue
        deps[pkg] = spec or "latest"
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
        resolution = node.get("resolution")
        out.append(
            PackageRef(
                name=name,
                version=version,
                resolution=resolution if isinstance(resolution, dict) else None,
            )
        )
    for child in node.get("children", []):
        _collect(child, seen, out)


def flatten_pypi_manifest(manifest: dict) -> list[PackageRef]:
    """Flatten a synthetic PyPI manifest (from ``fetch_pypi_manifest``) into ``PackageRef``s."""
    deps = manifest.get("dependencies", {})
    refs: list[PackageRef] = []
    for name, value in deps.items():
        if not name:
            continue
        requested_spec = None
        resolved_version = None
        resolution = None
        if isinstance(value, dict):
            requested_spec = _coerce_manifest_dependency_spec(value.get("requested_spec"))
            resolved_version = _coerce_manifest_dependency_spec(value.get("resolved_version")) or _coerce_manifest_dependency_spec(value.get("version"))
            resolution = value.get("resolution") if isinstance(value.get("resolution"), dict) else None
        elif isinstance(value, str):
            requested_spec = value
            resolved_version = value
        refs.append(
            PackageRef(
                name=name,
                version=resolved_version or requested_spec or "unknown",
                resolution=resolution,
            )
        )
    return refs


def build_npm_scan_workload(manifest: dict, tree: dict) -> NpmScanWorkload:
    """Build npm scan workload metrics from lockfile-first data.

    Scan workload is derived from the normalized dependency tree so scan counts
    match what the dependency graph endpoint exposes to clients.
    """
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

    children = []
    for name, version in deps.items():
        if not name:
            continue
        requested_spec = _coerce_manifest_dependency_spec(version)
        resolved_version, resolution = _resolve_pypi_version_spec(name, requested_spec)
        children.append(
            _make_node(
                name,
                resolved_version,
                resolution=DependencyResolution(
                    **{
                        **asdict(resolution),
                        "is_direct_dependency": True,
                        "transitive_depth": 1,
                    }
                ),
                children=[],
            )
        )

    return _make_node(str(project_name), str(project_version), children=children)


def _find_npm_lockfile_entry(packages: dict, dep_name: str, parent_path: str) -> tuple[str | None, dict | None]:
    """Locate the closest npm lockfile entry for a dependency name."""
    direct_path = f"{parent_path}/node_modules/{dep_name}" if parent_path else f"node_modules/{dep_name}"
    direct_entry = packages.get(direct_path)
    if isinstance(direct_entry, dict):
        return direct_path, direct_entry

    fallback_root = f"node_modules/{dep_name}"
    fallback_entry = packages.get(fallback_root)
    if isinstance(fallback_entry, dict):
        return fallback_root, fallback_entry

    for key, value in packages.items():
        if key.endswith(f"/node_modules/{dep_name}") and isinstance(value, dict):
            return key, value

    return None, None


def _resolve_npm_lockfile_node(
    dep_name: str,
    packages: dict,
    parent_path: str,
    seen_paths: set[str],
    depth: int,
    requested_spec: str | None,
) -> dict:
    dep_path, dep_entry = _find_npm_lockfile_entry(packages, dep_name, parent_path)
    if dep_entry is None:
        resolved_version = requested_spec or "unknown"
        return _make_node(
            dep_name,
            resolved_version,
            resolution=DependencyResolution(
                source="npm-lockfile",
                resolution_kind="unresolved-intent",
                is_direct_dependency=depth == 1,
                transitive_depth=depth,
                requested_spec=requested_spec,
                resolved_version=None,
                resolved_artifact=False,
                is_exact_version=_is_exact_npm_version(requested_spec),
                is_version_range=not _is_exact_npm_version(requested_spec) if requested_spec else None,
            ),
        )

    if dep_path in seen_paths:
        resolved_version = str(dep_entry.get("version") or requested_spec or "unknown")
        return _make_node(
            dep_name,
            resolved_version,
            resolution=DependencyResolution(
                source="npm-lockfile",
                resolution_kind="resolved",
                is_direct_dependency=depth == 1,
                transitive_depth=depth,
                requested_spec=requested_spec,
                resolved_version=resolved_version,
                resolved_artifact=True,
                is_exact_version=_is_exact_npm_version(requested_spec),
                is_version_range=not _is_exact_npm_version(requested_spec) if requested_spec else None,
            ),
        )

    nested = dep_entry.get("dependencies", {})
    if not isinstance(nested, dict):
        nested = {}

    child_seen = set(seen_paths)
    if dep_path is not None:
        child_seen.add(dep_path)

    children = [
        _resolve_npm_lockfile_node(
            child_name,
            packages,
            dep_path or parent_path,
            child_seen,
            depth + 1,
            _coerce_manifest_dependency_spec(child_payload),
        )
        for child_name, child_payload in nested.items()
        if child_name
    ]

    resolved_version = str(dep_entry.get("version") or requested_spec or "unknown")
    return _make_node(
        dep_name,
        resolved_version,
        resolution=DependencyResolution(
            source="npm-lockfile",
            resolution_kind="resolved",
            is_direct_dependency=depth == 1,
            transitive_depth=depth,
            requested_spec=requested_spec,
            resolved_version=resolved_version,
            resolved_artifact=True,
            is_exact_version=_is_exact_npm_version(requested_spec),
            is_version_range=not _is_exact_npm_version(requested_spec) if requested_spec else None,
        ),
        children=children,
    )


def _resolve_npm_lockfile_tree(lockfile: dict) -> dict:
    project_name = lockfile.get("name") or "project"
    project_version = lockfile.get("version") or "0.0.0"

    packages = lockfile.get("packages")
    if isinstance(packages, dict) and packages:
        root_pkg = packages.get("") if isinstance(packages.get(""), dict) else {}
        if isinstance(root_pkg, dict):
            project_name = root_pkg.get("name") or project_name
            project_version = root_pkg.get("version") or project_version

        root_dependencies = root_pkg.get("dependencies", {}) if isinstance(root_pkg, dict) else {}
        if not isinstance(root_dependencies, dict):
            root_dependencies = {}

        children = [
            _resolve_npm_lockfile_node(
                dep_name,
                packages,
                "",
                set(),
                1,
                _coerce_manifest_dependency_spec(dep_spec),
            )
            for dep_name, dep_spec in root_dependencies.items()
            if dep_name
        ]
        return _make_node(
            str(project_name),
            str(project_version),
            children=children,
            resolution=DependencyResolution(
                source="npm-lockfile",
                resolution_kind="root",
                is_direct_dependency=False,
                transitive_depth=0,
                resolved_version=str(project_version),
                resolved_artifact=True,
            ),
        )

    dependencies = lockfile.get("dependencies", {})
    if not isinstance(dependencies, dict):
        dependencies = {}

    def _resolve_v1_node(
        dep_name: str,
        dep_payload: dict,
        seen_names: set[str],
        depth: int,
        requested_spec: str | None,
    ) -> dict:
        if dep_name in seen_names:
            resolved_version = str(dep_payload.get("version") or requested_spec or "unknown")
            return _make_node(
                dep_name,
                resolved_version,
                resolution=DependencyResolution(
                    source="npm-lockfile",
                    resolution_kind="resolved",
                    is_direct_dependency=depth == 1,
                    transitive_depth=depth,
                    requested_spec=requested_spec,
                    resolved_version=resolved_version,
                    resolved_artifact=True,
                    is_exact_version=_is_exact_npm_version(requested_spec),
                    is_version_range=not _is_exact_npm_version(requested_spec) if requested_spec else None,
                ),
            )

        nested = dep_payload.get("dependencies", {})
        if not isinstance(nested, dict):
            nested = {}

        child_seen = set(seen_names)
        child_seen.add(dep_name)
        children = [
            _resolve_v1_node(
                child_name,
                child_payload,
                child_seen,
                depth + 1,
                _coerce_manifest_dependency_spec(child_payload),
            )
            for child_name, child_payload in nested.items()
            if isinstance(child_payload, dict)
        ]

        resolved_version = str(dep_payload.get("version") or requested_spec or "unknown")
        return _make_node(
            dep_name,
            resolved_version,
            resolution=DependencyResolution(
                source="npm-lockfile",
                resolution_kind="resolved",
                is_direct_dependency=depth == 1,
                transitive_depth=depth,
                requested_spec=requested_spec,
                resolved_version=resolved_version,
                resolved_artifact=True,
                is_exact_version=_is_exact_npm_version(requested_spec),
                is_version_range=not _is_exact_npm_version(requested_spec) if requested_spec else None,
            ),
            children=children,
        )

    children = [
        _resolve_v1_node(dep_name, dep_payload, set(), 1, _coerce_manifest_dependency_spec(dep_payload))
        for dep_name, dep_payload in dependencies.items()
        if isinstance(dep_payload, dict)
    ]
    return _make_node(
        str(project_name),
        str(project_version),
        children=children,
        resolution=DependencyResolution(
            source="npm-lockfile",
            resolution_kind="root",
            is_direct_dependency=False,
            transitive_depth=0,
            resolved_version=str(project_version),
            resolved_artifact=True,
        ),
    )


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

    direct_versions: dict[str, list[str]] = {}
    direct_latest: dict[str, str | None] = {}
    if deps:
        direct_sem = asyncio.Semaphore(max(1, max_concurrency))

        async def _prefetch_direct(dep_name: str, dep_spec: object) -> None:
            requested_spec = _coerce_manifest_dependency_spec(dep_spec)
            async with direct_sem:
                try:
                    versions_resp = await package_fetcher.list_pypi_package_versions(dep_name, client=client)
                except Exception:
                    direct_versions[dep_name] = []
                    direct_latest[dep_name] = None
                    return

            if isinstance(versions_resp, dict):
                direct_versions[dep_name] = [version for version in versions_resp.get("versions", []) if isinstance(version, str)]
                direct_latest[dep_name] = versions_resp.get("latest_version") if isinstance(versions_resp.get("latest_version"), str) else None
            else:
                direct_versions[dep_name] = []
                direct_latest[dep_name] = None

        await asyncio.gather(
            *[
                _prefetch_direct(dep_name, dep_spec)
                for dep_name, dep_spec in deps.items()
                if dep_name
            ]
        )

    metadata_cache: dict[tuple[str, str], tuple[str, str, list[str]]] = {}
    expanded_nodes: set[str] = set()
    fetch_semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def _resolve_node(
        pkg_name: str,
        version_hint: str,
        depth: int,
        lineage: set[str],
        *,
        direct_dependency: bool,
        requested_spec: str | None,
    ) -> dict:
        normalized_name = pkg_name.lower()
        node = _make_node(
            pkg_name,
            version_hint or "unknown",
            resolution=DependencyResolution(
                source="pypi-metadata",
                resolution_kind="unresolved-intent" if not requested_spec else "resolved",
                is_direct_dependency=direct_dependency,
                transitive_depth=depth,
                requested_spec=requested_spec,
                resolved_version=version_hint or None,
                resolved_artifact=False,
                is_exact_version=requested_spec.startswith("==") if requested_spec else None,
                is_version_range=(requested_spec is not None and not requested_spec.startswith("==")) if requested_spec else None,
            ),
            children=[],
        )

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
        node["resolution"] = _resolution_payload(
            DependencyResolution(
                source="pypi-metadata",
                resolution_kind="resolved",
                is_direct_dependency=direct_dependency,
                transitive_depth=depth,
                requested_spec=requested_spec,
                resolved_version=resolved_version,
                resolved_artifact=True,
                is_exact_version=requested_spec.startswith("==") if requested_spec else None,
                is_version_range=(requested_spec is not None and not requested_spec.startswith("==")) if requested_spec else None,
            )
        )

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
                    direct_dependency=False,
                    requested_spec=None,
                )
                for child_name in deduped_child_names
            ]
        )
        node["children"] = children
        return node

    children = await asyncio.gather(
        *[
            _resolve_node(
                dep_name,
                _select_matching_version(
                    direct_versions.get(dep_name, []),
                    _coerce_manifest_dependency_spec(dep_version),
                    ecosystem="pypi",
                )
                or direct_latest.get(dep_name)
                or str(dep_version)
                or "latest",
                1,
                set(),
                direct_dependency=True,
                requested_spec=_coerce_manifest_dependency_spec(dep_version),
            )
            for dep_name, dep_version in deps.items()
            if dep_name
        ]
    )

    return {
        "name": str(project_name),
        "version": str(project_version),
        "children": children,
        "resolution": _resolution_payload(
            DependencyResolution(
                source="pypi-manifest",
                resolution_kind="root",
                is_direct_dependency=False,
                transitive_depth=0,
                resolved_version=str(project_version),
                resolved_artifact=True,
            )
        ),
    }


async def resolve_npm_dependency_tree(
    client: httpx.AsyncClient,
    manifest: dict,
) -> dict:
    """Build an npm dependency tree with explicit resolution metadata."""
    project_name = manifest.get("name") or "project"
    project_version = manifest.get("version") or "0.0.0"

    packages = manifest.get("packages")
    if isinstance(packages, dict) and packages:
        return _resolve_npm_lockfile_tree(manifest)

    dependencies = manifest.get("dependencies", {})
    if not isinstance(dependencies, dict):
        dependencies = {}

    children: list[dict] = []
    for dep_name, dep_spec in dependencies.items():
        if not dep_name:
            continue
        requested_spec = _coerce_manifest_dependency_spec(dep_spec)
        versions_resp = await package_fetcher.list_npm_package_versions(dep_name, client=client)
        available_versions = versions_resp.get("versions", []) if isinstance(versions_resp, dict) else []
        latest_version = versions_resp.get("latest_version") if isinstance(versions_resp, dict) else None
        resolved_version, resolution = _resolve_npm_version_spec(dep_name, requested_spec, versions=available_versions)
        if resolved_version in {None, "unknown"} and isinstance(latest_version, str) and latest_version:
            resolved_version = latest_version
            resolution = DependencyResolution(
                **{**asdict(resolution), "resolved_version": resolved_version, "resolved_artifact": True}
            )

        children.append(
            _make_node(
                dep_name,
                resolved_version,
                resolution=DependencyResolution(
                    **{
                        **asdict(resolution),
                        "source": "npm-registry",
                        "is_direct_dependency": True,
                        "transitive_depth": 1,
                    }
                ),
                children=[],
            )
        )

    return _make_node(
        str(project_name),
        str(project_version),
        children=children,
        resolution=DependencyResolution(
            source="npm-manifest",
            resolution_kind="root",
            is_direct_dependency=False,
            transitive_depth=0,
            resolved_version=str(project_version),
            resolved_artifact=True,
        ),
    )
