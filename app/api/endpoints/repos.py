import base64
import json
import logging
import time as _time

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import get_current_user, require_authenticated_token
from app.api.schemas.dependency import (
    AddDependencyRequest,
    AddDependencyResponse,
    DependencySpec,
    PackageDetailsResponse,
    PackagePrescanResult,
    PackageSearchResponse,
    PackageVersionsResponse,
    PrescanResponse,
)
from app.core.config import settings
from app.core.github_app import get_app_jwt
from app.models.user import User
from app.services import manifest_utils, package_fetcher, pr_creator, reputation_service, typosquat_guard
from app.services.scan_orchestrator import prescan_packages_full

router = APIRouter(tags=["Repositories"])
logger = logging.getLogger(__name__)


def _decode_github_content(payload: dict) -> str:
    """Decode GitHub Contents API payload content.

    Args:
        payload: Raw GitHub file-content response object.

    Returns:
        str: UTF-8 decoded file content.

    Raises:
        HTTPException: If payload content is missing or malformed.
    """
    encoded = payload.get("content")
    if not isinstance(encoded, str):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unexpected GitHub content response",
        )
    sanitized = encoded.replace("\n", "")
    return base64.b64decode(sanitized).decode("utf-8")


def _simplified_dep(name: str, version: str | None, children: list[dict] | None = None) -> dict:
    """Build a normalized dependency-node representation.

    Args:
        name: Package name.
        version: Package version.
        children: Child dependency nodes.

    Returns:
        dict: Dependency node in the API response shape.
    """
    return {
        "name": name,
        "version": version or "unknown",
        "children": children or [],
    }


def _resolve_v1_tree(dep_name: str, dep_payload: dict, seen: set[str]) -> dict:
    """Resolve one dependency subtree from lockfile v1 format.

    Args:
        dep_name: Dependency name.
        dep_payload: Dependency payload from lockfile.
        seen: Dependency names already traversed to avoid cycles.

    Returns:
        dict: Normalized dependency node with descendants.
    """
    if dep_name in seen:
        return _simplified_dep(dep_name, dep_payload.get("version"))

    nested = dep_payload.get("dependencies", {})
    if not isinstance(nested, dict):
        nested = {}

    child_seen = set(seen)
    child_seen.add(dep_name)
    children = [
        _resolve_v1_tree(child_name, child_payload, child_seen)
        for child_name, child_payload in nested.items()
        if isinstance(child_payload, dict)
    ]
    return _simplified_dep(dep_name, dep_payload.get("version"), children)


def _find_pkg_entry(packages: dict, dep_name: str, parent_path: str) -> tuple[str | None, dict | None]:
    """Locate a dependency entry in lockfile v2 ``packages`` map.

    Args:
        packages: Lockfile ``packages`` mapping.
        dep_name: Dependency name to find.
        parent_path: Parent package path for nearest resolution.

    Returns:
        tuple[str | None, dict | None]: Resolved path and package entry.
    """
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


def _resolve_v2_tree(dep_name: str, packages: dict, parent_path: str, seen_paths: set[str]) -> dict:
    """Resolve one dependency subtree from lockfile v2 format.

    Args:
        dep_name: Dependency name.
        packages: Lockfile ``packages`` mapping.
        parent_path: Parent package path used for closest lookup.
        seen_paths: Package paths already traversed to avoid cycles.

    Returns:
        dict: Normalized dependency node with descendants.
    """
    dep_path, dep_entry = _find_pkg_entry(packages, dep_name, parent_path)
    if dep_entry is None:
        return _simplified_dep(dep_name, None)

    if dep_path in seen_paths:
        return _simplified_dep(dep_name, dep_entry.get("version"))

    nested = dep_entry.get("dependencies", {})
    if not isinstance(nested, dict):
        nested = {}

    child_seen = set(seen_paths)
    child_seen.add(dep_path)
    children = [
        _resolve_v2_tree(child_name, packages, dep_path, child_seen)
        for child_name in nested.keys()
    ]
    return _simplified_dep(dep_name, dep_entry.get("version"), children)


def _build_npm_tree_from_lockfile(lockfile: dict) -> dict:
    """Build a normalized dependency tree from package-lock content."""
    return manifest_utils._resolve_npm_lockfile_tree(lockfile)


def _build_tree_from_package_json(package_json: dict) -> dict:
    """Build a shallow dependency tree from package.json only.

    Args:
        package_json: Parsed ``package.json`` payload.

    Returns:
        dict: Project root node with direct dependencies only.
    """
    project_name = package_json.get("name") or "project"
    project_version = package_json.get("version") or "0.0.0"
    dependencies = package_json.get("dependencies", {})
    if not isinstance(dependencies, dict):
        dependencies = {}

    children = [
        _simplified_dep(dep_name, str(dep_version), [])
        for dep_name, dep_version in dependencies.items()
    ]
    return _simplified_dep(str(project_name), str(project_version), children)


async def _build_pypi_tree_from_manifest(client: httpx.AsyncClient, manifest: dict) -> dict:
    """Build a normalized dependency tree from a synthetic PyPI manifest."""
    try:
        return await manifest_utils.build_pypi_dependency_tree_deep(client, manifest)
    except Exception as exc:
        logger.exception(
            "Falling back to shallow PyPI tree due to deep resolution failure (%s)",
            exc.__class__.__name__,
        )
        return manifest_utils.build_pypi_dependency_tree(manifest)


async def _get_installation_token_for_repo(client: httpx.AsyncClient, owner: str, repo_name: str) -> str:
    """Create a GitHub App installation token for a repository.

    Args:
        client: Shared HTTP client for GitHub requests.
        owner: Repository owner.
        repo_name: Repository name.

    Returns:
        str: Installation access token.

    Raises:
        HTTPException: If installation resolution or token issuance fails.
    """
    app_jwt = get_app_jwt()
    app_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {app_jwt}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    logger.info("GitHub → GET /repos/%s/%s/installation", owner, repo_name)
    installation_resp = await client.get(
        f"https://api.github.com/repos/{owner}/{repo_name}/installation",
        headers=app_headers,
    )
    if installation_resp.status_code == status.HTTP_404_NOT_FOUND:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository installation not found for this GitHub App",
        )
    if installation_resp.is_error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to resolve GitHub App installation: {installation_resp.status_code}",
        )

    installation_id = installation_resp.json().get("id")
    if installation_id is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="GitHub installation response missing id",
        )

    logger.info("GitHub → POST /app/installations/%s/access_tokens", installation_id)
    token_resp = await client.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers=app_headers,
        json={},
    )
    if token_resp.is_error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to create installation token: {token_resp.status_code}",
        )

    installation_token = token_resp.json().get("token")
    if not installation_token:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="GitHub installation token was not returned",
        )
    logger.debug("Installation token obtained for %s/%s (installation_id=%s)", owner, repo_name, installation_id)
    return installation_token


@router.get("/")
async def list_repositories(current_user: User = Depends(get_current_user)) -> list[dict]:
    """List repositories available through user installations.

    Args:
        current_user: Authenticated user with GitHub OAuth token.

    Returns:
        list[dict]: Deduplicated repository summaries.

    Raises:
        HTTPException: If GitHub APIs are unreachable or return an error.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {current_user.access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    install_params = {"per_page": 100}
    repo_params = {"per_page": 100}
    if settings.github_client_id:
        install_params["client_id"] = settings.github_client_id
        repo_params["client_id"] = settings.github_client_id

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            logger.info("GitHub → GET /user/installations  user=%s", current_user.username)
            installations_resp = await client.get(
                "https://api.github.com/user/installations",
                headers=headers,
                params=install_params,
            )

            if installations_resp.status_code == status.HTTP_401_UNAUTHORIZED:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="GitHub token revoked or expired",
                )

            if installations_resp.is_error:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=(
                        "GitHub API error while fetching installations: "
                        f"{installations_resp.status_code}"
                    ),
                )

            installations_payload = installations_resp.json()
            installations = installations_payload.get("installations", [])
            installation_ids = [item.get("id") for item in installations if item.get("id") is not None]
            logger.debug("GitHub installations for %s: %d found", current_user.username, len(installation_ids))

            all_repositories: list[dict] = []
            for installation_id in installation_ids:
                repos_url = (
                    "https://api.github.com/user/installations/"
                    f"{installation_id}/repositories"
                )
                logger.debug("GitHub → GET /user/installations/%s/repositories", installation_id)
                repos_resp = await client.get(repos_url, headers=headers, params=repo_params)

                if repos_resp.status_code == status.HTTP_401_UNAUTHORIZED:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="GitHub token revoked or expired",
                    )

                if repos_resp.is_error:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=(
                            "GitHub API error while fetching installation repositories: "
                            f"{repos_resp.status_code}"
                        ),
                    )

                repos_payload = repos_resp.json()
                repositories = repos_payload.get("repositories", [])
                if not isinstance(repositories, list):
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail="Unexpected response format from GitHub repositories API",
                    )

                all_repositories.extend(repositories)

        unique_by_id: dict[int, dict] = {}
        for repo in all_repositories:
            repo_id = repo.get("id")
            if isinstance(repo_id, int):
                unique_by_id[repo_id] = repo

        logger.info(
            "List repositories → FE: user=%s total_unique=%d",
            current_user.username,
            len(unique_by_id),
        )
        return [
            {
                "id": repo.get("id"),
                "name": repo.get("name"),
                "full_name": repo.get("full_name"),
                "private": repo.get("private"),
                "html_url": repo.get("html_url"),
                "description": repo.get("description"),
                "language": repo.get("language"),
            }
            for repo in unique_by_id.values()
        ]

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach GitHub API while fetching repositories",
        ) from exc


@router.get("/{owner}/{repo_name}/dependencies/npm")
async def get_npm_dependency_tree(
    owner: str,
    repo_name: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return normalized NPM dependency tree for a GitHub repository.

    Args:
        owner: Repository owner.
        repo_name: Repository name.
        current_user: Authenticated user with GitHub OAuth token.

    Returns:
        dict: Dependency tree rooted at project package.

    Raises:
        HTTPException: If manifests are missing, invalid, or GitHub calls fail.
    """
    user_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {current_user.access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            installation_headers: dict[str, str] | None = None
            try:
                installation_token = await _get_installation_token_for_repo(client, owner, repo_name)
                installation_headers = {
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {installation_token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
            except HTTPException as exc:
                if exc.status_code not in {
                    status.HTTP_401_UNAUTHORIZED,
                    status.HTTP_403_FORBIDDEN,
                    status.HTTP_404_NOT_FOUND,
                    status.HTTP_502_BAD_GATEWAY,
                }:
                    raise

            active_headers = installation_headers or user_headers

            logger.info("GitHub → GET /repos/%s/%s/contents/package-lock.json", owner, repo_name)
            lockfile_resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo_name}/contents/package-lock.json",
                headers=active_headers,
            )

            # Fall back to the user OAuth token if app token access is denied.
            """ if installation_headers and lockfile_resp.status_code in {
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_403_FORBIDDEN,
            }:
                lockfile_resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo_name}/contents/package-lock.json",
                    headers=user_headers,
                ) """

            if lockfile_resp.status_code == status.HTTP_404_NOT_FOUND:
                logger.info(
                    "package-lock.json not found, falling back to package.json for %s/%s",
                    owner,
                    repo_name,
                )
                logger.info("GitHub → GET /repos/%s/%s/contents/package.json", owner, repo_name)
                package_json_resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo_name}/contents/package.json",
                    headers=active_headers,
                )

                """ if installation_headers and package_json_resp.status_code in {
                    status.HTTP_401_UNAUTHORIZED,
                    status.HTTP_403_FORBIDDEN,
                }:
                    package_json_resp = await client.get(
                        f"https://api.github.com/repos/{owner}/{repo_name}/contents/package.json",
                        headers=user_headers,
                    ) """

                if package_json_resp.status_code == status.HTTP_404_NOT_FOUND:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="No NPM manifest files found.",
                    )

                if package_json_resp.is_error:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"GitHub API error while fetching package.json: {package_json_resp.status_code}",
                    )

                package_json_content = _decode_github_content(package_json_resp.json())
                package_json = json.loads(package_json_content)
                if not isinstance(package_json, dict):
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail="Invalid package.json format",
                    )
                return _build_tree_from_package_json(package_json)

            if lockfile_resp.is_error:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"GitHub API error while fetching package-lock.json: {lockfile_resp.status_code}",
                )

            lockfile_content = _decode_github_content(lockfile_resp.json())
            lockfile_json = json.loads(lockfile_content)
            if not isinstance(lockfile_json, dict):
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Invalid package-lock.json format",
                )
            tree = _build_npm_tree_from_lockfile(lockfile_json)
            logger.info(
                "NPM dependency tree → FE: owner=%s repo=%s children=%d",
                owner,
                repo_name,
                len(tree.get("children", [])),
            )
            return tree

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach GitHub API while fetching NPM dependencies",
        ) from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to parse NPM manifest JSON content",
        ) from exc


@router.get("/{owner}/{repo_name}/dependencies/pypi")
async def get_pypi_dependency_tree(
    owner: str,
    repo_name: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return a normalized PyPI dependency tree for a GitHub repository.

    Args:
        owner: Repository owner.
        repo_name: Repository name.
        current_user: Authenticated user with GitHub OAuth token.

    Returns:
        dict: Dependency tree rooted at project package.

    Raises:
        HTTPException: If requirements are missing, invalid, or GitHub calls fail.
    """
    user_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {current_user.access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        timeout = httpx.Timeout(connect=10.0, read=20.0, write=20.0, pool=30.0)
        limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
        async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
            logger.info("GitHub → fetching PyPI manifest for %s/%s", owner, repo_name)
            fetched = await manifest_utils.fetch_pypi_manifest(client, owner, repo_name, user_headers)
            tree = await _build_pypi_tree_from_manifest(client, fetched.parsed)
            logger.info(
                "PyPI dependency tree → FE: owner=%s repo=%s children=%d",
                owner,
                repo_name,
                len(tree.get("children", [])),
            )
            return tree

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach GitHub API while fetching PyPI dependencies",
        ) from exc


_PRESCAN_STATUS_EMOJI = {
    "malicious": "🔴",
    "suspicious": "🟠",
    "clean": "🟢",
    "error": "⚪",
    "unknown": "⚪",
}


def _format_static_features(features: dict[str, float] | None, limit: int = 6) -> str:
    """Render the most prominent (highest-scoring) static features as a short string."""
    if not features:
        return ""
    top = sorted(
        ((k, v) for k, v in features.items() if isinstance(v, (int, float)) and v > 0),
        key=lambda kv: kv[1],
        reverse=True,
    )[:limit]
    if not top:
        return ""
    parts = []
    for k, v in top:
        label = k.replace("_", " ")
        val = f"{v * 100:.0f}%" if 0 <= v <= 1 else f"{v:g}"
        parts.append(f"{label} {val}")
    return ", ".join(parts)


def _build_prescan_markdown(results: list[PackagePrescanResult]) -> str:
    """Build a markdown scan summary from in-memory prescan results.

    Mirrors the webhook PR-comment format (see ``webhook._build_scan_report``)
    so the embedded PR-body summary stays consistent with the automated report,
    then appends collapsible per-package details (CVEs, dynamic-analysis findings,
    notable static features) so the full scan is visible inside the PR.
    """
    if not results:
        return "_No packages were analysed._"

    issues = [r for r in results if r.overall_status in {"malicious", "suspicious"}]
    clean = [r for r in results if r.overall_status == "clean"]

    header = (
        "### SentinelFlow Dependency Scan\n\n"
        f"**{len(results)} package(s) scanned** — "
        f"**{len(issues)} issue(s) found**, {len(clean)} clean\n\n"
    )
    table_rows = [
        "| Package | Version | Status | Risk | CVEs |",
        "|---------|---------|--------|------|------|",
    ]
    for r in results:
        emoji = _PRESCAN_STATUS_EMOJI.get(r.overall_status or "unknown", "Clean")
        score = f"{r.overall_score:.2f}" if r.overall_score is not None else "—"
        cves = str(r.cve_count) if r.cve_count else "—"
        table_rows.append(
            f"| `{r.package_name}` | `{r.package_version}` | {emoji} {r.overall_status} | {score} | {cves} |"
        )

    detail_blocks: list[str] = []
    for r in results:
        emoji = _PRESCAN_STATUS_EMOJI.get(r.overall_status or "unknown", "Clean")
        lines: list[str] = []
        if r.overall_score is not None:
            lines.append(f"- **Risk score:** {r.overall_score:.2f} ({r.overall_score * 100:.0f}%)")
        if r.advisory_references:
            refs = ", ".join(f"`{ref}`" for ref in r.advisory_references)
            lines.append(f"- **CVEs / advisories:** {refs}")
        else:
            lines.append("- **CVEs / advisories:** none")
        if r.dynamic_status and r.dynamic_status != "skipped":
            dyn_parts = [str(r.dynamic_status)]
            if r.dynamic_risk_score is not None:
                dyn_parts.append(f"risk {r.dynamic_risk_score:.2f}")
            if r.vm_evasion_observed is not None:
                dyn_parts.append(f"VM evasion: {'yes' if r.vm_evasion_observed else 'no'}")
            if r.ioc_hit is not None:
                dyn_parts.append(f"IOC hit: {'yes' if r.ioc_hit else 'no'}")
            lines.append(f"- **Dynamic analysis:** {', '.join(dyn_parts)}")
        else:
            lines.append("- **Dynamic analysis:** not run (passed static/reputation gating)")
        feats = _format_static_features(r.static_features)
        if feats:
            lines.append(f"- **Notable static features:** {feats}")

        detail_blocks.append(
            "<details>\n"
            f"<summary>{emoji} <code>{r.package_name}@{r.package_version}</code> — {r.overall_status}</summary>\n\n"
            + "\n".join(lines)
            + "\n\n</details>"
        )

    body = header + "\n".join(table_rows)
    if detail_blocks:
        body += "\n\n#### Per-package details\n\n" + "\n\n".join(detail_blocks)
    return body


def _compose_pr_body(user_body: str | None, scan_summary_markdown: str | None) -> str | None:
    """Combine the user-supplied PR body with the scan summary markdown."""
    parts = [p.strip() for p in (user_body, scan_summary_markdown) if p and p.strip()]
    if not parts:
        return None
    return "\n\n---\n\n".join(parts)


async def _run_typosquat_check(
    ecosystem: str,
    dependencies: list[DependencySpec],
) -> list[dict]:
    """Run the cheap typosquat validation. Raises 400 on a blocked package,
    returns the list of (non-blocking) warning dicts otherwise. Fails open."""
    typosquat_warnings: list[dict] = []
    try:
        validations = await typosquat_guard.validate_packages(ecosystem, dependencies)
        blocked = [v for v in validations if v.risk_level == "blocked"]
        if blocked:
            blocked_details = "; ".join(
                f"{v.package_name}: {', '.join(v.reasons)}" for v in blocked
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Typosquatting risk detected — blocked packages: {blocked_details}",
            )
        typosquat_warnings = [
            {
                "package_name": v.package_name,
                "risk_level": v.risk_level,
                "reasons": v.reasons,
                "similar_to": v.similar_popular_package,
                "monthly_downloads": v.monthly_downloads,
            }
            for v in validations
            if v.risk_level == "warning"
        ]
    except HTTPException:
        raise
    except Exception:
        logger.warning("Typosquat validation failed, proceeding without")
    return typosquat_warnings


async def _run_dependency_prescan(
    ecosystem: str,
    dependencies: list[DependencySpec],
) -> tuple[list[PackagePrescanResult], list[dict]]:
    """Run typosquat validation + the full security pipeline (static → CVE →
    reputation → conditional dynamic) on the dependencies **without** creating
    a PR or persisting to the DB.

    Returns ``(prescan_results, typosquat_warnings)``. Raises ``HTTPException``
    (400) on a blocked typosquat or a confirmed malicious package. Fails open
    (no block) if the scanner itself errors.
    """
    typosquat_warnings = await _run_typosquat_check(ecosystem, dependencies)

    prescan_package_results: list[PackagePrescanResult] = []
    try:
        raw_results = await prescan_packages_full(
            [(dep.name, dep.version) for dep in dependencies],
            ecosystem,
        )
        for pkg_name, pkg_version, assessment in raw_results:
            if isinstance(assessment, BaseException):
                logger.warning("Pre-PR full scan error for %s@%s: %s", pkg_name, pkg_version, assessment)
                prescan_package_results.append(PackagePrescanResult(
                    package_name=pkg_name,
                    package_version=pkg_version,
                    overall_status="error",
                ))
                continue
            if assessment.overall_status == "malicious":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Package '{pkg_name}@{pkg_version}' failed security scan (malicious). PR creation blocked.",
                )
            dyn_meta = assessment.metadata.get("dynamic") if assessment.metadata else None
            if not isinstance(dyn_meta, dict):
                dyn_meta = {}
            feat = assessment.metadata.get("feature_snapshot") if assessment.metadata else None
            static_features: dict[str, float] | None = None
            if isinstance(feat, dict):
                static_features = {k: float(v) for k, v in feat.items() if isinstance(v, (int, float))}
            prescan_package_results.append(PackagePrescanResult(
                package_name=pkg_name,
                package_version=pkg_version,
                overall_status=assessment.overall_status,
                overall_score=assessment.overall_score,
                advisory_references=assessment.advisory_references,
                cve_count=len(assessment.advisory_references),
                static_features=static_features,
                dynamic_status=dyn_meta.get("status"),
                dynamic_risk_score=dyn_meta.get("risk_score"),
                vm_evasion_observed=dyn_meta.get("vm_evasion_observed"),
                ioc_hit=dyn_meta.get("ioc_hit"),
            ))
    except HTTPException:
        raise
    except Exception:
        logger.warning("Pre-PR full scan failed, proceeding without blocking", exc_info=True)

    return prescan_package_results, typosquat_warnings


@router.post(
    "/{owner}/{repo_name}/dependencies/prescan",
    status_code=status.HTTP_200_OK,
    response_model=PrescanResponse,
)
async def prescan_dependencies(
    owner: str,
    repo_name: str,
    payload: AddDependencyRequest,
    current_user: User = Depends(get_current_user),
) -> PrescanResponse:
    """Run the full pre-PR security scan on the requested dependencies **without**
    creating a pull request.

    This is the explicit, potentially long-running scan step. The frontend calls
    it first, lets the user review per-package results (and Ask AI about them),
    then calls ``/dependencies/add`` with ``run_prescan=false`` to open the PR
    without re-scanning.
    """
    del owner, repo_name, current_user  # auth enforced by dependency; coords unused here
    results, typosquat_warnings = await _run_dependency_prescan(
        payload.ecosystem, payload.dependencies
    )
    return PrescanResponse(
        prescan_results=results,
        typosquat_warnings=typosquat_warnings,
        scan_summary_markdown=_build_prescan_markdown(results),
    )


@router.post(
    "/{owner}/{repo_name}/dependencies/add",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=AddDependencyResponse,
)
async def add_dependencies_via_pr(
    owner: str,
    repo_name: str,
    payload: AddDependencyRequest,
    current_user: User = Depends(get_current_user),
) -> AddDependencyResponse:
    """Create a pull request that adds or updates dependencies.

    For npm, updates both ``package.json`` and ``package-lock.json``.
    For pypi, updates ``requirements.txt``.

    Runs the full security scan pipeline (static → CVE → reputation → conditional dynamic)
    on each dependency before creating the PR. Blocks on confirmed malicious packages.
    Returns per-package scan results in the response.
    """
    user_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {current_user.access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Security scan + typosquat. Two paths:
    #  • run_prescan=True (default, backward-compatible): run the full pipeline now,
    #    block on confirmed malicious, and build the summary from our own results.
    #  • run_prescan=False (two-step flow): the client already scanned the packages
    #    via /dependencies/prescan, so skip the heavy re-scan and only run the cheap
    #    typosquat check; embed the client-supplied summary in the PR body.
    if payload.run_prescan:
        prescan_package_results, typosquat_warnings = await _run_dependency_prescan(
            payload.ecosystem,
            payload.dependencies,
        )
        scan_summary_markdown = _build_prescan_markdown(prescan_package_results)
    else:
        prescan_package_results = []
        typosquat_warnings = await _run_typosquat_check(
            payload.ecosystem,
            payload.dependencies,
        )
        scan_summary_markdown = payload.scan_summary_markdown

    effective_pr_body = _compose_pr_body(payload.pr_body, scan_summary_markdown)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            active_headers = user_headers
            try:
                installation_token = await _get_installation_token_for_repo(client, owner, repo_name)
                active_headers = {
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {installation_token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
            except HTTPException as exc:
                if exc.status_code not in {
                    status.HTTP_401_UNAUTHORIZED,
                    status.HTTP_403_FORBIDDEN,
                    status.HTTP_404_NOT_FOUND,
                    status.HTTP_502_BAD_GATEWAY,
                }:
                    raise

            if payload.ecosystem == "npm":
                pr_result = await pr_creator.create_npm_dependency_pr(
                    client=client,
                    owner=owner,
                    repo_name=repo_name,
                    headers=active_headers,
                    dependencies=payload.dependencies,
                    updated_package_lock_json=payload.updated_package_lock_json,
                    preferred_branch_name=payload.branch_name,
                    pr_title=payload.pr_title,
                    pr_body=effective_pr_body,
                    idempotency_key=payload.idempotency_key,
                    generate_lockfile_server_side=payload.generate_lockfile_server_side,
                )
            else:
                pr_result = await pr_creator.create_pypi_dependency_pr(
                    client=client,
                    owner=owner,
                    repo_name=repo_name,
                    headers=active_headers,
                    dependencies=payload.dependencies,
                    preferred_branch_name=payload.branch_name,
                    pr_title=payload.pr_title,
                    pr_body=effective_pr_body,
                    idempotency_key=payload.idempotency_key,
                )

            return AddDependencyResponse(
                pr_url=pr_result.pr_url,
                pr_number=pr_result.pr_number,
                branch_name=pr_result.branch_name,
                typosquat_warnings=typosquat_warnings,
                prescan_results=prescan_package_results,
            )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach GitHub API while creating dependency pull request",
        ) from exc


_SEARCH_CACHE: dict[tuple, tuple[float, PackageSearchResponse]] = {}
_SEARCH_CACHE_TTL = 300
_SEARCH_CACHE_MAX = 200


@router.get(
    "/packages/search",
    response_model=PackageSearchResponse,
)
async def search_packages_proxy(
    ecosystem: str = Query(..., pattern=r"^(npm|pypi)$"),
    q: str = Query(..., min_length=1, max_length=128),
    page: int = Query(1, ge=1, le=10000),
    limit: int = Query(8, ge=1, le=50),
    authenticated_user_id: object = Depends(require_authenticated_token),
) -> PackageSearchResponse:
    """Proxy package search to npm/PyPI and add typosquatting hints.

    Frontend should call this endpoint instead of talking to public registries directly.
    """
    del authenticated_user_id

    cleaned_query = q.strip()
    if not cleaned_query:
        return PackageSearchResponse(
            ecosystem=ecosystem,
            query="",
            page=page,
            limit=limit,
            total=0,
            results=[],
            did_you_mean=None,
        )

    cache_key = (ecosystem, cleaned_query.lower(), page, limit)
    _now = _time.monotonic()
    _cached = _SEARCH_CACHE.get(cache_key)
    if _cached and (_now - _cached[0]) < _SEARCH_CACHE_TTL:
        return _cached[1]

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            if ecosystem == "npm":
                results = await package_fetcher.search_npm_packages(
                    cleaned_query,
                    page=page,
                    limit=limit,
                    client=client,
                )
            else:
                results = await package_fetcher.search_pypi_packages(
                    cleaned_query,
                    page=page,
                    limit=limit,
                    client=client,
                )

        await reputation_service.enrich_search_results(results, ecosystem)

        suggestion = package_fetcher.suggest_package_name(
            ecosystem,
            cleaned_query,
            results,
        )

        response = PackageSearchResponse(
            ecosystem=ecosystem,
            query=cleaned_query,
            page=page,
            limit=limit,
            total=len(results),
            results=results,
            did_you_mean=suggestion,
        )
        if response.results:
            if len(_SEARCH_CACHE) >= _SEARCH_CACHE_MAX:
                _SEARCH_CACHE.clear()
            _SEARCH_CACHE[cache_key] = (_now, response)
        return response
    except httpx.HTTPStatusError as exc:
        upstream_status = exc.response.status_code
        if upstream_status == status.HTTP_404_NOT_FOUND:
            return PackageSearchResponse(
                ecosystem=ecosystem,
                query=q.strip(),
                page=page,
                limit=limit,
                total=0,
                results=[],
                did_you_mean=None,
            )

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Registry API error while searching packages: {upstream_status}",
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach registry API while searching packages",
        ) from exc


@router.get(
    "/packages/versions",
    response_model=PackageVersionsResponse,
)
async def get_package_versions_proxy(
    ecosystem: str = Query(..., pattern=r"^(npm|pypi)$"),
    name: str = Query(..., min_length=1, max_length=214),
    authenticated_user_id: object = Depends(require_authenticated_token),
) -> PackageVersionsResponse:
    """Proxy package version lookup to npm/PyPI for frontend version selection."""
    del authenticated_user_id

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            if ecosystem == "npm":
                payload = await package_fetcher.list_npm_package_versions(name, client=client)
            else:
                payload = await package_fetcher.list_pypi_package_versions(name, client=client)

        return PackageVersionsResponse.model_validate(payload)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Package not found: {name}",
        )
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Registry API error while loading package versions: {exc.response.status_code}",
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach registry API while loading package versions",
        ) from exc


@router.get(
    "/packages/details",
    response_model=PackageDetailsResponse,
)
async def get_package_details(
    ecosystem: str = Query(..., pattern=r"^(npm|pypi)$"),
    name: str = Query(..., min_length=1, max_length=214),
    version: str | None = Query(default=None),
    current_user: User = Depends(get_current_user),
) -> PackageDetailsResponse:
    """Fetch rich metadata for a single npm or PyPI package."""
    del current_user
    try:
        details = await reputation_service.fetch_package_details(ecosystem, name, version)
        return PackageDetailsResponse.model_validate(details)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Package not found: {name}",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to fetch package details from upstream registries",
        )
