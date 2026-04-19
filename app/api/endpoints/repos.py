import base64
import json
import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import get_current_user, require_authenticated_token
from app.api.schemas.dependency import (
    AddDependencyRequest,
    AddDependencyResponse,
    PackageSearchResponse,
    PackageVersionsResponse,
)
from app.core.config import settings
from app.core.github_app import get_app_jwt
from app.models.user import User
from app.services import manifest_utils, package_fetcher, pr_creator

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
    """Build a normalized dependency tree from package-lock content.

    Args:
        lockfile: Parsed ``package-lock.json`` payload.

    Returns:
        dict: Tree rooted at the project package.
    """
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
            _resolve_v2_tree(dep_name, packages, "", set())
            for dep_name in root_dependencies.keys()
        ]
        return _simplified_dep(str(project_name), str(project_version), children)

    dependencies = lockfile.get("dependencies", {})
    if not isinstance(dependencies, dict):
        dependencies = {}

    children = [
        _resolve_v1_tree(dep_name, dep_payload, set())
        for dep_name, dep_payload in dependencies.items()
        if isinstance(dep_payload, dict)
    ]
    return _simplified_dep(str(project_name), str(project_version), children)


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

            all_repositories: list[dict] = []
            for installation_id in installation_ids:
                repos_url = (
                    "https://api.github.com/user/installations/"
                    f"{installation_id}/repositories"
                )
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
            return _build_npm_tree_from_lockfile(lockfile_json)

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
            manifest = await manifest_utils.fetch_pypi_manifest(client, owner, repo_name, user_headers)
            return await _build_pypi_tree_from_manifest(client, manifest)

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach GitHub API while fetching PyPI dependencies",
        ) from exc


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
    """
    user_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {current_user.access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

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
                    pr_body=payload.pr_body,
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
                    pr_body=payload.pr_body,
                    idempotency_key=payload.idempotency_key,
                )

            return AddDependencyResponse(
                pr_url=pr_result.pr_url,
                pr_number=pr_result.pr_number,
                branch_name=pr_result.branch_name,
            )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach GitHub API while creating dependency pull request",
        ) from exc


@router.get(
    "/packages/search",
    response_model=PackageSearchResponse,
)
async def search_packages_proxy(
    ecosystem: str = Query(..., pattern=r"^(npm|pypi)$"),
    q: str = Query(..., min_length=1, max_length=128),
    authenticated_user_id: object = Depends(require_authenticated_token),
) -> PackageSearchResponse:
    """Proxy package search to npm/PyPI and add typosquatting hints.

    Frontend should call this endpoint instead of talking to public registries directly.
    """
    del authenticated_user_id

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            cleaned_query = q.strip()
            if not cleaned_query:
                return PackageSearchResponse(
                    ecosystem=ecosystem,
                    query="",
                    total=0,
                    results=[],
                    did_you_mean=None,
                )
            if ecosystem == "npm":
                results = await package_fetcher.search_npm_packages(
                    cleaned_query,
                    client=client,
                )
            else:
                results = await package_fetcher.search_pypi_packages(
                    cleaned_query,
                    client=client,
                )

        suggestion = package_fetcher.suggest_package_name(
            ecosystem,
            cleaned_query,
            results,
        )

        return PackageSearchResponse(
            ecosystem=ecosystem,
            query=cleaned_query,
            total=len(results),
            results=results,
            did_you_mean=suggestion,
        )
    except httpx.HTTPStatusError as exc:
        upstream_status = exc.response.status_code
        if upstream_status == status.HTTP_404_NOT_FOUND:
            return PackageSearchResponse(
                ecosystem=ecosystem,
                query=q.strip(),
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
