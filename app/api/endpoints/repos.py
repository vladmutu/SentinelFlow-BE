import base64
import json

import httpx
from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.github_app import get_app_jwt
from app.models.user import User

router = APIRouter(tags=["Repositories"])


def _decode_github_content(payload: dict) -> str:
    encoded = payload.get("content")
    if not isinstance(encoded, str):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unexpected GitHub content response",
        )
    sanitized = encoded.replace("\n", "")
    return base64.b64decode(sanitized).decode("utf-8")


def _simplified_dep(name: str, version: str | None, children: list[dict] | None = None) -> dict:
    return {
        "name": name,
        "version": version or "unknown",
        "children": children or [],
    }


def _resolve_v1_tree(dep_name: str, dep_payload: dict, seen: set[str]) -> dict:
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


async def _get_installation_token_for_repo(client: httpx.AsyncClient, owner: str, repo_name: str) -> str:
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
            if installation_headers and lockfile_resp.status_code in {
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_403_FORBIDDEN,
            }:
                lockfile_resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo_name}/contents/package-lock.json",
                    headers=user_headers,
                )

            if lockfile_resp.status_code == status.HTTP_404_NOT_FOUND:
                package_json_resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo_name}/contents/package.json",
                    headers=active_headers,
                )

                if installation_headers and package_json_resp.status_code in {
                    status.HTTP_401_UNAUTHORIZED,
                    status.HTTP_403_FORBIDDEN,
                }:
                    package_json_resp = await client.get(
                        f"https://api.github.com/repos/{owner}/{repo_name}/contents/package.json",
                        headers=user_headers,
                    )

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
