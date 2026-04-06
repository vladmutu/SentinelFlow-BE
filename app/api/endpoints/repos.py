import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.api.deps import get_current_user
from app.core.config import settings
from app.models.user import User

router = APIRouter(tags=["Repositories"])


@router.get("/")
async def list_repositories(
    response: Response,
    refresh: bool = Query(
        default=False,
        description="Force fresh GitHub sync for repository metadata",
    ),
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    # Always return uncached installation metadata so visibility changes are reflected immediately.
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    _ = refresh

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
                "full_name": repo.get("full_name")
                or f"{(repo.get('owner') or {}).get('login', '')}/{repo.get('name', '')}",
                "owner": {
                    "login": (repo.get("owner") or {}).get("login"),
                },
                "private": bool(repo.get("private", False)),
                "visibility": (
                    str(repo.get("visibility")).lower()
                    if repo.get("visibility")
                    else ("private" if bool(repo.get("private", False)) else "public")
                ),
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
    _ = current_user

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            installation_token = await _get_installation_token_for_repo(client, owner, repo_name)
            installation_headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {installation_token}",
                "X-GitHub-Api-Version": "2022-11-28",
            }

            lockfile_resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo_name}/contents/package-lock.json",
                headers=installation_headers,
            )

            if lockfile_resp.status_code == status.HTTP_404_NOT_FOUND:
                package_json_resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo_name}/contents/package.json",
                    headers=installation_headers,
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
