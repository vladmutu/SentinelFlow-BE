import base64
import json
import re

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.github_app import get_app_jwt
from app.models.user import User

router = APIRouter(tags=["Repositories"])


def _github_error_summary(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except Exception:
        return ""

    if not isinstance(payload, dict):
        return ""

    message = str(payload.get("message") or "").strip()
    errors = payload.get("errors")

    extra = ""
    if isinstance(errors, list) and errors:
        extra = "; ".join(str(item) for item in errors[:2])
    elif isinstance(errors, dict):
        extra = str(errors)

    if message and extra:
        return f"{message} ({extra})"
    return message or extra


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

        root_dependencies: dict[str, str] = {}
        if isinstance(root_pkg, dict):
            for dep_section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                section_payload = root_pkg.get(dep_section, {})
                if isinstance(section_payload, dict):
                    for dep_name, dep_version in section_payload.items():
                        root_dependencies[str(dep_name)] = str(dep_version)

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
    dependencies: dict[str, str] = {}
    for dep_section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        section_payload = package_json.get(dep_section, {})
        if isinstance(section_payload, dict):
            for dep_name, dep_version in section_payload.items():
                dependencies[str(dep_name)] = str(dep_version)

    children = [
        _simplified_dep(dep_name, str(dep_version), [])
        for dep_name, dep_version in dependencies.items()
    ]
    return _simplified_dep(str(project_name), str(project_version), children)


def _parse_requirement_entry(entry: str) -> tuple[str | None, str | None]:
    # Remove comments and environment markers from requirement declarations.
    cleaned = entry.split("#", 1)[0].split(";", 1)[0].strip()
    if not cleaned:
        return None, None

    if cleaned.startswith(("-", ".", "git+", "http://", "https://")):
        return None, None

    if " @ " in cleaned:
        name = cleaned.split(" @ ", 1)[0].strip()
        base_name = re.match(r"^([A-Za-z0-9_.-]+)", name)
        if not base_name:
            return None, None
        return base_name.group(1), None

    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(===|==|~=|>=|<=|!=|>|<)?\s*(.*)$", cleaned)
    if not match:
        return None, None

    name = match.group(1)
    version_raw = (match.group(3) or "").strip() if match.group(2) else ""
    version = version_raw if version_raw else None
    return name, version


def _parse_requirements_txt(content: str) -> list[dict]:
    parsed: list[dict] = []
    seen: set[str] = set()

    for raw_line in content.splitlines():
        name, version = _parse_requirement_entry(raw_line)
        if not name:
            continue

        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        parsed.append(_simplified_dep(name, version, []))

    return parsed


def _parse_pyproject_toml(content: str) -> list[dict]:
    if tomllib is None:
        return []

    try:
        payload = tomllib.loads(content)
    except Exception:
        return []

    entries: list[str] = []

    project = payload.get("project", {}) if isinstance(payload, dict) else {}
    if isinstance(project, dict):
        project_deps = project.get("dependencies", [])
        if isinstance(project_deps, list):
            entries.extend(dep for dep in project_deps if isinstance(dep, str))

    tool = payload.get("tool", {}) if isinstance(payload, dict) else {}
    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
    poetry_deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
    if isinstance(poetry_deps, dict):
        for name, meta in poetry_deps.items():
            if str(name).lower() == "python":
                continue
            if isinstance(meta, str):
                entries.append(f"{name}{meta}")
            elif isinstance(meta, dict):
                version = meta.get("version")
                if isinstance(version, str) and version.strip():
                    entries.append(f"{name}{version}")
                else:
                    entries.append(str(name))

    parsed: list[dict] = []
    seen: set[str] = set()
    for entry in entries:
        name, version = _parse_requirement_entry(entry)
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        parsed.append(_simplified_dep(name, version, []))

    return parsed


def _build_python_dependency_tree(repo_name: str, dependencies: list[dict]) -> dict:
    return _simplified_dep(repo_name, "latest", dependencies)


def _parse_requires_dist_entry(entry: str) -> tuple[str | None, str | None]:
    main = entry.split(";", 1)[0].strip()
    if not main:
        return None, None

    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:\(([^)]+)\))?$", main)
    if not match:
        return None, None

    name = match.group(1)
    version = match.group(2).strip() if match.group(2) else None
    return name, version


def _should_skip_requires_dist(entry: str) -> bool:
    marker = entry.split(";", 1)[1].strip().lower() if ";" in entry else ""
    return "extra ==" in marker


def _is_exact_version(version: str | None) -> bool:
    if not version:
        return False
    cleaned = version.strip()
    if not cleaned:
        return False
    if any(token in cleaned for token in ("<", ">", "=", "!", "~", ",", " ")):
        return False
    return True


async def _fetch_pypi_deps_recursive(
    client: httpx.AsyncClient,
    package_name: str,
    version: str | None,
    depth: int,
    cache: dict[tuple[str, str], list[dict]],
    visiting: set[str],
) -> list[dict]:
    if depth >= 3:
        return []

    normalized_name = package_name.lower()
    normalized_version = (version or "latest").strip().lower()
    cache_key = (normalized_name, normalized_version)
    if cache_key in cache:
        return [dict(item) for item in cache[cache_key]]

    if normalized_name in visiting:
        return []

    visiting_next = set(visiting)
    visiting_next.add(normalized_name)

    pypi_url = (
        f"https://pypi.org/pypi/{package_name}/{version}/json"
        if _is_exact_version(version) and version and version.lower() != "latest"
        else f"https://pypi.org/pypi/{package_name}/json"
    )

    try:
        response = await client.get(pypi_url)
    except httpx.RequestError:
        cache[cache_key] = []
        return []

    if response.is_error:
        cache[cache_key] = []
        return []

    payload = response.json()
    info = payload.get("info", {}) if isinstance(payload, dict) else {}
    requires_dist = info.get("requires_dist", []) if isinstance(info, dict) else []
    if not isinstance(requires_dist, list):
        requires_dist = []

    children: list[dict] = []
    seen_children: set[str] = set()
    for raw_dep in requires_dist:
        if not isinstance(raw_dep, str) or _should_skip_requires_dist(raw_dep):
            continue

        dep_name, dep_version = _parse_requires_dist_entry(raw_dep)
        if not dep_name:
            continue

        child_key = dep_name.lower()
        if child_key in seen_children:
            continue
        seen_children.add(child_key)

        nested_children = await _fetch_pypi_deps_recursive(
            client=client,
            package_name=dep_name,
            version=dep_version,
            depth=depth + 1,
            cache=cache,
            visiting=visiting_next,
        )
        children.append(_simplified_dep(dep_name, dep_version, nested_children))

    cache[cache_key] = [dict(item) for item in children]
    return children


async def fetch_pypi_deps(package_name: str, version: str | None = None) -> list[dict]:
    async with httpx.AsyncClient(timeout=15.0) as client:
        return await _fetch_pypi_deps_recursive(
            client=client,
            package_name=package_name,
            version=version,
            depth=0,
            cache={},
            visiting=set(),
        )


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
        detail_suffix = _github_error_summary(installation_resp)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Repository installation not found for this GitHub App"
                + (f": {detail_suffix}" if detail_suffix else "")
            ),
        )
    if installation_resp.is_error:
        detail_suffix = _github_error_summary(installation_resp)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Failed to resolve GitHub App installation: {installation_resp.status_code}"
                + (f" ({detail_suffix})" if detail_suffix else "")
            ),
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
        detail_suffix = _github_error_summary(token_resp)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Failed to create installation token: {token_resp.status_code}"
                + (f" ({detail_suffix})" if detail_suffix else "")
            ),
        )

    installation_token = token_resp.json().get("token")
    if not installation_token:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="GitHub installation token was not returned",
        )
    return installation_token


async def resolve_owner_for_repo_name(repo_name: str, current_user: User) -> str:
    """Resolve owner login when only repo name is provided by the client."""
    repos = await list_repositories(
        response=Response(),
        refresh=False,
        current_user=current_user,
    )

    matches = [repo for repo in repos if str(repo.get("name")) == repo_name]
    if not matches:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found for current user installations",
        )

    if len(matches) > 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Repository name is ambiguous across owners; use full_name owner/repo",
        )

    owner_login = ((matches[0].get("owner") or {}).get("login") or "").strip()
    if not owner_login:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Repository owner login is missing from GitHub metadata",
        )

    return owner_login


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


@router.get("/{repo_name}/dependencies/npm")
async def get_npm_dependency_tree_by_repo_name(
    repo_name: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    owner = await resolve_owner_for_repo_name(repo_name, current_user)
    return await get_npm_dependency_tree(owner, repo_name, current_user)


@router.get("/{owner}/{repo_name}/dependencies/python")
async def get_python_dependency_tree(
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

            requirements_resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo_name}/contents/requirements.txt",
                headers=active_headers,
            )

            if installation_headers and requirements_resp.status_code in {
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_403_FORBIDDEN,
            }:
                requirements_resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo_name}/contents/requirements.txt",
                    headers=user_headers,
                )

            if requirements_resp.status_code == status.HTTP_404_NOT_FOUND:
                pyproject_resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo_name}/contents/pyproject.toml",
                    headers=active_headers,
                )

                if installation_headers and pyproject_resp.status_code in {
                    status.HTTP_401_UNAUTHORIZED,
                    status.HTTP_403_FORBIDDEN,
                }:
                    pyproject_resp = await client.get(
                        f"https://api.github.com/repos/{owner}/{repo_name}/contents/pyproject.toml",
                        headers=user_headers,
                    )

                if pyproject_resp.status_code == status.HTTP_404_NOT_FOUND:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="No Python dependency manifest files found.",
                    )

                if pyproject_resp.is_error:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"GitHub API error while fetching pyproject.toml: {pyproject_resp.status_code}",
                    )

                pyproject_content = _decode_github_content(pyproject_resp.json())
                top_level_dependencies = _parse_pyproject_toml(pyproject_content)
            else:
                if requirements_resp.is_error:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"GitHub API error while fetching requirements.txt: {requirements_resp.status_code}",
                    )

                requirements_content = _decode_github_content(requirements_resp.json())
                top_level_dependencies = _parse_requirements_txt(requirements_content)

            pypi_cache: dict[tuple[str, str], list[dict]] = {}
            resolved_children: list[dict] = []

            for dependency in top_level_dependencies:
                dep_name = dependency.get("name")
                dep_version = dependency.get("version")
                if not isinstance(dep_name, str):
                    continue

                nested_children = await _fetch_pypi_deps_recursive(
                    client=client,
                    package_name=dep_name,
                    version=dep_version if isinstance(dep_version, str) else None,
                    depth=0,
                    cache=pypi_cache,
                    visiting=set(),
                )

                resolved_children.append(
                    _simplified_dep(
                        dep_name,
                        dep_version if isinstance(dep_version, str) else None,
                        nested_children,
                    )
                )

            return _build_python_dependency_tree(repo_name, resolved_children)

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach GitHub API while fetching Python dependencies",
        ) from exc


@router.get("/{repo_name}/dependencies/python")
async def get_python_dependency_tree_by_repo_name(
    repo_name: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    owner = await resolve_owner_for_repo_name(repo_name, current_user)
    return await get_python_dependency_tree(owner, repo_name, current_user)
