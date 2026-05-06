"""GitHub PR creation helpers for dependency updates."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import subprocess
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
from fastapi import HTTPException, status

from app.api.schemas.dependency import DependencySpec
from app.core.config import settings


@dataclass(frozen=True)
class PullRequestResult:
    """Minimal pull request metadata returned to API handlers."""

    pr_url: str
    pr_number: int
    branch_name: str


def _encode_content(content: str) -> str:
    return base64.b64encode(content.encode("utf-8")).decode("ascii")


def _decode_content(payload: dict) -> str:
    encoded = payload.get("content")
    if not isinstance(encoded, str):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unexpected GitHub content response",
        )
    try:
        return base64.b64decode(encoded.replace("\n", "")).decode("utf-8")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to decode repository file content",
        ) from exc


def _slugify_branch_fragment(value: str) -> str:
    lowered = value.lower().strip().replace("_", "-")
    allowed = [ch if ch.isalnum() or ch in {"-", "/"} else "-" for ch in lowered]
    collapsed = "".join(allowed)
    while "--" in collapsed:
        collapsed = collapsed.replace("--", "-")
    collapsed = collapsed.strip("-/")
    return collapsed or "dependency-update"


async def _get_repo_default_branch(
    client: httpx.AsyncClient,
    owner: str,
    repo_name: str,
    headers: dict[str, str],
) -> str:
    resp = await client.get(
        f"https://api.github.com/repos/{owner}/{repo_name}",
        headers=headers,
    )
    if resp.status_code == status.HTTP_404_NOT_FOUND:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")
    if resp.status_code == status.HTTP_403_FORBIDDEN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient repository permissions for dependency updates",
        )
    if resp.is_error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub API error while reading repository metadata: {resp.status_code}",
        )

    default_branch = resp.json().get("default_branch")
    if not isinstance(default_branch, str) or not default_branch:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Repository metadata missing default branch",
        )
    return default_branch


async def _get_branch_sha(
    client: httpx.AsyncClient,
    owner: str,
    repo_name: str,
    branch: str,
    headers: dict[str, str],
) -> str:
    encoded_branch = quote(branch, safe="")
    resp = await client.get(
        f"https://api.github.com/repos/{owner}/{repo_name}/git/ref/heads/{encoded_branch}",
        headers=headers,
    )
    if resp.status_code == status.HTTP_404_NOT_FOUND:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Base branch '{branch}' was not found",
        )
    if resp.is_error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub API error while reading branch ref: {resp.status_code}",
        )

    sha = resp.json().get("object", {}).get("sha")
    if not isinstance(sha, str) or not sha:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Branch ref response missing commit SHA",
        )
    return sha


async def _branch_exists(
    client: httpx.AsyncClient,
    owner: str,
    repo_name: str,
    branch: str,
    headers: dict[str, str],
) -> bool:
    encoded_branch = quote(branch, safe="")
    resp = await client.get(
        f"https://api.github.com/repos/{owner}/{repo_name}/git/ref/heads/{encoded_branch}",
        headers=headers,
    )
    if resp.status_code == status.HTTP_404_NOT_FOUND:
        return False
    if resp.is_error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub API error while checking target branch: {resp.status_code}",
        )
    return True


def _next_branch_candidate(preferred: str, attempt: int) -> str:
    if attempt == 0:
        return preferred
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{preferred}-{stamp}-{attempt}"


def _idempotent_branch_name(base_branch: str, idempotency_key: str) -> str:
    digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:10]
    return _slugify_branch_fragment(f"{base_branch}-{digest}")


async def _find_open_pull_request_for_head(
    client: httpx.AsyncClient,
    owner: str,
    repo_name: str,
    head_branch: str,
    base_branch: str,
    headers: dict[str, str],
) -> PullRequestResult | None:
    resp = await client.get(
        f"https://api.github.com/repos/{owner}/{repo_name}/pulls",
        headers=headers,
        params={"state": "open", "head": f"{owner}:{head_branch}", "base": base_branch},
    )
    if resp.is_error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub API error while checking existing pull requests: {resp.status_code}",
        )

    payload = resp.json()
    if not isinstance(payload, list) or not payload:
        return None

    first = payload[0]
    number = first.get("number")
    url = first.get("html_url")
    if not isinstance(number, int) or not isinstance(url, str) or not url:
        return None
    return PullRequestResult(pr_url=url, pr_number=number, branch_name=head_branch)


async def _create_branch_with_retry(
    client: httpx.AsyncClient,
    owner: str,
    repo_name: str,
    preferred_branch: str,
    base_sha: str,
    headers: dict[str, str],
    *,
    max_attempts: int = 5,
) -> str:
    for attempt in range(max_attempts):
        candidate = _next_branch_candidate(preferred_branch, attempt)
        if await _branch_exists(client, owner, repo_name, candidate, headers):
            continue

        create_resp = await client.post(
            f"https://api.github.com/repos/{owner}/{repo_name}/git/refs",
            headers=headers,
            json={"ref": f"refs/heads/{candidate}", "sha": base_sha},
        )
        if create_resp.status_code in {status.HTTP_201_CREATED, status.HTTP_200_OK}:
            return candidate
        if create_resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
            # Branch was likely created between existence check and creation.
            continue
        if create_resp.status_code == status.HTTP_403_FORBIDDEN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient repository permissions to create branch",
            )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub API error while creating branch: {create_resp.status_code}",
        )

    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Could not allocate a unique branch name after multiple attempts",
    )


async def _get_file_content_and_sha(
    client: httpx.AsyncClient,
    owner: str,
    repo_name: str,
    path: str,
    ref: str,
    headers: dict[str, str],
) -> tuple[str, str]:
    resp = await client.get(
        f"https://api.github.com/repos/{owner}/{repo_name}/contents/{path}",
        headers=headers,
        params={"ref": ref},
    )
    if resp.status_code == status.HTTP_404_NOT_FOUND:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Required file not found: {path}",
        )
    if resp.is_error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub API error while reading {path}: {resp.status_code}",
        )

    payload = resp.json()
    sha = payload.get("sha")
    if not isinstance(sha, str) or not sha:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub response missing SHA for {path}",
        )

    return _decode_content(payload), sha


def _build_updated_package_json(
    package_json_content: str,
    dependencies: list[DependencySpec],
) -> str:
    try:
        parsed = json.loads(package_json_content)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="package.json is not valid JSON",
        ) from exc

    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="package.json has an unexpected structure",
        )

    deps = parsed.get("dependencies")
    if deps is None:
        deps = {}
    if not isinstance(deps, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="package.json dependencies field must be an object",
        )

    for dep in dependencies:
        existing_spec = deps.get(dep.name)
        existing_str = existing_spec if isinstance(existing_spec, str) else None
        _ensure_npm_update_is_compatible(dep.name, existing_str, dep.version)
        deps[dep.name] = _normalize_npm_update_spec(existing_str, dep.version)

    parsed["dependencies"] = deps
    return json.dumps(parsed, indent=2, ensure_ascii=False) + "\n"


def _validate_updated_lockfile(content: str) -> str:
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="updated_package_lock_json must be valid JSON",
        ) from exc

    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="updated_package_lock_json must contain a JSON object",
        )

    return json.dumps(parsed, indent=2, ensure_ascii=False) + "\n"


_EXACT_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)")
_REQ_SPEC_RE = re.compile(r"^\s*[A-Za-z0-9_.-]+\s*([^;#]+)?")
_COMPARATOR_TOKEN_RE = re.compile(r"(==|!=|~=|>=|<=|>|<)\s*([^,\s]+)")


def _parse_semver_tuple(value: str) -> tuple[int, int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value.strip().lstrip("v"))
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _compare_semver(left: str, right: str) -> int | None:
    left_tuple = _parse_semver_tuple(left)
    right_tuple = _parse_semver_tuple(right)
    if left_tuple is None or right_tuple is None:
        return None
    if left_tuple < right_tuple:
        return -1
    if left_tuple > right_tuple:
        return 1
    return 0


def _exact_version_or_none(spec: str) -> str | None:
    cleaned = spec.strip()
    if _EXACT_SEMVER_RE.match(cleaned):
        return cleaned
    return None


def _is_comparator_expression(spec: str) -> bool:
    cleaned = spec.strip()
    tokens = [token for token in re.split(r"[ ,]+", cleaned) if token]
    if not tokens:
        return False
    return all(token[:2] in {">=", "<=", "!=", "==", "~="} or token[:1] in {">", "<", "="} for token in tokens)


def _npm_range_contains_exact(range_spec: str, exact_version: str) -> bool:
    cleaned = range_spec.strip()
    exact_tuple = _parse_semver_tuple(exact_version)
    if exact_tuple is None:
        return False

    if cleaned.startswith("^"):
        base = cleaned[1:].strip()
        base_tuple = _parse_semver_tuple(base)
        if base_tuple is None:
            return False
        if base_tuple[0] > 0:
            return exact_tuple[0] == base_tuple[0] and _compare_semver(exact_version, base) in {0, 1}
        if base_tuple[1] > 0:
            return exact_tuple[0] == 0 and exact_tuple[1] == base_tuple[1] and _compare_semver(exact_version, base) in {0, 1}
        return exact_tuple[0] == 0 and exact_tuple[1] == 0 and exact_tuple[2] >= base_tuple[2]

    if cleaned.startswith("~"):
        base = cleaned[1:].strip()
        base_tuple = _parse_semver_tuple(base)
        if base_tuple is None:
            return False
        return (
            exact_tuple[0] == base_tuple[0]
            and exact_tuple[1] == base_tuple[1]
            and _compare_semver(exact_version, base) in {0, 1}
        )

    if _EXACT_SEMVER_RE.match(cleaned):
        return cleaned == exact_version

    if _is_comparator_expression(cleaned):
        parts = [part for part in re.split(r"[ ,]+", cleaned) if part]
        for token in parts:
            op = token[:2] if token[:2] in {">=", "<=", "!=", "=="} else token[:1]
            operand = token[len(op):].strip()
            cmp_result = _compare_semver(exact_version, operand)
            if cmp_result is None:
                return False
            if op in {"==", "="} and cmp_result != 0:
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
        return True

    return False


def _normalize_npm_update_spec(existing_spec: str | None, requested_spec: str) -> str:
    requested = requested_spec.strip()
    if not requested:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Dependency version must not be empty",
        )

    if existing_spec is None:
        return requested

    current = existing_spec.strip()
    requested_exact = _exact_version_or_none(requested)

    if current.startswith("^") and requested_exact:
        base = current[1:].strip()
        base_tuple = _parse_semver_tuple(base)
        requested_tuple = _parse_semver_tuple(requested_exact)
        if base_tuple and requested_tuple and base_tuple[0] == requested_tuple[0]:
            return f"^{requested_exact}"

    if current.startswith("~") and requested_exact:
        base = current[1:].strip()
        base_tuple = _parse_semver_tuple(base)
        requested_tuple = _parse_semver_tuple(requested_exact)
        if base_tuple and requested_tuple and base_tuple[0] == requested_tuple[0] and base_tuple[1] == requested_tuple[1]:
            return f"~{requested_exact}"

    return requested


def _ensure_npm_update_is_compatible(
    package_name: str,
    existing_spec: str | None,
    requested_spec: str,
) -> None:
    if existing_spec is None:
        return

    current = existing_spec.strip()
    requested = requested_spec.strip()
    requested_exact = _exact_version_or_none(requested)

    if requested_exact is None:
        if requested == current:
            return
        # For non-exact requested ranges we cannot prove compatibility in a robust way.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsafe npm update for {package_name}: backend cannot verify compatibility "
                f"for non-exact requested spec '{requested}' against existing constraint '{current}'"
            ),
        )

    if _npm_range_contains_exact(current, requested_exact):
        return

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=(
            f"Unsafe npm update for {package_name}: requested version {requested_exact} "
            f"is incompatible with existing constraint '{current}'"
        ),
    )


def _extract_requirement_spec_from_line(raw_line: str) -> str | None:
    match = _REQ_SPEC_RE.match(raw_line)
    if not match:
        return None
    spec = match.group(1)
    if not isinstance(spec, str):
        return None
    cleaned = spec.strip()
    return cleaned or None


def _pypi_requirement_contains_exact(existing_spec: str, exact_version: str) -> bool:
    tokens = _COMPARATOR_TOKEN_RE.findall(existing_spec)
    if not tokens:
        return False
    for op, operand in tokens:
        cmp_result = _compare_semver(exact_version, operand)
        if cmp_result is None:
            return False
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
            base_tuple = _parse_semver_tuple(operand)
            candidate_tuple = _parse_semver_tuple(exact_version)
            if base_tuple is None or candidate_tuple is None:
                return False
            if candidate_tuple[0] != base_tuple[0]:
                return False
            if _compare_semver(exact_version, operand) == -1:
                return False
    return True


def _normalize_pypi_update_spec(existing_spec: str | None, requested_spec: str) -> str:
    requested = requested_spec.strip()
    if existing_spec is None:
        return requested

    requested_exact = _exact_version_or_none(requested)
    if requested_exact is None:
        return requested

    tokens = _COMPARATOR_TOKEN_RE.findall(existing_spec)
    if len(tokens) == 1 and tokens[0][0] in {"==", "~=", ">=", "<=", ">", "<"}:
        operator = tokens[0][0]
        return f"{operator}{requested_exact}"

    if existing_spec.startswith("=="):
        return f"=={requested_exact}"

    return f"=={requested_exact}"


def _ensure_pypi_update_is_compatible(
    package_name: str,
    existing_spec: str | None,
    requested_spec: str,
) -> None:
    if existing_spec is None:
        return

    requested = requested_spec.strip()
    if requested == existing_spec.strip():
        return

    requested_exact = _exact_version_or_none(requested)
    if requested_exact is None:
        # For explicit comparator/range inputs, let caller preserve that exact intent.
        return

    existing_clean = existing_spec.strip()
    if existing_clean.startswith("=="):
        pinned = existing_clean[2:].strip()
        pinned_tuple = _parse_semver_tuple(pinned)
        requested_tuple = _parse_semver_tuple(requested_exact)
        if pinned_tuple is not None and requested_tuple is not None and pinned_tuple[0] == requested_tuple[0]:
            return

    if _pypi_requirement_contains_exact(existing_spec, requested_exact):
        return

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=(
            f"Unsafe PyPI update for {package_name}: requested version {requested_exact} "
            f"is incompatible with existing requirement '{existing_spec}'"
        ),
    )


def _extract_lockfile_direct_deps(parsed_lockfile: dict) -> dict[str, str]:
    direct: dict[str, str] = {}

    packages = parsed_lockfile.get("packages")
    if isinstance(packages, dict):
        root = packages.get("")
        if isinstance(root, dict):
            root_deps = root.get("dependencies")
            if isinstance(root_deps, dict):
                for name, version in root_deps.items():
                    if isinstance(name, str) and isinstance(version, str):
                        direct[name] = version

    # lockfile v1 fallback
    if not direct:
        lock_deps = parsed_lockfile.get("dependencies")
        if isinstance(lock_deps, dict):
            for name, payload in lock_deps.items():
                if not isinstance(name, str) or not isinstance(payload, dict):
                    continue
                version = payload.get("version")
                if isinstance(version, str) and version:
                    direct[name] = version

    return direct


def _ensure_lockfile_contains_requested_direct_deps(
    parsed_lockfile: dict,
    dependencies: list[DependencySpec],
) -> None:
    direct_deps = _extract_lockfile_direct_deps(parsed_lockfile)

    missing: list[str] = []
    mismatched: list[str] = []
    for dep in dependencies:
        locked_version = direct_deps.get(dep.name)
        if locked_version is None:
            missing.append(dep.name)
            continue
        if _EXACT_SEMVER_RE.match(dep.version) and locked_version != dep.version:
            mismatched.append(f"{dep.name} (expected {dep.version}, got {locked_version})")

    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "package-lock.json does not include requested direct dependencies: "
                + ", ".join(missing)
            ),
        )
    if mismatched:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "package-lock.json direct dependency versions are inconsistent: "
                + ", ".join(mismatched)
            ),
        )


async def _generate_lockfile_server_side(updated_package_json: str, current_lockfile: str) -> str:
    if not settings.npm_lockfile_generation_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "updated_package_lock_json is required unless server-side lockfile generation "
                "is enabled"
            ),
        )

    npm_path = shutil.which("npm")
    if not npm_path:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="npm executable not found for server-side lockfile generation",
        )

    tmp_dir = Path(tempfile.mkdtemp(prefix="sentinelflow_npm_lock_"))
    try:
        package_json_path = tmp_dir / "package.json"
        package_lock_path = tmp_dir / "package-lock.json"
        package_json_path.write_text(updated_package_json, encoding="utf-8")
        package_lock_path.write_text(current_lockfile, encoding="utf-8")

        def _run_npm_install() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    npm_path,
                    "install",
                    "--package-lock-only",
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                ],
                cwd=str(tmp_dir),
                capture_output=True,
                text=True,
                check=False,
                timeout=max(10, settings.npm_lockfile_generation_timeout_seconds),
            )

        try:
            proc = await asyncio.to_thread(_run_npm_install)
        except subprocess.TimeoutExpired as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Server-side lockfile generation timed out",
            ) from exc
        except NotImplementedError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    "Server-side lockfile generation is not supported by the current "
                    "Python event loop on this host"
                ),
            ) from exc

        if proc.returncode != 0:
            err = (proc.stderr or "").strip()
            short_err = err[:300] if err else "npm install failed"
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Server-side lockfile generation failed: {short_err}",
            )

        return package_lock_path.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def _commit_file_update(
    client: httpx.AsyncClient,
    owner: str,
    repo_name: str,
    path: str,
    branch: str,
    previous_sha: str,
    new_content: str,
    commit_message: str,
    headers: dict[str, str],
) -> None:
    resp = await client.put(
        f"https://api.github.com/repos/{owner}/{repo_name}/contents/{path}",
        headers=headers,
        json={
            "message": commit_message,
            "content": _encode_content(new_content),
            "sha": previous_sha,
            "branch": branch,
        },
    )
    if resp.status_code in {status.HTTP_200_OK, status.HTTP_201_CREATED}:
        return
    if resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
        # Idempotent retry path: treat validation/no-op as success if target content already matches.
        current_content, _ = await _get_file_content_and_sha(
            client,
            owner,
            repo_name,
            path,
            branch,
            headers,
        )
        if current_content == new_content:
            return
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Could not update {path}: validation conflict or stale blob SHA",
        )
    if resp.status_code == status.HTTP_409_CONFLICT:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Could not update {path}: file changed upstream",
        )
    if resp.status_code == status.HTTP_403_FORBIDDEN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient repository permissions to update files",
        )
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"GitHub API error while updating {path}: {resp.status_code}",
    )


async def _create_pull_request(
    client: httpx.AsyncClient,
    owner: str,
    repo_name: str,
    head_branch: str,
    base_branch: str,
    title: str,
    body: str,
    headers: dict[str, str],
) -> PullRequestResult:
    resp = await client.post(
        f"https://api.github.com/repos/{owner}/{repo_name}/pulls",
        headers=headers,
        json={
            "title": title,
            "head": head_branch,
            "base": base_branch,
            "body": body,
        },
    )
    if resp.status_code in {status.HTTP_201_CREATED, status.HTTP_200_OK}:
        payload = resp.json()
        number = payload.get("number")
        url = payload.get("html_url")
        if not isinstance(number, int) or number <= 0 or not isinstance(url, str) or not url:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="GitHub API returned an invalid pull request payload",
            )
        return PullRequestResult(
            pr_url=url,
            pr_number=number,
            branch_name=head_branch,
        )
    if resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Could not create pull request due to branch or validation conflict",
        )
    if resp.status_code == status.HTTP_403_FORBIDDEN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient repository permissions to create pull request",
        )
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"GitHub API error while creating pull request: {resp.status_code}",
    )


def _default_branch_name(dependencies: list[DependencySpec]) -> str:
    first = dependencies[0].name
    return _slugify_branch_fragment(f"sentinelflow/deps/{first}")


def _default_pypi_branch_name(dependencies: list[DependencySpec]) -> str:
    first = dependencies[0].name
    return _slugify_branch_fragment(f"sentinelflow/deps-pypi/{first}")


def _default_pr_title(dependencies: list[DependencySpec]) -> str:
    if len(dependencies) == 1:
        dep = dependencies[0]
        return f"chore(deps): add {dep.name}@{dep.version}"
    return f"chore(deps): add {len(dependencies)} npm dependencies"


def _default_pypi_pr_title(dependencies: list[DependencySpec]) -> str:
    if len(dependencies) == 1:
        dep = dependencies[0]
        return f"chore(deps): add {dep.name} ({dep.version})"
    return f"chore(deps): add {len(dependencies)} pypi dependencies"


def _default_pr_body(dependencies: list[DependencySpec]) -> str:
    lines = ["This pull request was generated by SentinelFlow.", "", "Updated dependencies:"]
    for dep in dependencies:
        lines.append(f"- {dep.name}: {dep.version}")
    return "\n".join(lines)


def _render_pypi_requirement(dep: DependencySpec) -> str:
    version = dep.version.strip()
    if version.startswith(("==", ">=", "<=", "~=", "!=", ">", "<")):
        return f"{dep.name}{version}"
    return f"{dep.name}=={version}"


def _build_updated_requirements_txt(
    requirements_content: str,
    dependencies: list[DependencySpec],
) -> str:
    lines = requirements_content.splitlines()
    deps_by_name = {dep.name.lower(): dep for dep in dependencies}
    updates: dict[str, str] = {}
    order: list[str] = []
    for dep in dependencies:
        key = dep.name.lower()
        if key not in updates:
            order.append(key)
        updates[key] = _render_pypi_requirement(dep)

    consumed: set[str] = set()
    out_lines: list[str] = []
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(raw_line)
            continue

        match = _REQ_NAME_RE.match(raw_line)
        if not match:
            out_lines.append(raw_line)
            continue

        pkg_name = match.group(1).lower()
        if pkg_name not in updates:
            out_lines.append(raw_line)
            continue

        dep = deps_by_name[pkg_name]
        existing_spec = _extract_requirement_spec_from_line(raw_line)
        if existing_spec is not None:
            _ensure_pypi_update_is_compatible(dep.name, existing_spec, dep.version)
        normalized_spec = _normalize_pypi_update_spec(existing_spec, dep.version)
        updates[pkg_name] = f"{dep.name}{normalized_spec}" if normalized_spec.startswith(("==", "!=", "~=", ">=", "<=", ">", "<")) else _render_pypi_requirement(dep)

        if pkg_name in consumed:
            # Remove duplicate entries for same package by keeping first replacement.
            continue

        out_lines.append(updates[pkg_name])
        consumed.add(pkg_name)

    for key in order:
        if key not in consumed:
            out_lines.append(updates[key])

    return "\n".join(out_lines).rstrip("\n") + "\n"


async def _create_or_reuse_branch(
    client: httpx.AsyncClient,
    owner: str,
    repo_name: str,
    default_branch: str,
    base_sha: str,
    desired_branch: str,
    headers: dict[str, str],
    idempotency_key: str | None,
) -> tuple[str, PullRequestResult | None]:
    if idempotency_key:
        branch_name = _idempotent_branch_name(desired_branch, idempotency_key)
        existing_pr = await _find_open_pull_request_for_head(
            client,
            owner,
            repo_name,
            branch_name,
            default_branch,
            headers,
        )
        if existing_pr is not None:
            return branch_name, existing_pr

        if not await _branch_exists(client, owner, repo_name, branch_name, headers):
            create_resp = await client.post(
                f"https://api.github.com/repos/{owner}/{repo_name}/git/refs",
                headers=headers,
                json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
            )
            if create_resp.status_code not in {status.HTTP_201_CREATED, status.HTTP_200_OK}:
                if create_resp.status_code == status.HTTP_403_FORBIDDEN:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Insufficient repository permissions to create branch",
                    )
                if create_resp.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"GitHub API error while creating branch: {create_resp.status_code}",
                    )
        return branch_name, None

    branch_name = await _create_branch_with_retry(
        client,
        owner,
        repo_name,
        desired_branch,
        base_sha,
        headers,
    )
    return branch_name, None


async def create_npm_dependency_pr(
    client: httpx.AsyncClient,
    owner: str,
    repo_name: str,
    headers: dict[str, str],
    dependencies: list[DependencySpec],
    updated_package_lock_json: str | None,
    *,
    preferred_branch_name: str | None = None,
    pr_title: str | None = None,
    pr_body: str | None = None,
    idempotency_key: str | None = None,
    generate_lockfile_server_side: bool = False,
) -> PullRequestResult:
    """Create a pull request that updates package.json and package-lock.json."""
    default_branch = await _get_repo_default_branch(client, owner, repo_name, headers)
    base_sha = await _get_branch_sha(client, owner, repo_name, default_branch, headers)

    desired_branch = _slugify_branch_fragment(preferred_branch_name or _default_branch_name(dependencies))
    branch_name, existing_pr = await _create_or_reuse_branch(
        client,
        owner,
        repo_name,
        default_branch,
        base_sha,
        desired_branch,
        headers,
        idempotency_key,
    )
    if existing_pr is not None:
        return existing_pr

    package_json_content, package_json_sha = await _get_file_content_and_sha(
        client,
        owner,
        repo_name,
        "package.json",
        branch_name,
        headers,
    )

    # Presence of package-lock.json is mandatory for v1 to keep installs reproducible.
    current_lockfile_content, package_lock_sha = await _get_file_content_and_sha(
        client,
        owner,
        repo_name,
        "package-lock.json",
        branch_name,
        headers,
    )

    updated_package_json = _build_updated_package_json(package_json_content, dependencies)
    if updated_package_lock_json:
        lockfile_source = updated_package_lock_json
    elif generate_lockfile_server_side:
        lockfile_source = await _generate_lockfile_server_side(updated_package_json, current_lockfile_content)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "updated_package_lock_json is required unless generate_lockfile_server_side=true"
            ),
        )

    validated_lock = _validate_updated_lockfile(lockfile_source)
    parsed_lock = json.loads(validated_lock)
    _ensure_lockfile_contains_requested_direct_deps(parsed_lock, dependencies)

    deps_label = ", ".join([f"{dep.name}@{dep.version}" for dep in dependencies[:3]])
    await _commit_file_update(
        client,
        owner,
        repo_name,
        "package.json",
        branch_name,
        package_json_sha,
        updated_package_json,
        f"chore(deps): update package.json ({deps_label})",
        headers,
    )
    await _commit_file_update(
        client,
        owner,
        repo_name,
        "package-lock.json",
        branch_name,
        package_lock_sha,
        validated_lock,
        "chore(deps): update package-lock.json",
        headers,
    )

    if idempotency_key:
        existing_after_commit = await _find_open_pull_request_for_head(
            client,
            owner,
            repo_name,
            branch_name,
            default_branch,
            headers,
        )
        if existing_after_commit is not None:
            return existing_after_commit

    return await _create_pull_request(
        client,
        owner,
        repo_name,
        branch_name,
        default_branch,
        pr_title or _default_pr_title(dependencies),
        pr_body or _default_pr_body(dependencies),
        headers,
    )


async def create_pypi_dependency_pr(
    client: httpx.AsyncClient,
    owner: str,
    repo_name: str,
    headers: dict[str, str],
    dependencies: list[DependencySpec],
    *,
    preferred_branch_name: str | None = None,
    pr_title: str | None = None,
    pr_body: str | None = None,
    idempotency_key: str | None = None,
) -> PullRequestResult:
    """Create a pull request that updates requirements.txt for PyPI dependencies."""
    default_branch = await _get_repo_default_branch(client, owner, repo_name, headers)
    base_sha = await _get_branch_sha(client, owner, repo_name, default_branch, headers)

    desired_branch = _slugify_branch_fragment(
        preferred_branch_name or _default_pypi_branch_name(dependencies)
    )
    branch_name, existing_pr = await _create_or_reuse_branch(
        client,
        owner,
        repo_name,
        default_branch,
        base_sha,
        desired_branch,
        headers,
        idempotency_key,
    )
    if existing_pr is not None:
        return existing_pr

    requirements_content, requirements_sha = await _get_file_content_and_sha(
        client,
        owner,
        repo_name,
        "requirements.txt",
        branch_name,
        headers,
    )

    updated_requirements = _build_updated_requirements_txt(requirements_content, dependencies)
    deps_label = ", ".join([f"{dep.name}:{dep.version}" for dep in dependencies[:3]])
    await _commit_file_update(
        client,
        owner,
        repo_name,
        "requirements.txt",
        branch_name,
        requirements_sha,
        updated_requirements,
        f"chore(deps): update requirements.txt ({deps_label})",
        headers,
    )

    if idempotency_key:
        existing_after_commit = await _find_open_pull_request_for_head(
            client,
            owner,
            repo_name,
            branch_name,
            default_branch,
            headers,
        )
        if existing_after_commit is not None:
            return existing_after_commit

    return await _create_pull_request(
        client,
        owner,
        repo_name,
        branch_name,
        default_branch,
        pr_title or _default_pypi_pr_title(dependencies),
        pr_body or _default_pr_body(dependencies),
        headers,
    )
