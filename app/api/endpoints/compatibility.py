"""Pre-flight dependency version compatibility check endpoint.

Allows the frontend to validate whether a set of dependency changes
are compatible with existing constraints before committing to a PR.
"""

from __future__ import annotations

import json
import logging
import re

import httpx
from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import get_current_user
from app.api.schemas.compatibility import (
    CompatibilityCheckRequest,
    CompatibilityCheckResponse,
    CompatibilityCheckResult,
)
from app.models.user import User
from app.services.manifest_utils import decode_github_content

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Dependencies"])

_EXACT_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")


def _parse_semver_tuple(value: str) -> tuple[int, int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value.strip().lstrip("v"))
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _compare_semver(left: str, right: str) -> int | None:
    lt = _parse_semver_tuple(left)
    rt = _parse_semver_tuple(right)
    if lt is None or rt is None:
        return None
    if lt < rt:
        return -1
    if lt > rt:
        return 1
    return 0


def _check_npm_compatibility(
    name: str,
    requested: str,
    existing: str | None,
) -> CompatibilityCheckResult:
    """Check if a requested npm version is compatible with an existing constraint."""
    if existing is None:
        return CompatibilityCheckResult(
            name=name,
            requested_version=requested,
            existing_constraint=None,
            compatible=True,
            exists_in_manifest=False,
            reason="New dependency — no existing constraint",
        )

    current = existing.strip()
    req = requested.strip()
    req_exact = req if _EXACT_SEMVER_RE.match(req) else None

    if req_exact is None:
        if req == current:
            return CompatibilityCheckResult(
                name=name,
                requested_version=requested,
                existing_constraint=current,
                compatible=True,
                exists_in_manifest=True,
                reason="Requested spec matches existing constraint",
            )
        return CompatibilityCheckResult(
            name=name,
            requested_version=requested,
            existing_constraint=current,
            compatible=False,
            exists_in_manifest=True,
            reason=f"Cannot verify compatibility for non-exact spec '{req}' against '{current}'",
            suggestion="Provide an exact semver version (e.g., 4.17.21)",
        )

    req_tuple = _parse_semver_tuple(req_exact)
    if req_tuple is None:
        return CompatibilityCheckResult(
            name=name,
            requested_version=requested,
            existing_constraint=current,
            compatible=False,
            exists_in_manifest=True,
            reason="Requested version is not valid semver",
        )

    # Caret range (^)
    if current.startswith("^"):
        base = current[1:].strip()
        base_tuple = _parse_semver_tuple(base)
        if base_tuple:
            if base_tuple[0] > 0:
                compatible = req_tuple[0] == base_tuple[0] and _compare_semver(req_exact, base) in {0, 1}
                if not compatible:
                    return CompatibilityCheckResult(
                        name=name,
                        requested_version=requested,
                        existing_constraint=current,
                        compatible=False,
                        exists_in_manifest=True,
                        reason=f"Major version {req_tuple[0]} is outside caret range {current}",
                        suggestion=f"Use a version in the {base_tuple[0]}.x.x range (>= {base})",
                    )
            else:
                compatible = _compare_semver(req_exact, base) in {0, 1}
                if not compatible:
                    return CompatibilityCheckResult(
                        name=name,
                        requested_version=requested,
                        existing_constraint=current,
                        compatible=False,
                        exists_in_manifest=True,
                        reason=f"Version {req_exact} is below minimum {base}",
                    )

            return CompatibilityCheckResult(
                name=name,
                requested_version=requested,
                existing_constraint=current,
                compatible=True,
                exists_in_manifest=True,
                reason=f"Version {req_exact} is within caret range {current}",
            )

    # Tilde range (~)
    if current.startswith("~"):
        base = current[1:].strip()
        base_tuple = _parse_semver_tuple(base)
        if base_tuple:
            compatible = (
                req_tuple[0] == base_tuple[0]
                and req_tuple[1] == base_tuple[1]
                and _compare_semver(req_exact, base) in {0, 1}
            )
            if not compatible:
                return CompatibilityCheckResult(
                    name=name,
                    requested_version=requested,
                    existing_constraint=current,
                    compatible=False,
                    exists_in_manifest=True,
                    reason=f"Version {req_exact} is outside tilde range {current}",
                    suggestion=f"Use a version in the {base_tuple[0]}.{base_tuple[1]}.x range (>= {base})",
                )
            return CompatibilityCheckResult(
                name=name,
                requested_version=requested,
                existing_constraint=current,
                compatible=True,
                exists_in_manifest=True,
                reason=f"Version {req_exact} is within tilde range {current}",
            )

    # Exact match
    if _EXACT_SEMVER_RE.match(current):
        compatible = _compare_semver(req_exact, current) == 0
        return CompatibilityCheckResult(
            name=name,
            requested_version=requested,
            existing_constraint=current,
            compatible=compatible,
            exists_in_manifest=True,
            reason="Matches pinned version" if compatible else f"Pinned to {current}, requested {req_exact}",
            suggestion=f"Use exactly {current}" if not compatible else None,
        )

    return CompatibilityCheckResult(
        name=name,
        requested_version=requested,
        existing_constraint=current,
        compatible=True,
        exists_in_manifest=True,
        reason="Could not fully validate — treating as compatible",
    )


def _check_pypi_compatibility(
    name: str,
    requested: str,
    existing: str | None,
) -> CompatibilityCheckResult:
    """Check if a requested PyPI version is compatible with an existing requirement."""
    if existing is None:
        return CompatibilityCheckResult(
            name=name,
            requested_version=requested,
            existing_constraint=None,
            compatible=True,
            exists_in_manifest=False,
            reason="New dependency — no existing constraint",
        )

    current = existing.strip()
    req = requested.strip()
    req_exact = req if _EXACT_SEMVER_RE.match(req) else None

    if req_exact is None:
        return CompatibilityCheckResult(
            name=name,
            requested_version=requested,
            existing_constraint=current,
            compatible=True,
            exists_in_manifest=True,
            reason="Non-exact version spec — compatibility assumed",
        )

    req_tuple = _parse_semver_tuple(req_exact)
    if req_tuple is None:
        return CompatibilityCheckResult(
            name=name,
            requested_version=requested,
            existing_constraint=current,
            compatible=False,
            exists_in_manifest=True,
            reason="Requested version is not valid semver",
        )

    # ==pinned
    if current.startswith("=="):
        pinned = current[2:].strip()
        pinned_tuple = _parse_semver_tuple(pinned)
        if pinned_tuple:
            if pinned_tuple[0] == req_tuple[0]:
                return CompatibilityCheckResult(
                    name=name,
                    requested_version=requested,
                    existing_constraint=current,
                    compatible=True,
                    exists_in_manifest=True,
                    reason=f"Same major version as pinned {current}",
                )
            return CompatibilityCheckResult(
                name=name,
                requested_version=requested,
                existing_constraint=current,
                compatible=False,
                exists_in_manifest=True,
                reason=f"Major version {req_tuple[0]} differs from pinned {current}",
                suggestion=f"Use a version with major version {pinned_tuple[0]}",
            )

    # >=lower bound
    if current.startswith(">="):
        lower = current[2:].strip()
        cmp = _compare_semver(req_exact, lower)
        if cmp is not None and cmp < 0:
            return CompatibilityCheckResult(
                name=name,
                requested_version=requested,
                existing_constraint=current,
                compatible=False,
                exists_in_manifest=True,
                reason=f"Version {req_exact} is below lower bound {current}",
                suggestion=f"Use a version >= {lower}",
            )
        return CompatibilityCheckResult(
            name=name,
            requested_version=requested,
            existing_constraint=current,
            compatible=True,
            exists_in_manifest=True,
            reason=f"Version {req_exact} satisfies {current}",
        )

    # ~= compatible release
    if current.startswith("~="):
        base = current[2:].strip()
        base_tuple = _parse_semver_tuple(base)
        if base_tuple:
            compatible = (
                req_tuple[0] == base_tuple[0]
                and _compare_semver(req_exact, base) in {0, 1}
            )
            if not compatible:
                return CompatibilityCheckResult(
                    name=name,
                    requested_version=requested,
                    existing_constraint=current,
                    compatible=False,
                    exists_in_manifest=True,
                    reason=f"Version {req_exact} is outside compatible release range {current}",
                    suggestion=f"Use a version in the {base_tuple[0]}.x.x range (>= {base})",
                )
            return CompatibilityCheckResult(
                name=name,
                requested_version=requested,
                existing_constraint=current,
                compatible=True,
                exists_in_manifest=True,
                reason=f"Version {req_exact} is within compatible release range {current}",
            )

    return CompatibilityCheckResult(
        name=name,
        requested_version=requested,
        existing_constraint=current,
        compatible=True,
        exists_in_manifest=True,
        reason="Could not fully validate — treating as compatible",
    )


def _parse_requirements_txt(content: str) -> dict[str, str | None]:
    """Parse requirements.txt into a name → spec mapping."""
    deps: dict[str, str | None] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()
        line = line.split("[", 1)[0].strip()
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
            if sep in line:
                pkg, spec = line.split(sep, 1)
                deps[pkg.strip().lower()] = f"{sep}{spec.strip()}"
                break
        else:
            deps[line.strip().lower()] = None
    return deps


@router.post(
    "/{owner}/{repo_name}/dependencies/check-compatibility",
    response_model=CompatibilityCheckResponse,
)
async def check_compatibility(
    owner: str,
    repo_name: str,
    body: CompatibilityCheckRequest,
    current_user: User = Depends(get_current_user),
) -> CompatibilityCheckResponse:
    """Check if a set of dependency changes are compatible with existing constraints.

    This is a dry-run check — no PR is created. Use this before calling
    the add-dependency endpoint.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {current_user.access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Fetch the current manifest
    existing_deps: dict[str, str | None] = {}

    async with httpx.AsyncClient(timeout=15.0) as client:
        if body.ecosystem == "npm":
            resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo_name}/contents/package.json",
                headers=headers,
            )
            if resp.status_code == 404:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="package.json not found",
                )
            if resp.is_error:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"GitHub API error: {resp.status_code}",
                )

            content = decode_github_content(resp.json())
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="package.json is not valid JSON",
                )

            if isinstance(parsed, dict):
                deps = parsed.get("dependencies", {})
                if isinstance(deps, dict):
                    existing_deps = {k.lower(): v for k, v in deps.items() if isinstance(v, str)}

        else:  # pypi
            resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo_name}/contents/requirements.txt",
                headers=headers,
            )
            if resp.status_code == 404:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="requirements.txt not found",
                )
            if resp.is_error:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"GitHub API error: {resp.status_code}",
                )

            content = decode_github_content(resp.json())
            existing_deps = _parse_requirements_txt(content)

    # Run compatibility checks
    checks: list[CompatibilityCheckResult] = []
    all_compatible = True

    for dep in body.dependencies:
        existing_spec = existing_deps.get(dep.name.lower())

        if body.ecosystem == "npm":
            result = _check_npm_compatibility(dep.name, dep.version, existing_spec)
        else:
            result = _check_pypi_compatibility(dep.name, dep.version, existing_spec)

        if not result.compatible:
            all_compatible = False

        checks.append(result)

    return CompatibilityCheckResponse(
        ecosystem=body.ecosystem,
        compatible=all_compatible,
        checks=checks,
    )
