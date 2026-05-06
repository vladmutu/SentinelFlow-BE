"""REST endpoints for SBOM generation and CycloneDX export.

* ``GET /{owner}/{repo_name}/sbom``           – generate SBOM JSON
* ``GET /{owner}/{repo_name}/sbom/cyclonedx``  – export as CycloneDX 1.5
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import get_current_user
from app.api.schemas.sbom import CycloneDxDocument, SbomDocument
from app.models.user import User
from app.services import sbom_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["SBOM"])


@router.get(
    "/{owner}/{repo_name}/sbom",
    response_model=SbomDocument,
)
async def get_sbom(
    owner: str,
    repo_name: str,
    ecosystem: str = Query(..., pattern=r"^(npm|pypi)$"),
    current_user: User = Depends(get_current_user),
) -> SbomDocument:
    """Generate an SBOM document for the repository.

    Combines the dependency tree with scan results and license data
    into a structured SBOM.

    Args:
        owner: Repository owner.
        repo_name: Repository name.
        ecosystem: Package ecosystem to generate SBOM for.
        current_user: Authenticated user.

    Returns:
        SbomDocument: SBOM with components, licenses, and vulnerability data.
    """
    try:
        return await sbom_service.generate_sbom(
            owner=owner,
            repo=repo_name,
            ecosystem=ecosystem,
            access_token=current_user.access_token,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("SBOM generation failed for %s/%s", owner, repo_name)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SBOM generation failed: {exc}",
        ) from exc


@router.get(
    "/{owner}/{repo_name}/sbom/cyclonedx",
    response_model=CycloneDxDocument,
)
async def get_sbom_cyclonedx(
    owner: str,
    repo_name: str,
    ecosystem: str = Query(..., pattern=r"^(npm|pypi)$"),
    current_user: User = Depends(get_current_user),
) -> CycloneDxDocument:
    """Export SBOM in CycloneDX 1.5 JSON format.

    Args:
        owner: Repository owner.
        repo_name: Repository name.
        ecosystem: Package ecosystem to generate SBOM for.
        current_user: Authenticated user.

    Returns:
        CycloneDxDocument: CycloneDX 1.5 compliant BOM.
    """
    try:
        sbom = await sbom_service.generate_sbom(
            owner=owner,
            repo=repo_name,
            ecosystem=ecosystem,
            access_token=current_user.access_token,
        )
        return sbom_service.export_cyclonedx(sbom)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("CycloneDX export failed for %s/%s", owner, repo_name)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"CycloneDX export failed: {exc}",
        ) from exc
