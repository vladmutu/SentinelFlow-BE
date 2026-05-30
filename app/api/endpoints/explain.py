"""AI explainability endpoint — POST /api/explain/package."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import get_current_user
from app.api.schemas.explain import ExplainPackageRequest, ExplainPackageResponse
from app.core.config import settings
from app.models.user import User
from app.services.explain_service import (
    OllamaResponseError,
    OllamaUnavailableError,
    explain_package,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Explainability"])


@router.post(
    "/package",
    response_model=ExplainPackageResponse,
    status_code=status.HTTP_200_OK,
)
async def explain_package_endpoint(
    body: ExplainPackageRequest,
    current_user: User = Depends(get_current_user),
) -> ExplainPackageResponse:
    """Generate a plain-English AI explanation for a package scan verdict.

    Requires authentication. Calls the local Ollama/Mistral instance and returns
    a structured explanation derived from all available analysis data.
    """
    if not settings.ollama_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI explanations are disabled on this instance (OLLAMA_ENABLED=false).",
        )

    logger.info(
        "Explain request for %s@%s by user=%s",
        body.package_name,
        body.package_version,
        current_user.username if hasattr(current_user, "username") else "unknown",
    )

    try:
        return await explain_package(body)
    except OllamaUnavailableError as exc:
        logger.warning(
            "Ollama unavailable for %s@%s: %s",
            body.package_name,
            body.package_version,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI explanation service is not reachable. Ensure Ollama is running locally.",
        ) from exc
    except OllamaResponseError as exc:
        logger.error(
            "Ollama error for %s@%s: %s",
            body.package_name,
            body.package_version,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="AI model returned an unexpected response.",
        ) from exc
