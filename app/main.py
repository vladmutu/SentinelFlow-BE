import logging

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.endpoints.auth import router as auth_router
from app.api.endpoints.repos import router as repos_router
from app.api.endpoints.scan import router as scan_router
from app.api.endpoints.sbom import router as sbom_router
from app.api.endpoints.webhook import router as webhook_router
from app.api.endpoints.compatibility import router as compatibility_router
from app.core.config import settings
from app.db.session import get_db

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance.

    Returns:
        FastAPI: Configured application with routers and middleware.
    """
    app = FastAPI(
        title=settings.app_name,
        debug=settings.app_debug,
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth_router)
    app.include_router(repos_router, prefix="/api/repos")
    app.include_router(scan_router, prefix="/api/repos")
    app.include_router(sbom_router, prefix="/api/repos")
    app.include_router(compatibility_router, prefix="/api/repos")
    app.include_router(webhook_router, prefix="/api/webhooks")

    @app.on_event("startup")
    async def _startup_ngrok() -> None:
        """Optionally start an ngrok tunnel for webhook development."""
        if not settings.webhook_ngrok_enabled:
            return
        try:
            from pyngrok import ngrok, conf

            if settings.webhook_ngrok_authtoken:
                conf.get_default().auth_token = settings.webhook_ngrok_authtoken

            options = {"bind_tls": True}
            if settings.webhook_ngrok_domain:
                options["hostname"] = settings.webhook_ngrok_domain

            tunnel = ngrok.connect(8000, **options)
            public_url = tunnel.public_url
            logger.info("ngrok tunnel started: %s", public_url)
            logger.info("Webhook URL: %s/api/webhooks/github", public_url)
        except ImportError:
            logger.warning(
                "pyngrok not installed — set WEBHOOK_NGROK_ENABLED=false or "
                "install pyngrok to enable ngrok tunneling"
            )
        except Exception:
            logger.exception("Failed to start ngrok tunnel")

    @app.get(f"{settings.api_v1_prefix}/health", tags=["Health"])
    async def health_check(db: AsyncSession = Depends(get_db)) -> dict[str, str]:
        """Validate service and database availability.

        Args:
            db: Active asynchronous database session.

        Returns:
            dict[str, str]: Health status payload.

        Raises:
            HTTPException: If the database connectivity check fails.
        """
        try:
            await db.execute(text("SELECT 1"))
            return {"status": "ok", "database": "reachable"}
        except SQLAlchemyError as exc:
            raise HTTPException(status_code=503, detail="Database unavailable") from exc

    return app


app = create_app()
