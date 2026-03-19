from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.endpoints.auth import router as auth_router
from app.core.config import settings
from app.db.session import get_db


def create_app() -> FastAPI:
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

    @app.get(f"{settings.api_v1_prefix}/health", tags=["Health"])
    async def health_check(db: AsyncSession = Depends(get_db)) -> dict[str, str]:
        try:
            await db.execute(text("SELECT 1"))
            return {"status": "ok", "database": "reachable"}
        except SQLAlchemyError as exc:
            raise HTTPException(status_code=503, detail="Database unavailable") from exc

    return app


app = create_app()
