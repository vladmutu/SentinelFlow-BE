from fastapi import APIRouter

router = APIRouter()


@router.get("/health", summary="Simple health check")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}
