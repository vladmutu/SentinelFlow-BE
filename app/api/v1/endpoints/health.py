from fastapi import APIRouter

router = APIRouter()


@router.get("/health", summary="Simple health check")
async def health_check() -> dict[str, str]:
    """Return a lightweight liveness response for API clients.

    Returns:
        dict[str, str]: Liveness payload with ``status=ok``.
    """
    return {"status": "ok"}
