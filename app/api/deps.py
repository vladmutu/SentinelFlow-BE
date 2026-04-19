from uuid import UUID

import httpx
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.user import User

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    authorization: str | None = Header(default=None),
    access_token_cookie: str | None = Cookie(default=None, alias="access_token"),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve and validate the authenticated user from bearer credentials.

    Args:
        credentials: Parsed HTTP bearer authorization credentials.
        db: Active asynchronous database session.

    Returns:
        User: Authenticated and GitHub-token-validated user.

    Raises:
        HTTPException: For invalid tokens, missing users, GitHub token failures,
            upstream GitHub errors, or database failures.
    """
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )

    token = None
    if credentials is not None:
        token = credentials.credentials
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif access_token_cookie:
        token = access_token_cookie.strip()

    if not token:
        raise unauthorized

    try:
        payload = decode_access_token(token)
        subject = payload.get("sub")
        user_id = UUID(subject)
    except (ValueError, TypeError):
        raise unauthorized

    try:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while loading current user",
        ) from exc

    if user is None:
        raise unauthorized

    if not user.access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GitHub token revoked or expired",
        )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://api.github.com/user",
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {user.access_token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )

        if response.status_code == status.HTTP_401_UNAUTHORIZED:
            # Bonus behavior: clear stale token so future checks fail fast locally.
            user.access_token = ""
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="GitHub token revoked or expired",
            )

        if response.is_error:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to validate GitHub token",
            )

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach GitHub API for token validation",
        ) from exc

    return user


async def require_authenticated_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    authorization: str | None = Header(default=None),
    access_token_cookie: str | None = Cookie(default=None, alias="access_token"),
) -> UUID:
    """Validate request authentication token without loading user from DB.

    Useful for high-frequency endpoints where only authentication presence is required.
    """
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )

    token = None
    if credentials is not None:
        token = credentials.credentials
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif access_token_cookie:
        token = access_token_cookie.strip()

    if not token:
        raise unauthorized

    try:
        payload = decode_access_token(token)
        subject = payload.get("sub")
        return UUID(subject)
    except (ValueError, TypeError):
        raise unauthorized
