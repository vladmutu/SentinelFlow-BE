from datetime import datetime, timezone
import logging
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.security import create_access_token
from app.db.session import get_db
from app.models.user import User

print("!!! AUTH ROUTER LOADED !!!")

router = APIRouter(prefix="/api/auth", tags=["Auth"])
logger = logging.getLogger(__name__)


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)) -> dict[str, str | None]:
    return {
        "username": current_user.username,
        "email": current_user.email,
        "avatar_url": current_user.avatar_url,
    }


@router.get("/github/login")
async def github_login() -> RedirectResponse:
    if not settings.github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub OAuth is not configured",
        )

    query_params = urlencode(
        {
            "client_id": settings.github_client_id,
            "redirect_uri": settings.github_redirect_uri,
            "scope": "read:user user:email",
        }
    )
    github_oauth_url = f"https://github.com/login/oauth/authorize?{query_params}"
    return RedirectResponse(url=github_oauth_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/github/callback")
async def github_callback(
    code: str = Query(..., min_length=1),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    if not settings.github_client_id or not settings.github_client_secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub OAuth is not configured",
        )

    print(f"DEBUG: Using Client ID: '{settings.github_client_id}'")
    print(f"DEBUG: Client ID Length: {len(settings.github_client_id)}")
    if not settings.github_client_id:
        raise SystemExit("GITHUB_CLIENT_ID is empty; stopping server.")

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            logger.info("GitHub OAuth exchange using client_id=%s", settings.github_client_id)
            try:
                response = await client.post(
                    "https://github.com/login/oauth/access_token",
                    headers={"Accept": "application/json"},
                    data={
                        "client_id": settings.github_client_id,
                        "client_secret": settings.github_client_secret,
                        "code": code,
                    },
                )
            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Unable to reach GitHub OAuth endpoints",
                ) from exc

            print(f"DEBUG: GitHub Response Status: {response.status_code}")
            print(f"DEBUG: GitHub Response Body: {response.text}")
            print(f"DEBUG: GitHub Raw Response: {response.text}")

            if response.status_code != status.HTTP_200_OK:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"GitHub Error: {response.text}",
                )

            token_payload = response.json()

            access_token = token_payload.get("access_token")
            if not access_token:
                error_description = token_payload.get("error_description", "OAuth token exchange failed")
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_description)

            user_resp = await client.get(
                "https://api.github.com/user",
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {access_token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            user_resp.raise_for_status()
            github_user = user_resp.json()

            email = github_user.get("email")
            if not email:
                emails_resp = await client.get(
                    "https://api.github.com/user/emails",
                    headers={
                        "Accept": "application/vnd.github+json",
                        "Authorization": f"Bearer {access_token}",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )
                if emails_resp.is_success:
                    emails_payload = emails_resp.json()
                    primary = next(
                        (item for item in emails_payload if item.get("primary") and item.get("verified")),
                        None,
                    )
                    if primary:
                        email = primary.get("email")

        github_id = github_user.get("id")
        username = github_user.get("login")
        if not github_id or not username:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="GitHub profile response missing required fields",
            )

        result = await db.execute(select(User).where(User.github_id == int(github_id)))
        user = result.scalar_one_or_none()

        if user is None:
            user = User(
                github_id=int(github_id),
                username=str(username),
                email=email,
                avatar_url=github_user.get("avatar_url"),
                access_token=access_token,
            )
            db.add(user)
        else:
            user.username = str(username)
            user.email = email
            user.avatar_url = github_user.get("avatar_url")
            user.access_token = access_token
            user.updated_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(user)

        jwt_token = create_access_token(subject=str(user.id))
        frontend_redirect = f"{settings.frontend_url}/dashboard?token={jwt_token}"
        return RedirectResponse(url=frontend_redirect, status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub API error: {exc.response.status_code}",
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach GitHub OAuth endpoints",
        ) from exc
    except SQLAlchemyError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed while saving user",
        ) from exc
