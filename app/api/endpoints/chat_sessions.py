"""Chat session management endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.api.schemas.chat import CreateSessionRequest, MessageOut, SessionDetail, SessionSummary
from app.db.session import get_db
from app.models.user import User
from app.services import chat_service

router = APIRouter(prefix="/chat", tags=["Chat Sessions"])


@router.post("/sessions", response_model=SessionSummary, status_code=status.HTTP_201_CREATED)
async def create_session(
    body: CreateSessionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SessionSummary:
    session = await chat_service.create_session(
        db, current_user.id, body.owner, body.repo_name, body.title
    )
    return SessionSummary(
        id=session.id,
        owner=session.owner,
        repo_name=session.repo_name,
        title=session.title,
        created_at=session.created_at,
        updated_at=session.updated_at,
        message_count=0,
    )


@router.get("/sessions", response_model=list[SessionSummary])
async def list_sessions(
    owner: str = Query(...),
    repo_name: str = Query(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[SessionSummary]:
    sessions = await chat_service.list_sessions(db, current_user.id, owner, repo_name)
    result = []
    for s in sessions:
        count = await chat_service.count_messages(db, s.id)
        result.append(
            SessionSummary(
                id=s.id,
                owner=s.owner,
                repo_name=s.repo_name,
                title=s.title,
                created_at=s.created_at,
                updated_at=s.updated_at,
                message_count=count,
            )
        )
    return result


@router.get("/sessions/{session_id}", response_model=SessionDetail)
async def get_session(
    session_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SessionDetail:
    session = await chat_service.get_session(db, session_id, current_user.id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    messages = await chat_service.get_messages(db, session_id)
    return SessionDetail(
        id=session.id,
        owner=session.owner,
        repo_name=session.repo_name,
        title=session.title,
        created_at=session.created_at,
        updated_at=session.updated_at,
        message_count=len(messages),
        messages=[MessageOut(id=m.id, role=m.role, content=m.content, created_at=m.created_at) for m in messages],
    )


@router.delete("/sessions/{session_id}")
async def delete_session(
    session_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    deleted = await chat_service.delete_session(db, session_id, current_user.id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
