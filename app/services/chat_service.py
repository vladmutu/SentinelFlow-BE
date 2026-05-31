"""CRUD operations for persistent chat sessions and messages."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.chat import ChatMessage, ChatSession


async def create_session(
    db: AsyncSession,
    user_id: UUID,
    owner: str,
    repo_name: str,
    title: str | None = None,
) -> ChatSession:
    session = ChatSession(user_id=user_id, owner=owner, repo_name=repo_name, title=title)
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return session


async def list_sessions(
    db: AsyncSession,
    user_id: UUID,
    owner: str,
    repo_name: str,
) -> list[ChatSession]:
    result = await db.execute(
        select(ChatSession)
        .where(
            ChatSession.user_id == user_id,
            ChatSession.owner == owner,
            ChatSession.repo_name == repo_name,
        )
        .order_by(ChatSession.updated_at.desc())
    )
    return list(result.scalars().all())


async def get_session(
    db: AsyncSession,
    session_id: UUID,
    user_id: UUID,
) -> ChatSession | None:
    result = await db.execute(
        select(ChatSession).where(
            ChatSession.id == session_id,
            ChatSession.user_id == user_id,
        )
    )
    return result.scalar_one_or_none()


async def delete_session(
    db: AsyncSession,
    session_id: UUID,
    user_id: UUID,
) -> bool:
    session = await get_session(db, session_id, user_id)
    if session is None:
        return False
    await db.delete(session)
    await db.commit()
    return True


async def get_messages(
    db: AsyncSession,
    session_id: UUID,
) -> list[ChatMessage]:
    result = await db.execute(
        select(ChatMessage)
        .where(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.created_at)
    )
    return list(result.scalars().all())


async def append_messages(
    db: AsyncSession,
    session: ChatSession,
    user_content: str,
    assistant_content: str,
) -> None:
    """Persist a user + assistant turn and bump the session's updated_at timestamp."""
    db.add(ChatMessage(session_id=session.id, role="user", content=user_content))
    db.add(ChatMessage(session_id=session.id, role="assistant", content=assistant_content))
    session.updated_at = datetime.now(timezone.utc)
    if session.title is None:
        session.title = user_content[:80]
    await db.commit()


async def count_messages(db: AsyncSession, session_id: UUID) -> int:
    result = await db.execute(
        select(func.count()).where(ChatMessage.session_id == session_id)
    )
    return result.scalar_one()
