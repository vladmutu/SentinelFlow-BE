"""AI explainability endpoints — streaming SSE via Ollama/Mistral."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.api.schemas.explain import AgentChatRequest, ExplainPackageRequest
from app.core.config import settings
from app.db.session import get_db
from app.models.user import User
from app.services import chat_service
from app.services.explain_service import (
    OFF_TOPIC_RESPONSE,
    OllamaResponseError,
    OllamaUnavailableError,
    build_chat_prompt_with_rag,
    build_prompt,
    classify_topic,
    stream_ollama,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Explainability"])

_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",
    "Connection": "keep-alive",
}


def _unavailable_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="AI explanations are disabled on this instance (OLLAMA_ENABLED=false).",
    )


async def _sse_stream(prompt: str) -> AsyncGenerator[str, None]:
    """Wrap stream_ollama output as SSE events."""
    try:
        async for token in stream_ollama(prompt):
            yield f"data: {json.dumps({'token': token})}\n\n"
        yield "data: [DONE]\n\n"
    except OllamaUnavailableError as exc:
        logger.warning("Ollama unavailable during SSE stream: %s", exc)
        yield f"data: {json.dumps({'error': 'Ollama not reachable. Ensure it is running locally.'})}\n\n"
    except OllamaResponseError as exc:
        logger.error("Ollama response error during SSE stream: %s", exc)
        yield f"data: {json.dumps({'error': 'AI model returned an unexpected response.'})}\n\n"


@router.post("/package")
async def explain_package_endpoint(
    body: ExplainPackageRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Stream a plain-English AI explanation for a package scan verdict via SSE.

    Each event: `data: {"token": "..."}\\n\\n`
    Terminal event: `data: [DONE]\\n\\n`
    Error event: `data: {"error": "..."}\\n\\n`

    When ``session_id`` is provided the interaction is persisted to the chat session.
    """
    if not settings.ollama_enabled:
        raise _unavailable_error()

    logger.info(
        "SSE explain request for %s@%s by user=%s",
        body.package_name,
        body.package_version,
        getattr(current_user, "username", "unknown"),
    )

    prompt = build_prompt(body)

    if body.session_id is not None:
        session = await chat_service.get_session(db, body.session_id, current_user.id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat session not found")

        user_content = f"Explain {body.package_name}@{body.package_version}"

        async def _persistent_explain_stream() -> AsyncGenerator[str, None]:
            accumulated: list[str] = []
            try:
                async for token in stream_ollama(prompt):
                    accumulated.append(token)
                    yield f"data: {json.dumps({'token': token})}\n\n"
                yield "data: [DONE]\n\n"
            except OllamaUnavailableError as exc:
                logger.warning("Ollama unavailable during explain SSE: %s", exc)
                yield f"data: {json.dumps({'error': 'Ollama not reachable. Ensure it is running locally.'})}\n\n"
                return
            except OllamaResponseError as exc:
                logger.error("Ollama response error during explain SSE: %s", exc)
                yield f"data: {json.dumps({'error': 'AI model returned an unexpected response.'})}\n\n"
                return
            finally:
                if accumulated:
                    from app.db.session import AsyncSessionLocal
                    async with AsyncSessionLocal() as persist_db:
                        fresh_session = await chat_service.get_session(persist_db, session.id, current_user.id)
                        if fresh_session is not None:
                            await chat_service.append_messages(
                                persist_db,
                                fresh_session,
                                user_content,
                                "".join(accumulated),
                            )

        return StreamingResponse(_persistent_explain_stream(), media_type="text/event-stream", headers=_SSE_HEADERS)

    return StreamingResponse(_sse_stream(prompt), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/chat")
async def agent_chat_endpoint(
    body: AgentChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Stream an agent chat response via SSE.

    Stateless mode (no session_id): history passed in request, nothing persisted.
    Persistent mode (session_id provided): history loaded from DB, both turns saved
    after the stream completes.
    """
    if not settings.ollama_enabled:
        raise _unavailable_error()

    if not body.messages:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="messages cannot be empty")

    latest = body.messages[-1]

    # --- Pre-flight topic classification ---
    is_security = await classify_topic(latest.content)
    if not is_security:
        async def _refuse() -> AsyncGenerator[str, None]:
            yield f"data: {json.dumps({'token': OFF_TOPIC_RESPONSE})}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(_refuse(), media_type="text/event-stream", headers=_SSE_HEADERS)

    # --- Resolve conversation history ---
    session = None
    if body.session_id is not None:
        session = await chat_service.get_session(db, body.session_id, current_user.id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat session not found")
        db_messages = await chat_service.get_messages(db, session.id)
        history = [{"role": m.role, "content": m.content} for m in db_messages]
        history.append({"role": "user", "content": latest.content})
    else:
        history = [m.model_dump() for m in body.messages]

    logger.info(
        "SSE chat request (%d history turns, session=%s) by user=%s",
        len(history),
        body.session_id,
        getattr(current_user, "username", "unknown"),
    )

    prompt = await build_chat_prompt_with_rag(
        user_message=latest.content,
        history=history,
        scan_context=body.scan_context,
    )

    # --- Stream with optional persistence ---
    if session is not None:
        async def _persistent_stream() -> AsyncGenerator[str, None]:
            accumulated: list[str] = []
            try:
                async for token in stream_ollama(prompt):
                    accumulated.append(token)
                    yield f"data: {json.dumps({'token': token})}\n\n"
                yield "data: [DONE]\n\n"
            except OllamaUnavailableError as exc:
                logger.warning("Ollama unavailable during SSE stream: %s", exc)
                yield f"data: {json.dumps({'error': 'Ollama not reachable. Ensure it is running locally.'})}\n\n"
                return
            except OllamaResponseError as exc:
                logger.error("Ollama response error during SSE stream: %s", exc)
                yield f"data: {json.dumps({'error': 'AI model returned an unexpected response.'})}\n\n"
                return
            finally:
                if accumulated:
                    from app.db.session import AsyncSessionLocal
                    async with AsyncSessionLocal() as persist_db:
                        fresh_session = await chat_service.get_session(persist_db, session.id, current_user.id)
                        if fresh_session is not None:
                            await chat_service.append_messages(
                                persist_db,
                                fresh_session,
                                latest.content,
                                "".join(accumulated),
                            )

        return StreamingResponse(_persistent_stream(), media_type="text/event-stream", headers=_SSE_HEADERS)

    return StreamingResponse(_sse_stream(prompt), media_type="text/event-stream", headers=_SSE_HEADERS)
