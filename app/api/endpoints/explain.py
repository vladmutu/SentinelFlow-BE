"""AI explainability endpoints — streaming SSE via Ollama/Mistral."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse

from app.api.deps import get_current_user
from app.api.schemas.explain import AgentChatRequest, ExplainPackageRequest
from app.core.config import settings
from app.models.user import User
from app.services.explain_service import (
    OllamaResponseError,
    OllamaUnavailableError,
    build_chat_prompt_with_rag,
    build_prompt,
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
) -> StreamingResponse:
    """Stream a plain-English AI explanation for a package scan verdict via SSE.

    Each event: `data: {"token": "..."}\\n\\n`
    Terminal event: `data: [DONE]\\n\\n`
    Error event: `data: {"error": "..."}\\n\\n`
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
    return StreamingResponse(_sse_stream(prompt), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/chat")
async def agent_chat_endpoint(
    body: AgentChatRequest,
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Stream an agent chat response via SSE.

    Accepts a conversation history plus optional scan context.
    The agent is constrained to cybersecurity / SentinelFlow topics.
    """
    if not settings.ollama_enabled:
        raise _unavailable_error()

    if not body.messages:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="messages cannot be empty")

    latest = body.messages[-1]
    history = [m.model_dump() for m in body.messages]

    logger.info(
        "SSE chat request (%d messages) by user=%s",
        len(body.messages),
        getattr(current_user, "username", "unknown"),
    )

    prompt = await build_chat_prompt_with_rag(
        user_message=latest.content,
        history=history,
        scan_context=body.scan_context,
    )
    return StreamingResponse(_sse_stream(prompt), media_type="text/event-stream", headers=_SSE_HEADERS)
