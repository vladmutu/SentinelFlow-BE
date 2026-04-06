"""Thin background-job executor.

The default implementation uses ``asyncio.create_task`` to run coroutines
in the same event loop.  This is the simplest option when the project
does not yet have a worker infrastructure (Celery, RQ, Arq, etc.).

To migrate to Celery later, create a ``CeleryJobRunner`` that serialises
the call and pushes it onto a queue instead of scheduling it locally.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Coroutine, Any

logger = logging.getLogger(__name__)


class JobRunner:
    """Submit coroutines for background execution.

    Usage::

        runner = JobRunner()
        runner.submit(some_coroutine(...))
    """

    def submit(self, coro: Coroutine[Any, Any, None]) -> asyncio.Task:
        """Schedule *coro* as a fire-and-forget background task.

        The returned ``asyncio.Task`` can be awaited in tests but is
        otherwise safe to ignore.
        """
        task = asyncio.create_task(coro)
        task.add_done_callback(self._on_done)
        return task

    # ── internal ───────────────────────────────────────────────────────
    @staticmethod
    def _on_done(task: asyncio.Task) -> None:
        if task.cancelled():
            logger.warning("Background job was cancelled")
            return
        exc = task.exception()
        if exc is not None:
            logger.error("Background job failed: %s", exc, exc_info=exc)


# Module-level singleton.
job_runner = JobRunner()
