"""
SSE (Server-Sent Events) helper utilities for the cyber-agents-demo backend.

Provides:
- format_sse()    : serialise a dict into the SSE wire format
- EventQueue      : thin asyncio.Queue wrapper with typed put/get
- event_generator : async generator that drains an EventQueue for StreamingResponse
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncGenerator, Optional

logger = logging.getLogger(__name__)

# Sentinel value pushed to the queue when the stream should terminate
_STREAM_DONE = object()


def format_sse(data: dict, event: Optional[str] = None) -> str:
    """
    Serialise *data* into a valid SSE frame.

    Parameters
    ----------
    data:
        JSON-serialisable dict to send as the event payload.
    event:
        Optional SSE event name (sets the ``event:`` field).
        When omitted the browser will fire a generic ``message`` event.

    Returns
    -------
    A string ready to be yielded from a StreamingResponse, e.g.::

        "data: {...}\\n\\n"
        "event: game_over\\ndata: {...}\\n\\n"
    """
    payload = json.dumps(data, default=str)
    lines: list[str] = []
    if event:
        lines.append(f"event: {event}")
    lines.append(f"data: {payload}")
    return "\n".join(lines) + "\n\n"


class EventQueue:
    """
    Thin wrapper around :class:`asyncio.Queue` for SSE event buffering.

    Usage::

        queue = EventQueue()

        # producer side
        await queue.put({"type": "action", "team": "red", ...})
        await queue.close()   # signal end-of-stream

        # consumer side (usually inside event_generator)
        event = await queue.get()
    """

    def __init__(self, maxsize: int = 0) -> None:
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=maxsize)

    async def put(self, item: dict) -> None:
        """Enqueue an event dict."""
        await self._queue.put(item)

    async def get(self) -> Any:
        """
        Dequeue the next item.

        Returns the sentinel ``_STREAM_DONE`` when :meth:`close` has been called
        and the queue is drained.  Callers should check for this with
        :func:`is_done`.
        """
        return await self._queue.get()

    def get_nowait(self) -> Any:
        """Non-blocking dequeue; raises asyncio.QueueEmpty if empty."""
        return self._queue.get_nowait()

    async def close(self) -> None:
        """Push the end-of-stream sentinel so the generator terminates cleanly."""
        await self._queue.put(_STREAM_DONE)

    def is_done(self, item: Any) -> bool:
        """Return True if *item* is the end-of-stream sentinel."""
        return item is _STREAM_DONE

    def empty(self) -> bool:
        return self._queue.empty()

    def qsize(self) -> int:
        return self._queue.qsize()


async def event_generator(
    queue: EventQueue,
    timeout: float = 120.0,
) -> AsyncGenerator[str, None]:
    """
    Async generator that drains *queue* and yields SSE-formatted strings.

    Designed to be passed directly to FastAPI's ``StreamingResponse``::

        return StreamingResponse(
            event_generator(queue),
            media_type="text/event-stream",
        )

    Parameters
    ----------
    queue:
        An :class:`EventQueue` fed by the simulation engine.
    timeout:
        Maximum wall-clock seconds to wait for the next event before
        yielding a keep-alive comment and continuing to wait.
        Prevents proxy / load-balancer connection resets on long turns.

    Yields
    ------
    SSE-formatted strings (``"data: {...}\\n\\n"`` etc.).
    """
    while True:
        try:
            item = await asyncio.wait_for(queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            # Send a keep-alive comment so the connection is not closed
            logger.debug("SSE keep-alive sent (no event in %.0fs)", timeout)
            yield ": keep-alive\n\n"
            continue

        if queue.is_done(item):
            logger.debug("SSE stream closed (done sentinel received)")
            break

        # item may already contain an 'event' field used as the SSE event name
        event_name: Optional[str] = item.pop("_sse_event", None) if isinstance(item, dict) else None
        yield format_sse(item, event=event_name)
