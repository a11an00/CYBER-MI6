"""POST /api/events (sensor ingestion) and GET /api/events (dashboard feed)."""

import logging
from datetime import datetime
from typing import Annotated, Union

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Discriminator, Tag
from starlette.concurrency import run_in_threadpool

from app import storage
from backend.auth import require_user
from app.config import Settings, get_settings
from app.db import Database
from backend.deps import get_db, get_ingest_limiter
from app.detection import engine
from app.models import Event, EventBatch, EventIn, EventType
from backend.ratelimit import SlidingWindowLimiter
from backend.routes.websocket import broadcast_alert, broadcast_event
from backend.security import require_api_key

log = logging.getLogger(__name__)
router = APIRouter()


def _body_kind(value) -> str:
    # {"events": [...]} is a batch; anything else is validated as a single event, so error
    # messages point at the model the sender most likely meant.
    return "batch" if isinstance(value, dict) and "events" in value else "single"


IngestBody = Annotated[
    Union[Annotated[EventIn, Tag("single")], Annotated[EventBatch, Tag("batch")]],
    Discriminator(_body_kind),
]


def enforce_ingest_rate_limit(
    request: Request,
    limiter: SlidingWindowLimiter = Depends(get_ingest_limiter),
) -> None:
    """One hit per request, keyed by client IP. Runs BEFORE the key check so that
    guessing API keys is throttled too."""
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client):
        raise HTTPException(
            429,
            "Rate limit exceeded",
            headers={"Retry-After": str(limiter.window)},
        )


@router.post(
    "/events",
    status_code=201,
    dependencies=[Depends(enforce_ingest_rate_limit), Depends(require_api_key)],
)
async def ingest_events(
    body: IngestBody,
    db: Database = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Store one event or a batch, run detection on it, and push everything to live clients."""
    events_in = body.events if isinstance(body, EventBatch) else [body]
    if len(events_in) > settings.ingest_max_batch:
        raise HTTPException(
            413, f"Batch too large: {len(events_in)} events (limit {settings.ingest_max_batch})"
        )

    stored = await run_in_threadpool(storage.insert_events, db, events_in)

    # The events are committed at this point. Detection or broadcast trouble must not turn
    # a successful ingest into an error: the sensor would retry and create duplicates.
    try:
        results = await run_in_threadpool(engine.process_events, db, stored, settings)
    except Exception:
        log.exception("detection failed for a stored batch; events kept, no alerts raised")
        results = []

    # A batch that keeps tripping one rule updates the SAME alert once per event; send each
    # alert once, in its final state, instead of a burst of near-identical messages.
    final_alerts = {r.alert.id: r.alert for r in results}

    for event in stored:
        await broadcast_event(event.model_dump(mode="json"))
    for alert in final_alerts.values():
        await broadcast_alert(alert.model_dump(mode="json"))

    return {"accepted": len(stored), "event_ids": [e.id for e in stored]}


@router.get("/events", response_model=list[Event], dependencies=[Depends(require_user)])
def list_events(
    db: Database = Depends(get_db),
    type: EventType | None = None,
    src_ip: Annotated[str | None, Query(max_length=45)] = None,
    since: Annotated[datetime | None, Query(alias="from")] = None,
    until: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=storage.MAX_LIST_LIMIT)] = storage.DEFAULT_LIST_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Newest first. ``from`` / ``to`` are inclusive ISO 8601 timestamps."""
    return storage.list_events(
        db, type=type, src_ip=src_ip, since=since, until=until, limit=limit, offset=offset
    )
