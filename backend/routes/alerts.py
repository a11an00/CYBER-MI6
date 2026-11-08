"""GET /api/alerts, GET /api/alerts/{id}, PATCH /api/alerts/{id}."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from app import storage
from backend.auth import require_user
from app.db import Database
from backend.deps import get_db
from app.models import Alert, AlertDetail, AlertStatus, AlertUpdate, Severity

router = APIRouter(dependencies=[Depends(require_user)])  # any logged-in user


@router.get("/alerts", response_model=list[Alert])
def list_alerts(
    db: Database = Depends(get_db),
    severity: Severity | None = None,
    status: AlertStatus | None = None,
    rule: Annotated[str | None, Query(max_length=64)] = None,
    src_ip: Annotated[str | None, Query(max_length=45)] = None,
    limit: Annotated[int, Query(ge=1, le=storage.MAX_LIST_LIMIT)] = storage.DEFAULT_LIST_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Newest first (by creation time)."""
    return storage.list_alerts(
        db, severity=severity, status=status, rule=rule, src_ip=src_ip, limit=limit, offset=offset
    )


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: int, db: Database = Depends(get_db)):
    alert = storage.get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    evidence = storage.get_events_by_ids(db, alert.evidence_event_ids)
    return AlertDetail.model_construct(**alert.model_dump(), evidence=evidence)


@router.patch("/alerts/{alert_id}", response_model=Alert)
def update_alert(alert_id: int, update: AlertUpdate, db: Database = Depends(get_db)):
    """Any status may move to any other status for now (see docs/FUTURE_CHANGES.md)."""
    alert = storage.update_alert_status(db, alert_id, update)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    return alert
