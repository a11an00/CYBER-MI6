"""The blocklist: GET /api/blocklist, POST /api/blocklist, DELETE /api/blocklist/{ip}.

RECORD ONLY. These routes keep a list of addresses an analyst marked as blocked; nothing in the
system refuses traffic from them yet. Enforcement is a separate design (docs/FUTURE_CHANGES.md).
"""

from fastapi import APIRouter, Depends, HTTPException, Response

from app import storage
from app.db import Database
from app.models import BlockedIp, BlockRequest, canonical_ip
from backend.auth import require_user
from backend.deps import get_db

router = APIRouter(dependencies=[Depends(require_user)])  # any logged-in user


@router.get("/blocklist", response_model=list[BlockedIp])
def list_blocklist(db: Database = Depends(get_db)):
    return storage.list_blocked(db)


@router.post("/blocklist", response_model=BlockedIp)
def block_ip(
    body: BlockRequest,
    response: Response,
    db: Database = Depends(get_db),
    user: storage.UserRecord = Depends(require_user),
):
    """201 when newly recorded; 200 with the existing entry if the address was already listed."""
    if body.alert_id is not None and storage.get_alert(db, body.alert_id) is None:
        raise HTTPException(422, f"alert {body.alert_id} does not exist")
    entry, created = storage.add_block(
        db, ip=body.ip, alert_id=body.alert_id, reason=body.reason, blocked_by=user.username
    )
    response.status_code = 201 if created else 200
    return entry


@router.delete("/blocklist/{ip}", status_code=204)
def unblock_ip(ip: str, db: Database = Depends(get_db)) -> Response:
    try:
        address = canonical_ip(ip)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    if not storage.remove_block(db, address):
        raise HTTPException(404, "IP is not blocked")
    return Response(status_code=204)
