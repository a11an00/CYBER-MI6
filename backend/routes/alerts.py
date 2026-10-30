from fastapi import APIRouter

router = APIRouter()


@router.get("/alerts")
async def list_alerts():
    return []


@router.post("/alerts")
async def create_alert():
    return {"status": "created"}