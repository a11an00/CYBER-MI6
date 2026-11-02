from fastapi import APIRouter

router = APIRouter()


@router.get("/events")
async def list_events():
    return []


@router.post("/events")
async def create_event():
    return {"status": "created"}