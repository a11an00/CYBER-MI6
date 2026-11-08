"""GET /api/stats: the dashboard's headline numbers."""

from fastapi import APIRouter, Depends

from app import storage
from backend.auth import require_user
from app.db import Database
from backend.deps import get_db
from app.models import Stats

router = APIRouter(dependencies=[Depends(require_user)])  # any logged-in user


@router.get("/stats", response_model=Stats)
def get_stats(db: Database = Depends(get_db)):
    return storage.stats(db)
