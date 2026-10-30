import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException  as StarletteHTTPException

from app.config import get_settings
from app.db import open_database
from app.ratelimit import SlidingWindowLimiter
from app.routes import ws

log = logging.getLogger(__name__)

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
RETENTION_INTERVAL_SECONDS = 3600


def error_response(status: int, code: str, detail, headers=None) -> JSONResponse:
    """Every error the API returns has this shape: {"error": ..., "detail": ...}"""
    return JSONResponse(
        content={"error": code, "detail": detail},
        status_code= status,
        headers=headers,
    )
    
async def _retention_loop(db, retention_days: int) -> None:
    from app import storage #imported here so main.py loads before storage.py is merged
    while True:
        try:
            removed= await run_in_threadpool(storage.purge_old_events, db, retention_days)
            if removed:
                log.info("Reception removed %d old events", removed)
        except Exception:
            log.exception("Retention job failed; will retry")
        await asyncio.sleep(RETENTION_INTERVAL_SECONDS)
        
        
@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    db = open_database(settings.database_path) #creates the file and tables
    app.state.db = db
    app.state.ingest_limiter = SlidingWindowLimiter(
        settings.ingest_rate_limit, settings.ingest_rate_window_seconds
    )
    retention = asyncio.create_task(_retention_loop(db, settings.event_retention_days))
    try:
        yield
    finally:
        retention.cancel()
        with suppress(asyncio.CancelledError):
            await retention
        db.close()
        
        
def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="CYBER-MI6 API",
        version="1.0.0",
        description="Event ingenstion, alerts, and live dashboard feed.",
        lifespan=lifespan,
    )
    if settings.origins_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.origins_list,
            allow_methods=["GET", "POST", "PATCH"],
            allow_headers=["Content-Type", "X-API-Key"],
        )
        
    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: RequestValidationError):
        errors = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]
        return error_response(422, "validation_error", errors)
    
    @app.exception_handler(StarletteHTTPException)
    async def http_handler(request: Request, exc: StarletteHTTPException):
        return error_response(exc.status_code, f"http_{exc.status_code}", exc.detail, exc.headers)
    
    app.include_router(ws.router)
    #Add the events, alerts and stats routers here as each on is merged.
    
    #Mounted last, so the static files can't shadow API routes.
    if WEB_DIR.is_dir():
        app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
        
    return app

app = create_app()
    