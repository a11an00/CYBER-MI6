import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings
from app.db import open_database
from backend.ratelimit import SlidingWindowLimiter
from backend.routes import websocket as ws_module

log = logging.getLogger(__name__)

# The Svelte dashboard is built to frontend/dist/ via `npm run build` in frontend/.
# Fall back to the legacy web/ placeholder if the build output doesn't exist yet.
_FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
_WEB_LEGACY = Path(__file__).resolve().parent.parent / "web"
WEB_DIR = _FRONTEND_DIST if _FRONTEND_DIST.is_dir() else _WEB_LEGACY

RETENTION_INTERVAL_SECONDS = 3600


def error_response(status: int, code: str, detail, headers=None) -> JSONResponse:
    """Every error the API returns has this shape: {"error": ..., "detail": ...}"""
    return JSONResponse(
        content={"error": code, "detail": detail},
        status_code=status,
        headers=headers,
    )


async def _retention_loop(db, retention_days: int, executor: ThreadPoolExecutor) -> None:
    from app import storage
    loop = asyncio.get_running_loop()
    while True:
        try:
            # Own single-thread executor (not the shared threadpool) so shutdown can WAIT for
            # an in-flight purge. Cancelling this task does not stop a running thread.
            removed = await loop.run_in_executor(executor, storage.purge_old_events, db, retention_days)
            if removed:
                log.info("Retention removed %d old events", removed)
        except Exception:
            log.exception("Retention job failed; will retry")
        await asyncio.sleep(RETENTION_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    db = open_database(settings.database_path)  # creates the file and tables
    app.state.db = db
    app.state.ingest_limiter = SlidingWindowLimiter(
        settings.ingest_rate_limit, settings.ingest_rate_window_seconds
    )
    app.state.login_limiter = SlidingWindowLimiter(
        settings.login_rate_limit, settings.login_rate_window_seconds
    )
    if not settings.jwt_secret:
        log.warning("JWT_SECRET is not set: dashboard login and every dashboard route are disabled (503)")
    retention_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="retention")
    retention = asyncio.create_task(
        _retention_loop(db, settings.event_retention_days, retention_executor)
    )
    try:
        yield
    finally:
        retention.cancel()
        with suppress(asyncio.CancelledError):
            await retention
        # Wait for an in-flight purge_old_events to finish BEFORE closing the connections:
        # closing a SQLite connection while another thread is inside a statement crashes
        # the interpreter (segfault). shutdown(wait=True) blocks until that thread is done.
        await run_in_threadpool(retention_executor.shutdown, True)
        db.close()


def create_app(*, mount_static: bool = True) -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="CYBER-MI6 API",
        version="1.0.0",
        description="Event ingestion, alerts, and live dashboard feed.",
        lifespan=lifespan,
    )
    if settings.origins_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.origins_list,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "X-API-Key", "Authorization"],
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        errors = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]
        return error_response(422, "validation_error", errors)

    @app.exception_handler(StarletteHTTPException)
    async def http_handler(request: Request, exc: StarletteHTTPException):
        return error_response(exc.status_code, f"http_{exc.status_code}", exc.detail, exc.headers)

    app.include_router(ws_module.router)
    from backend.routes import alerts, blocklist, events, stats
    from backend.routes import auth as auth_routes
    from backend.routes import users
    app.include_router(auth_routes.router, prefix="/api")
    app.include_router(users.router, prefix="/api")
    app.include_router(blocklist.router, prefix="/api")
    app.include_router(events.router, prefix="/api")
    app.include_router(alerts.router, prefix="/api")
    app.include_router(stats.router, prefix="/api")

    # Mounted last so static files cannot shadow API routes.
    if mount_static and WEB_DIR.is_dir():
        app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")

    return app


app = create_app()
