"""Dashboard authentication: JWT (JSON Web Token) creation and the dependencies that check it.

Sensors authenticate with the ingestion API key (backend/security.py). Humans use the
dashboard: they log in at POST /api/token and send ``Authorization: Bearer <token>``.

Design choices worth knowing:
* The token carries only the user id. Role and status are read from the database on EVERY
  request, so disabling a user or changing their role takes effect immediately, not when
  their token expires.
* Algorithm is pinned to HS256 on decode; ``exp``, ``iat``, ``sub`` and the issuer are required.
* No JWT_SECRET configured -> every protected route answers 503 (fail closed), same idea as API_KEY.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, WebSocket
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.concurrency import run_in_threadpool

from app import storage
from app.config import Settings, get_settings
from app.db import Database
from backend.deps import get_db
from app.models import ROLE_PERMISSIONS, UserProfile

log = logging.getLogger(__name__)

ALGORITHM = "HS256"
ISSUER = "cyber-mi6"
WS_AUTH_TIMEOUT_SECONDS = 5.0
WS_CLOSE_UNAUTHORIZED = 4401  # application-defined close code: "log in again"

_bearer = HTTPBearer(auto_error=False)  # we raise our own 401 (HTTPBearer's default is 403)
_UNAUTHORIZED_HEADERS = {"WWW-Authenticate": "Bearer"}


def to_profile(user: storage.UserRecord) -> UserProfile:
    """The password-free view of a user that routes are allowed to return."""
    return UserProfile(
        id=user.id,
        username=user.username,
        role=user.role,
        permissions=list(ROLE_PERMISSIONS[user.role]),
        status=user.status,
        last_login=user.last_login,
    )


def create_access_token(user: storage.UserRecord, settings: Settings, *, now: datetime | None = None) -> str:
    issued = now or datetime.now(timezone.utc)
    claims = {
        "iss": ISSUER,
        "sub": user.id,
        "iat": issued,
        "exp": issued + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(claims, settings.jwt_secret, algorithm=ALGORITHM)


def user_from_token(db: Database, settings: Settings, token: str) -> storage.UserRecord | None:
    """The active user a token belongs to, or None for anything wrong with it
    (bad signature, expired, wrong issuer, unknown or disabled user)."""
    if not settings.jwt_secret:
        return None
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError:
        return None
    subject = claims.get("sub")
    if not isinstance(subject, str):
        return None
    user = storage.get_user(db, subject)
    return user if user is not None and user.status == "active" else None


def _require_configured(settings: Settings) -> None:
    if not settings.jwt_secret:
        raise HTTPException(503, "Login is disabled: JWT_SECRET is not configured")


def require_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Database = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> storage.UserRecord:
    """Dependency for any route that needs a logged-in, active user."""
    _require_configured(settings)
    if credentials is None:
        raise HTTPException(401, "Not authenticated", headers=_UNAUTHORIZED_HEADERS)
    user = user_from_token(db, settings, credentials.credentials)
    if user is None:
        raise HTTPException(401, "Invalid or expired token", headers=_UNAUTHORIZED_HEADERS)
    return user


def require_admin(user: storage.UserRecord = Depends(require_user)) -> storage.UserRecord:
    if user.role != "admin":
        raise HTTPException(403, "Admin role required")
    return user


# --------------------------------------------------------------------------
# WebSocket: browsers cannot set an Authorization header on a WebSocket, and a token in the
# URL ends up in logs and history. So the client sends {"type": "auth", "token": ...} as its
# FIRST message; the server only starts streaming after that checks out.
# --------------------------------------------------------------------------
async def authenticate_websocket(ws: WebSocket) -> bool:
    """Run the first-message handshake on an ACCEPTED socket. Closes it and returns False on failure."""

    async def reject() -> bool:
        with suppress(Exception):  # the client may already be gone
            await ws.close(code=WS_CLOSE_UNAUTHORIZED)
        return False

    try:
        message = await asyncio.wait_for(ws.receive_json(), WS_AUTH_TIMEOUT_SECONDS)
    except Exception:  # timeout, disconnect, not JSON, binary frame
        return await reject()
    token = message.get("token") if isinstance(message, dict) and message.get("type") == "auth" else None
    if not isinstance(token, str) or not token:
        return await reject()

    state = ws.app.state
    user = await run_in_threadpool(user_from_token, state.db, get_settings(), token)
    if user is None:
        return await reject()
    return True
