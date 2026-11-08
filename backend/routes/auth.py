"""POST /api/token: exchange a username and password for a JWT."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from backend import auth
from app import passwords, storage
from app.config import Settings, get_settings
from app.db import Database
from backend.deps import get_db, get_login_limiter
from app.models import AuthResponse, LoginRequest
from backend.ratelimit import SlidingWindowLimiter

log = logging.getLogger(__name__)
router = APIRouter()

_INVALID = "Invalid username or password"


def enforce_login_rate_limit(
    request: Request,
    limiter: SlidingWindowLimiter = Depends(get_login_limiter),
) -> None:
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client):
        raise HTTPException(429, "Too many login attempts", headers={"Retry-After": str(limiter.window)})


@router.post("/token", response_model=AuthResponse, dependencies=[Depends(enforce_login_rate_limit)])
def login(
    body: LoginRequest,
    db: Database = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AuthResponse:
    if not settings.jwt_secret:
        raise HTTPException(503, "Login is disabled: JWT_SECRET is not configured")

    user = storage.get_user_by_username(db, body.username)
    # Always run one argon2 verification, even for an unknown username, so response time does
    # not reveal which usernames exist. Every failure gets the same message for the same reason
    # (that includes a disabled account).
    password_ok = passwords.verify_password(
        user.password_hash if user else passwords.dummy_hash(), body.password
    )
    if user is None or not password_ok or user.status != "active":
        log.warning("failed login for %r", body.username[:64])
        raise HTTPException(401, _INVALID, headers={"WWW-Authenticate": "Bearer"})

    if passwords.needs_rehash(user.password_hash):  # parameters were raised since this hash was made
        user = storage.update_user(db, user.id, password_hash=passwords.hash_password(body.password)) or user
    storage.record_login(db, user.id)
    user = storage.get_user(db, user.id) or user
    return AuthResponse(access_token=auth.create_access_token(user, settings), user=auth.to_profile(user))
