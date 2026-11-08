"""User administration (admin role only): list, create, edit, enable/disable."""

from fastapi import APIRouter, Depends, HTTPException

from backend import auth
from app import passwords, storage
from app.db import Database
from backend.deps import get_db
from app.models import UserCreate, UserProfile, UserStatusUpdate, UserUpdate

router = APIRouter(dependencies=[Depends(auth.require_admin)])


def _taken() -> HTTPException:
    return HTTPException(409, "That username is already in use")


def _last_admin() -> HTTPException:
    return HTTPException(409, "This would leave no active admin; make another user an admin first")


@router.get("/users", response_model=list[UserProfile])
def list_users(db: Database = Depends(get_db)):
    return [auth.to_profile(u) for u in storage.list_users(db)]


@router.post("/users", response_model=UserProfile, status_code=201)
def create_user(body: UserCreate, db: Database = Depends(get_db)):
    try:
        user = storage.create_user(
            db,
            username=body.username,
            password_hash=passwords.hash_password(body.password),
            role=body.role,
            status=body.status,
        )
    except storage.UsernameTakenError:
        raise _taken() from None
    return auth.to_profile(user)


@router.patch("/users/{user_id}", response_model=UserProfile)
def update_user(user_id: str, body: UserUpdate, db: Database = Depends(get_db)):
    try:
        user = storage.update_user(
            db,
            user_id,
            username=body.username,
            password_hash=passwords.hash_password(body.password) if body.password else None,
            role=body.role,
            status=body.status,
        )
    except storage.UsernameTakenError:
        raise _taken() from None
    except storage.LastAdminError:
        raise _last_admin() from None
    if user is None:
        raise HTTPException(404, "User not found")
    return auth.to_profile(user)


@router.patch("/users/{user_id}/status", response_model=UserProfile)
def set_status(user_id: str, body: UserStatusUpdate, db: Database = Depends(get_db)):
    try:
        user = storage.update_user(db, user_id, status=body.status)
    except storage.LastAdminError:
        raise _last_admin() from None
    if user is None:
        raise HTTPException(404, "User not found")
    return auth.to_profile(user)
