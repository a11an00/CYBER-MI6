from fastapi import Request

from app.db import Database

def get_db(request: Request) -> Database:
    return request.app.state.db

def get_ingest_limiter(request: Request):
    return request.app.state.ingest_limiter