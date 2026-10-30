import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from backend.config import Settings, get_settings
from backend.security import require_api_key


def make_client(api_key: str) -> TestClient:
    app = FastAPI()
    app.dependency_overrides[get_settings] = lambda: Settings(api_key=api_key)
    
    @app.get("/protected", dependencies=[Depends(require_api_key)])
    def protected():
        return {'ok':True}
    
    return TestClient(app)


def test_missing_header_is_401():
    assert make_client("secret").get("/protected").status_code == 401
    

def test_wrong_key_is_401():
    r = make_client("secret").get("/protected", headers={"X-API-Key": "nope"})
    assert r.status_code == 401
    
    
def test_correct_key_passes():
    r = make_client("secret").get("/protected", headers={"X-API-Key": "secret"})
    assert r.status_code == 200
    
    
def test_unconfigured_key_is_503():
    r = make_client("").get("/protected", headers={"X-API-Key": "anything"})
    assert r.status_code == 503
    

def test_non_ascii_key_is_401_not_500():
    client = make_client("secret")
    # Send the UTF-8 bytes directly: HTTP clients don't accept non-ASCII str headers.
    r = client.get("/protected", headers={"X-API-Key": "sécret".encode("utf-8")})
    assert r.status_code == 401