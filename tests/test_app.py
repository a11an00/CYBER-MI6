import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from backend.config import get_settings
from backend.main import create_app


class Body(BaseModel):
    n: int
    
@pytest.fixture
def settings_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("API_KEY", "test-key")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()
    
@pytest.fixture
def client(settings_env):
    app = create_app(mount_static=False)
    
    @app.post("/_test/validate")
    def validate(body: Body): #test-only route to trigger a validation error
        return body
    
    with TestClient(app) as c:
        yield c
        
def test_docs_are_served(client):
    assert client.get("/docs").status_code == 200
    
def test_unknown_api_path_returns_json_error(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404
    assert r.json()["error"] == "http_404"
    
def test_validation_error_has_standard_shape(client):
    r = client.post("/_test/validate", json={"n": "not a number"})
    assert r.status_code == 422
    body = r.json()
    assert body["error"] == "validation_error"
    assert body["detail"][0]["loc"][-1] == "n"
    
def test_startup_creates_database_file(settings_env):
    app = create_app(mount_static=False)
    with TestClient(app):
        assert (settings_env / "test.db").exists()
        assert app.state.db is not None