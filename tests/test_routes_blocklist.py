"""The blocklist is RECORD ONLY: these tests cover the list, not any enforcement."""

import pytest

from app import storage
from app.models import utcnow
from tests.conftest import alert as make_alert, bearer, event_json, ingest_headers, make_user, token_for


def block(api, ip="203.0.113.50", **extra):
    return api.post("/api/blocklist", json={"ip": ip, **extra})


def test_empty_list(api):
    assert api.get("/api/blocklist").json() == []


def test_block_then_list_in_the_shape_the_frontend_expects(api):
    r = block(api, reason="port scan")
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"ip", "alert_id", "reason", "blocked_at", "blocked_by"}
    assert body["ip"] == "203.0.113.50" and body["reason"] == "port scan" and body["alert_id"] is None
    assert body["blocked_by"] == "analyst1"
    assert api.get("/api/blocklist").json() == [body]


def test_block_from_an_alert_links_the_alert(api):
    alert = storage.insert_alert(api.app_ref.state.db, make_alert(ip="203.0.113.50"))
    assert block(api, alert_id=alert.id).json()["alert_id"] == alert.id


def test_unknown_alert_id_is_422(api):
    r = block(api, alert_id=9999)
    assert r.status_code == 422 and "does not exist" in r.json()["detail"]


def test_blocking_twice_is_idempotent_and_keeps_the_first_entry(api):
    first = block(api, reason="first").json()
    again = block(api, reason="second")
    assert again.status_code == 200 and again.json() == first
    assert len(api.get("/api/blocklist").json()) == 1


def test_ipv6_is_stored_in_canonical_form_so_spellings_are_one_entry(api):
    assert block(api, "2001:0db8:0000:0000:0000:0000:0000:0001").json()["ip"] == "2001:db8::1"
    assert block(api, "2001:db8::1").status_code == 200
    assert len(api.get("/api/blocklist").json()) == 1


@pytest.mark.parametrize("bad", ["", "not-an-ip", "300.1.1.1", "1.2.3", "10.0.0.1/24", "1.1.1.1; DROP TABLE users"])
def test_invalid_addresses_are_422(api, bad):
    assert block(api, bad).status_code == 422
    assert api.get("/api/blocklist").json() == []


def test_body_validation(api):
    assert api.post("/api/blocklist", json={}).status_code == 422
    assert api.post("/api/blocklist", json={"ip": "1.2.3.4", "extra": 1}).status_code == 422
    assert block(api, "1.2.3.4", reason="x" * 201).status_code == 422
    assert block(api, "1.2.3.4", alert_id=0).status_code == 422


def test_blank_reason_is_stored_as_no_reason(api):
    assert block(api, "1.2.3.4", reason="   ").json()["reason"] is None


def test_unblock(api):
    block(api)
    assert api.delete("/api/blocklist/203.0.113.50").status_code == 204
    assert api.get("/api/blocklist").json() == []


def test_unblock_accepts_any_spelling_of_the_same_ipv6_address(api):
    block(api, "2001:db8::1")
    assert api.delete("/api/blocklist/2001:0db8:0:0:0:0:0:1").status_code == 204


def test_unblock_unknown_is_404_and_bad_ip_is_422(api):
    assert api.delete("/api/blocklist/198.51.100.7").status_code == 404
    assert api.delete("/api/blocklist/not-an-ip").status_code == 422


def test_list_is_newest_first(api):
    db = api.app_ref.state.db
    from datetime import timedelta

    now = utcnow()
    storage.add_block(db, ip="10.0.0.1", alert_id=None, reason=None, blocked_by="x", now=now - timedelta(hours=2))
    storage.add_block(db, ip="10.0.0.2", alert_id=None, reason=None, blocked_by="x", now=now)
    assert [b["ip"] for b in api.get("/api/blocklist").json()] == ["10.0.0.2", "10.0.0.1"]


def test_needs_login(anon):
    assert anon.get("/api/blocklist").status_code == 401
    assert anon.post("/api/blocklist", json={"ip": "1.2.3.4"}).status_code == 401
    assert anon.delete("/api/blocklist/1.2.3.4").status_code == 401


def test_a_disabled_user_loses_access_immediately(anon):
    user = make_user(anon.app_ref)
    token = token_for(anon.app_ref, user)
    assert anon.get("/api/blocklist", headers=bearer(token)).status_code == 200
    storage.update_user(anon.app_ref.state.db, user.id, status="disabled")
    assert anon.get("/api/blocklist", headers=bearer(token)).status_code == 401


def test_it_really_is_record_only_blocked_sources_can_still_send_events(api):
    block(api, "10.0.0.5")
    r = api.post("/api/events", json=event_json(src_ip="10.0.0.5"), headers=ingest_headers())
    assert r.status_code == 201
    assert storage.count_events(api.app_ref.state.db) == 1


def test_cors_preflight_allows_delete(app_env, monkeypatch):
    from fastapi.testclient import TestClient

    from app.config import get_settings
    from backend.main import create_app

    monkeypatch.setenv("ALLOWED_ORIGINS", "http://localhost:5173")
    get_settings.cache_clear()
    with TestClient(create_app(mount_static=False)) as c:
        r = c.options("/api/blocklist/1.2.3.4", headers={"Origin": "http://localhost:5173",
                                                          "Access-Control-Request-Method": "DELETE"})
        assert "DELETE" in r.headers["access-control-allow-methods"]
