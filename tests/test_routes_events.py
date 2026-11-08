from datetime import timedelta

from app import storage
from app.models import utcnow
from backend.routes import websocket as ws_module
from tests.conftest import event_json, ingest_headers


def post(api, body, headers=None):
    return api.post("/api/events", json=body, headers=ingest_headers() if headers is None else headers)


# ---- POST /api/events ------------------------------------------------------
def test_single_event_is_stored(api):
    r = post(api, event_json())
    assert r.status_code == 201
    assert r.json()["accepted"] == 1
    assert storage.count_events(api.app_ref.state.db) == 1


def test_batch_is_stored(api):
    r = post(api, {"events": [event_json(dst_port=p) for p in (80, 81, 82)]})
    assert r.status_code == 201
    assert r.json()["accepted"] == 3
    assert len(r.json()["event_ids"]) == 3


def test_missing_key_is_401_and_nothing_stored(api):
    assert post(api, event_json(), headers={}).status_code == 401
    assert storage.count_events(api.app_ref.state.db) == 0


def test_wrong_key_is_401(api):
    assert post(api, event_json(), headers={"X-API-Key": "nope"}).status_code == 401


def test_bad_key_beats_bad_body(api):
    # Auth is checked before validation: a stranger learns nothing about the schema.
    assert post(api, {"nonsense": 1}, headers={"X-API-Key": "nope"}).status_code == 401


def test_invalid_event_is_422_in_standard_error_shape(api):
    r = post(api, event_json(type="not_a_type"))
    assert r.status_code == 422
    assert r.json()["error"] == "validation_error"


def test_invalid_event_inside_batch_rejects_whole_batch(api):
    r = post(api, {"events": [event_json(), event_json(src_ip="not-an-ip")]})
    assert r.status_code == 422
    assert storage.count_events(api.app_ref.state.db) == 0


def test_empty_batch_is_422(api):
    assert post(api, {"events": []}).status_code == 422


def test_batch_over_configured_limit_is_413(api, monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("INGEST_MAX_BATCH", "2")
    get_settings.cache_clear()
    r = post(api, {"events": [event_json(dst_port=p) for p in (1, 2, 3)]})
    assert r.status_code == 413
    assert storage.count_events(api.app_ref.state.db) == 0


def test_rate_limit_returns_429_with_retry_after(api):
    api.app_ref.state.ingest_limiter = type(api.app_ref.state.ingest_limiter)(2, 60)
    assert post(api, event_json()).status_code == 201
    assert post(api, event_json()).status_code == 201
    r = post(api, event_json())
    assert r.status_code == 429
    assert r.headers["retry-after"] == "60"


def test_rate_limit_also_throttles_bad_keys(api):
    api.app_ref.state.ingest_limiter = type(api.app_ref.state.ingest_limiter)(2, 60)
    for _ in range(2):
        assert post(api, event_json(), headers={"X-API-Key": "guess"}).status_code == 401
    assert post(api, event_json(), headers={"X-API-Key": "guess"}).status_code == 429


def test_ingest_disabled_when_key_unconfigured(app_env, monkeypatch):
    from fastapi.testclient import TestClient

    from app.config import get_settings
    from backend.main import create_app

    monkeypatch.setenv("API_KEY", "")
    get_settings.cache_clear()
    with TestClient(create_app(mount_static=False)) as c:
        assert c.post("/api/events", json=event_json(), headers={"X-API-Key": "x"}).status_code == 503


def test_port_scan_batch_raises_an_alert(api):
    body = {"events": [event_json(dst_port=p) for p in range(1, 26)]}
    assert post(api, body).status_code == 201
    alerts = storage.list_alerts(api.app_ref.state.db)
    assert [a.rule for a in alerts] == ["port_scan"]


def test_detection_failure_does_not_fail_ingest(api, monkeypatch):
    from app.detection import engine

    def boom(*a, **k):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(engine, "process_events", boom)
    r = post(api, event_json())
    assert r.status_code == 201
    assert storage.count_events(api.app_ref.state.db) == 1


def test_ingest_broadcasts_event_and_alert(api, monkeypatch):
    sent = []

    async def capture(message):
        sent.append(message)

    monkeypatch.setattr(ws_module.manager, "broadcast", capture)
    post(api, {"events": [event_json(dst_port=p) for p in range(1, 26)]})
    kinds = [m["kind"] for m in sent]
    assert kinds.count("event") == 25
    assert kinds.count("alert") == 1
    assert sent[-1]["data"]["rule"] == "port_scan"


# ---- GET /api/events -------------------------------------------------------
def seed(api):
    db = api.app_ref.state.db
    now = utcnow()
    from app.models import EventIn

    storage.insert_events(db, [
        EventIn(type="dns_query", timestamp=now - timedelta(hours=2), source="s", src_ip="10.0.0.1", dns_name="a.com"),
        EventIn(type="dns_query", timestamp=now - timedelta(hours=1), source="s", src_ip="10.0.0.2", dns_name="b.com"),
        EventIn(type="network_connection", timestamp=now, source="s", src_ip="10.0.0.2", dst_ip="10.0.0.9", dst_port=22),
    ])
    return now


def test_list_events_newest_first(api):
    seed(api)
    body = api.get("/api/events").json()
    assert [e["type"] for e in body] == ["network_connection", "dns_query", "dns_query"]
    assert body[0]["id"] > body[1]["id"] > body[2]["id"]


def test_list_events_filters(api):
    seed(api)
    assert len(api.get("/api/events", params={"type": "dns_query"}).json()) == 2
    assert len(api.get("/api/events", params={"src_ip": "10.0.0.2"}).json()) == 2
    both = api.get("/api/events", params={"type": "dns_query", "src_ip": "10.0.0.2"}).json()
    assert [e["dns_name"] for e in both] == ["b.com"]


def test_list_events_from_and_to_aliases(api):
    now = seed(api)
    since = (now - timedelta(minutes=90)).isoformat()
    until = (now - timedelta(minutes=30)).isoformat()
    body = api.get("/api/events", params={"from": since, "to": until}).json()
    assert [e["dns_name"] for e in body] == ["b.com"]


def test_list_events_limit_and_offset(api):
    seed(api)
    assert len(api.get("/api/events", params={"limit": 1}).json()) == 1
    page2 = api.get("/api/events", params={"limit": 1, "offset": 1}).json()
    assert page2[0]["type"] == "dns_query"


def test_list_events_rejects_bad_params(api):
    assert api.get("/api/events", params={"type": "bogus"}).status_code == 422
    assert api.get("/api/events", params={"limit": 0}).status_code == 422
    assert api.get("/api/events", params={"limit": 5000}).status_code == 422
    assert api.get("/api/events", params={"offset": -1}).status_code == 422
    assert api.get("/api/events", params={"from": "yesterday-ish"}).status_code == 422


def test_ingested_event_is_returned_with_expected_fields(api):
    post(api, event_json())
    e = api.get("/api/events").json()[0]
    assert e["src_ip"] == "10.0.0.5" and e["dst_port"] == 80 and e["protocol"] == "tcp"
    assert "received_at" in e and e["details"] is None


def test_alert_updated_many_times_in_one_batch_is_broadcast_once_in_final_state(api, monkeypatch):
    sent = []

    async def capture(message):
        sent.append(message)

    monkeypatch.setattr(ws_module.manager, "broadcast", capture)
    post(api, {"events": [event_json(dst_port=p) for p in range(1, 31)]})
    alerts = [m["data"] for m in sent if m["kind"] == "alert"]
    assert len(alerts) == 1
    assert alerts[0]["count"] == storage.list_alerts(api.app_ref.state.db)[0].count
