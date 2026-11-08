from app import storage
from app.models import EventIn, utcnow
from tests.conftest import alert as make_alert


def seed_alert(api, **kw):
    db = api.app_ref.state.db
    ev = storage.insert_events(db, [
        EventIn(type="network_connection", timestamp=utcnow(), source="s", src_ip="10.0.0.5",
                dst_ip="10.0.0.1", dst_port=p) for p in (1, 2, 3)
    ])
    a = make_alert(ids=[e.id for e in ev], **kw)
    return storage.insert_alert(db, a), ev


# ---- GET /api/alerts -------------------------------------------------------
def test_list_alerts_empty(api):
    assert api.get("/api/alerts").json() == []


def test_list_alerts_filters(api):
    db = api.app_ref.state.db
    storage.insert_alert(db, make_alert(rule="port_scan", ip="10.0.0.5", severity="high"))
    storage.insert_alert(db, make_alert(rule="dns_anomaly", ip="10.0.0.6", severity="low"))
    assert len(api.get("/api/alerts").json()) == 2
    assert [a["rule"] for a in api.get("/api/alerts", params={"severity": "high"}).json()] == ["port_scan"]
    assert [a["rule"] for a in api.get("/api/alerts", params={"rule": "dns_anomaly"}).json()] == ["dns_anomaly"]
    assert [a["rule"] for a in api.get("/api/alerts", params={"src_ip": "10.0.0.6"}).json()] == ["dns_anomaly"]
    assert api.get("/api/alerts", params={"status": "resolved"}).json() == []


def test_list_alerts_unknown_enum_is_422_not_500(api):
    assert api.get("/api/alerts", params={"severity": "catastrophic"}).status_code == 422
    assert api.get("/api/alerts", params={"status": "maybe"}).status_code == 422


def test_list_alerts_paging(api):
    db = api.app_ref.state.db
    for i in range(3):
        storage.insert_alert(db, make_alert(ip=f"10.0.0.{i + 1}"))
    first = api.get("/api/alerts", params={"limit": 2}).json()
    rest = api.get("/api/alerts", params={"limit": 2, "offset": 2}).json()
    assert len(first) == 2 and len(rest) == 1
    assert first[0]["id"] > first[1]["id"] > rest[0]["id"]


# ---- GET /api/alerts/{id} ----------------------------------------------------
def test_alert_detail_includes_evidence(api):
    alert, events = seed_alert(api)
    body = api.get(f"/api/alerts/{alert.id}").json()
    assert body["id"] == alert.id
    assert [e["id"] for e in body["evidence"]] == [e.id for e in events]
    assert body["evidence_event_ids"] == [e.id for e in events]


def test_alert_detail_tolerates_purged_evidence(api):
    alert, events = seed_alert(api)
    with api.app_ref.state.db.transaction() as conn:
        conn.execute("DELETE FROM events WHERE id = ?", (events[0].id,))
    body = api.get(f"/api/alerts/{alert.id}").json()
    assert len(body["evidence"]) == 2
    assert len(body["evidence_event_ids"]) == 3


def test_alert_detail_404_in_standard_shape(api):
    r = api.get("/api/alerts/9999")
    assert r.status_code == 404
    assert r.json() == {"error": "http_404", "detail": "Alert not found"}


def test_alert_id_must_be_an_integer(api):
    assert api.get("/api/alerts/abc").status_code == 422


# ---- PATCH /api/alerts/{id} ----------------------------------------------------
def test_patch_changes_status(api):
    alert, _ = seed_alert(api)
    r = api.patch(f"/api/alerts/{alert.id}", json={"status": "investigating"})
    assert r.status_code == 200
    assert r.json()["status"] == "investigating"
    assert api.get(f"/api/alerts/{alert.id}").json()["status"] == "investigating"


def test_patch_any_status_to_any_status(api):
    alert, _ = seed_alert(api)
    for status in ("resolved", "new", "false_positive", "investigating"):
        assert api.patch(f"/api/alerts/{alert.id}", json={"status": status}).json()["status"] == status


def test_patch_rejects_unknown_status_and_extra_fields(api):
    alert, _ = seed_alert(api)
    assert api.patch(f"/api/alerts/{alert.id}", json={"status": "closed"}).status_code == 422
    assert api.patch(f"/api/alerts/{alert.id}", json={"status": "new", "title": "x"}).status_code == 422
    assert api.patch(f"/api/alerts/{alert.id}", json={}).status_code == 422


def test_patch_404(api):
    assert api.patch("/api/alerts/9999", json={"status": "resolved"}).status_code == 404


def test_patch_moves_updated_at_forward_and_counts_as_closed(api):
    alert, _ = seed_alert(api)
    r = api.patch(f"/api/alerts/{alert.id}", json={"status": "resolved"}).json()
    assert r["updated_at"] >= alert.updated_at.isoformat().replace("+00:00", "Z")[:19]
    assert api.get("/api/stats").json()["open_alerts"] == 0


def test_post_alerts_no_longer_exists(api):
    # The old stub accepted unauthenticated POSTs and pretended to create an alert.
    assert api.post("/api/alerts", json={}).status_code == 405


# ---- GET /api/stats ----------------------------------------------------------
def test_stats_on_empty_database(api):
    body = api.get("/api/stats").json()
    assert body["events_total"] == 0 and body["alerts_total"] == 0 and body["open_alerts"] == 0
    assert body["top_source_ips"] == []
    assert set(body["alerts_by_severity"]) == {"low", "medium", "high", "critical"}
    assert set(body["alerts_by_status"]) == {"new", "investigating", "resolved", "false_positive"}


def test_stats_reflect_ingested_data(api):
    seed_alert(api, severity="high")
    body = api.get("/api/stats").json()
    assert body["events_total"] == 3
    assert body["alerts_total"] == 1 and body["open_alerts"] == 1
    assert body["alerts_by_severity"]["high"] == 1
    assert body["top_source_ips"] == [{"src_ip": "10.0.0.5", "count": 3}]
