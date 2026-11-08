"""Every detector, end to end through the HTTP API: POST events -> alert appears in
GET /api/alerts -> GET /api/alerts/{id} returns the evidence and the rule's explanation."""

import pytest

from tests.conftest import event_json, ingest_headers


def ingest(api, events):
    r = api.post("/api/events", json={"events": events}, headers=ingest_headers())
    assert r.status_code == 201, r.text


SCENARIOS = {
    "port_scan": lambda: [event_json(dst_port=p) for p in range(1, 26)],
    "dns_anomaly": lambda: [
        event_json(type="dns_query", dns_name="a" * 45 + ".example.com", dst_ip=None, dst_port=None, protocol=None)
    ],
    "auth_failures": lambda: [
        event_json(type="auth_failure", username="alice", dst_ip=None, dst_port=None, protocol=None)
        for _ in range(6)
    ],
    "web_paths": lambda: [
        event_json(type="http_request", http_method="GET", http_path="/../../etc/passwd", http_status=404,
                   dst_ip=None, dst_port=None, protocol=None)
    ],
}


@pytest.mark.parametrize("rule", list(SCENARIOS))
def test_detector_alert_is_exposed_through_the_api(api, rule):
    ingest(api, SCENARIOS[rule]())

    alerts = api.get("/api/alerts", params={"rule": rule}).json()
    assert len(alerts) == 1, f"{rule} produced no alert via the API"
    summary = alerts[0]
    assert summary["rule"] == rule and summary["severity"] in {"low", "medium", "high", "critical"}
    assert summary["status"] == "new" and summary["title"]

    detail = api.get(f"/api/alerts/{summary['id']}").json()
    assert detail["explanation"], "explanation (why it fired) must reach the dashboard"
    assert detail["evidence"], "evidence events must reach the dashboard"
    assert {e["id"] for e in detail["evidence"]} == set(detail["evidence_event_ids"])
    assert api.get("/api/stats").json()["alerts_by_severity"][summary["severity"]] == 1


def test_all_four_rules_are_registered_in_the_engine():
    from app.detection import engine

    assert len(engine.RULES) == 4  # port_scan, dns_anomaly, auth_failures, web_paths


def test_benign_traffic_raises_nothing(api):
    ingest(api, [
        event_json(type="dns_query", dns_name="www.example.com", dst_ip=None, dst_port=None, protocol=None),
        event_json(type="http_request", http_method="GET", http_path="/index.html", http_status=200,
                   dst_ip=None, dst_port=None, protocol=None),
        event_json(dst_port=443),
    ])
    assert api.get("/api/alerts").json() == []
