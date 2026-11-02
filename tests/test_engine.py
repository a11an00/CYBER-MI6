import logging
import time
from datetime import timedelta
from types import SimpleNamespace

import pytest

from backend import storage
from backend.config import Settings
from backend.detection import auth_failures, dns_anomaly, engine, portscan
from backend.detection.engine import AlertResult, process_event, process_events
from backend.models import AlertIn, AlertUpdate
from tests.detection_helpers import T0, at, dns, login_fail, request, scan, syn

S = SimpleNamespace(port_scan_ports=20, port_scan_window_seconds=30, alert_cooldown_seconds=300)
RANDOM_LABEL = "x9f3k2q8z7w1m5v4b6n0c8d2"


def feed(db, events, settings=S, **kw):
    """Store events, then run the engine over them (what the ingestion route does)."""
    return process_events(db, storage.insert_events(db, events), settings, now=kw.pop("now", T0), **kw)


# ---- end to end --------------------------------------------------------------
def test_port_scan_end_to_end(db):
    results = feed(db, scan(range(1, 21)))
    assert len(results) == 1  # only the 20th distinct port reaches the threshold
    r = results[0]
    assert isinstance(r, AlertResult) and r.rule == "port_scan" and r.created is True
    stored = storage.get_alert(db, r.alert.id)
    assert stored.rule == "port_scan" and stored.status == "new" and stored.src_ip == "10.0.0.5"
    assert stored.evidence_event_ids == list(range(1, 21))
    assert stored.explanation["observed"] == 20 and stored.explanation["threshold"] == 20
    assert [e.id for e in storage.get_alert_evidence(db, stored.id)] == list(range(1, 21))


def test_no_alert_for_normal_traffic(db):
    normal = [syn(443, t=1), syn(80, t=2), syn(443, t=3), dns("example.com", t=4), request("/index.html", t=5),
              login_fail(t=6)]
    assert feed(db, normal) == []
    assert storage.list_alerts(db) == []


def test_each_rule_end_to_end(db):
    results = feed(db, [dns(f"{RANDOM_LABEL}.example.net"), request("/.env", ip="172.16.4.9", t=1)]
                   + [login_fail("admin", ip="10.0.0.9", t=2 + i) for i in range(5)])
    assert sorted(r.rule for r in results) == ["auth_failures", "dns_anomaly", "web_paths"]
    by_rule = {r.rule: r.alert for r in results}
    assert by_rule["web_paths"].severity == "high" and by_rule["web_paths"].src_ip == "172.16.4.9"
    assert by_rule["dns_anomaly"].evidence_event_ids == [1]
    assert by_rule["auth_failures"].count == 5


def test_one_event_can_raise_alerts_from_several_rules(db):
    rules_hit = process_event(
        db, storage.insert_event(db, request("/../../etc/passwd", ip="10.0.0.9")), S, now=T0)
    assert [r.rule for r in rules_hit] == ["web_paths"]


# ---- de-duplication ----------------------------------------------------------
def test_continuing_scan_updates_the_same_alert(db):
    first = feed(db, scan(range(1, 21)))[0].alert
    more = feed(db, scan(range(21, 26), start=10), now=T0 + timedelta(seconds=10))
    assert [r.created for r in more] == [False] * 5 and {r.alert.id for r in more} == {first.id}
    final = storage.get_alert(db, first.id)
    assert final.count == 25 and len(storage.list_alerts(db)) == 1
    assert final.explanation["observed"] == 25
    assert final.evidence_event_ids == list(range(1, 26))


def test_severity_escalates_as_the_scan_grows(db):
    feed(db, scan(range(1, 21), step=0.01))
    assert storage.list_alerts(db)[0].severity == "medium"
    feed(db, scan(range(21, 101), start=1, step=0.01), now=T0 + timedelta(seconds=1))
    alert = storage.list_alerts(db)[0]
    assert alert.severity == "high" and len(storage.list_alerts(db)) == 1


def test_after_the_cooldown_a_new_alert_is_created(db):
    feed(db, scan(range(1, 21)), now=T0)
    later = feed(db, scan(range(1, 21), ip="10.0.0.5", start=100), now=T0 + timedelta(seconds=400))
    assert [r.created for r in later] == [True] and len(storage.list_alerts(db)) == 2


def test_cooldown_zero_disables_deduplication(db):
    settings = SimpleNamespace(port_scan_ports=3, port_scan_window_seconds=30, alert_cooldown_seconds=0)
    results = feed(db, scan([1, 2, 3, 4, 5]), settings)  # fires on events 3, 4 and 5
    assert [r.created for r in results] == [True, True, True] and len(storage.list_alerts(db)) == 3


def test_resolved_alert_does_not_absorb_new_activity(db):
    first = feed(db, scan(range(1, 21)))[0].alert
    storage.update_alert_status(db, first.id, AlertUpdate(status="resolved"), now=T0)
    again = feed(db, scan(range(21, 22), start=10), now=T0 + timedelta(seconds=10))  # scan continues after it
    assert [r.created for r in again] == [True] and again[0].alert.id != first.id


def test_alerts_from_different_rules_and_sources_stay_separate(db):
    feed(db, scan(range(1, 21), ip="10.0.0.5") + scan(range(1, 21), ip="10.0.0.6", start=1))
    assert sorted(a.src_ip for a in storage.list_alerts(db)) == ["10.0.0.5", "10.0.0.6"]


# ---- windows use the event's own time ----------------------------------------
def test_late_arriving_event_is_judged_by_its_own_timestamp(db):
    feed(db, scan(range(1, 20), step=0.5))  # 19 ports at t = 0 .. 9, no alert
    assert storage.list_alerts(db) == []
    # a 20th port that happened at t=9.5 but only arrives now (sensor buffered it): still inside the window
    late = feed(db, [syn(20, t=9.5)])
    assert [r.rule for r in late] == ["port_scan"]


def test_old_events_do_not_combine_with_a_much_later_one(db):
    feed(db, scan(range(1, 20), step=0.5))
    assert feed(db, [syn(20, t=500)]) == []  # 490 s later: the window has moved on


# ---- ignore list and disabled rules ------------------------------------------
@pytest.mark.parametrize("ignore", ["10.0.0.5", "10.0.0.0/24", " 192.168.1.1 , 10.0.0.0/8 ", ["10.0.0.5"]])
def test_ignored_sources_never_alert(db, ignore):
    settings = SimpleNamespace(**{**S.__dict__, "detection_ignore_ips": ignore})
    assert feed(db, scan(range(1, 40)), settings) == []


def test_ignore_list_only_affects_matching_sources_and_tolerates_junk(db):
    settings = SimpleNamespace(**{**S.__dict__, "detection_ignore_ips": "not-an-ip, 10.9.9.9, 2001:db8::/32"})
    assert len(feed(db, scan(range(1, 21)), settings)) == 1


def test_disabled_rules_are_skipped(db):
    settings = SimpleNamespace(**{**S.__dict__, "detection_disabled_rules": "Port_Scan, dns_anomaly"})
    assert feed(db, scan(range(1, 21)) + [dns(f"{RANDOM_LABEL}.example.net", t=11)], settings) == []
    assert [r.rule for r in feed(db, [request("/.env", t=12)], settings)] == ["web_paths"]


# ---- robustness --------------------------------------------------------------
def test_a_failing_rule_does_not_stop_the_others_or_the_engine(db, caplog):
    class Broken:
        RULE_NAME = "broken"

        @staticmethod
        def evaluate(event, recent, settings):
            raise RuntimeError("bug in a rule")

    class NeedsBadQuery:
        RULE_NAME = "bad_query"

        @staticmethod
        def history_query(event, settings):
            return {"since": "not-a-datetime"}

        @staticmethod
        def evaluate(event, recent, settings):
            return None

    rules = (Broken, NeedsBadQuery, dns_anomaly)
    event = storage.insert_event(db, dns(f"{RANDOM_LABEL}.example.net"))
    with caplog.at_level(logging.ERROR, logger="backend.detection.engine"):
        results = process_event(db, event, S, rules=rules, now=T0)
    assert [r.rule for r in results] == ["dns_anomaly"]
    assert "broken" in caplog.text and "bad_query" in caplog.text


def test_process_event_requires_a_stored_event(db):
    with pytest.raises(ValueError, match="stored Event"):
        process_event(db, dns("example.com"), S)


def test_rules_without_history_do_not_touch_the_database(db, monkeypatch):
    calls = []
    real = storage.events_in_window
    monkeypatch.setattr(storage, "events_in_window", lambda *a, **k: calls.append(k) or real(*a, **k))
    process_event(db, storage.insert_event(db, dns("example.com")), S, now=T0)
    process_event(db, storage.insert_event(db, request("/index.html")), S, now=T0)
    assert calls == []  # dns and http events need no history queries
    process_event(db, storage.insert_event(db, syn(80)), S, now=T0)
    assert [c["type"] for c in calls] == ["network_connection"]


def test_custom_rule_modules_plug_in(db):
    class Always:
        RULE_NAME = "always"

        @staticmethod
        def evaluate(event, recent, settings):
            return AlertIn(rule="always", severity="low", title="t", src_ip=event.src_ip, evidence_event_ids=[event.id])

    event = storage.insert_event(db, request("/x"))
    (result,) = process_event(db, event, S, rules=(Always,), now=T0)
    assert result.alert.evidence_event_ids == [event.id]


def test_flood_from_one_source_stays_one_alert_and_fast(db):
    events = storage.insert_events(db, scan([1 + i % 400 for i in range(600)], step=0.01))
    started = time.perf_counter()
    results = process_events(db, events, S, now=T0)
    elapsed = time.perf_counter() - started
    assert len(storage.list_alerts(db)) == 1 and results[0].created is True
    assert elapsed < 20, f"600 flood events took {elapsed:.1f}s"
    print(f"\n  600-event flood processed in {elapsed:.2f}s ({elapsed / 600 * 1000:.1f} ms/event)")


# ---- integration with the real Settings class --------------------------------
def test_works_with_the_real_settings_object(db):
    settings = Settings(_env_file=None, port_scan_ports=5, port_scan_window_seconds=10, alert_cooldown_seconds=60)
    results = feed(db, scan(range(1, 6)), settings)
    assert [r.rule for r in results] == ["port_scan"]
    assert results[0].alert.explanation["threshold"] == 5 and results[0].alert.explanation["window_seconds"] == 10


def test_rule_defaults_match_the_defaults_in_config_py():
    """If someone changes a default in one place, this fails so the docs and rules don't drift."""
    s = Settings(_env_file=None)
    assert (portscan.DEFAULT_PORTS, portscan.DEFAULT_WINDOW_SECONDS) == (s.port_scan_ports, s.port_scan_window_seconds)
    assert dns_anomaly.DEFAULT_MAX_LABEL_LENGTH == s.dns_max_label_length
    assert dns_anomaly.DEFAULT_MIN_ENTROPY == s.dns_min_entropy
    assert (auth_failures.DEFAULT_COUNT, auth_failures.DEFAULT_WINDOW_SECONDS) == (s.auth_fail_count, s.auth_fail_window_seconds)
    assert engine.DEFAULT_COOLDOWN_SECONDS == s.alert_cooldown_seconds


def test_alert_payload_is_json_serialisable_for_the_websocket(db):
    (result,) = feed(db, scan(range(1, 21)))
    payload = result.alert.model_dump(mode="json")
    assert payload["rule"] == "port_scan" and payload["id"] == result.alert.id
    assert payload["created_at"].endswith("Z") or "+" in payload["created_at"]


def test_engine_is_safe_to_call_from_many_threads(db):
    """The ingestion route runs the engine in the threadpool, so several events are processed at once."""
    import threading

    events = storage.insert_events(db, scan(range(1, 101), step=0.01))
    errors, results = [], []

    def work(chunk):
        try:
            results.extend(process_events(db, chunk, S, now=T0))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(events[i::4],)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert errors == []
    assert sum(1 for r in results if r.created) == 1  # exactly one new alert; every other hit updated it
    assert len(storage.list_alerts(db)) == 1
