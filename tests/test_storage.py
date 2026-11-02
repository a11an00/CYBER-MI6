from datetime import timedelta

import pytest

from backend import storage as st
from backend.models import AlertUpdate
from tests.conftest import NOW, ago, alert, auth, dns, http, syn


# ---- events -----------------------------------------------------------------
def test_insert_and_get_roundtrip_all_types(db):
    stored = [
        st.insert_event(db, syn(port=445)),
        st.insert_event(db, dns("Long.Example.com.")),
        st.insert_event(db, auth("root")),
        st.insert_event(db, http("/login?token=abc", status=401)),
    ]
    assert [e.id for e in stored] == [1, 2, 3, 4]
    for e in stored:
        back = st.get_event(db, e.id)
        assert back.model_dump(exclude={"received_at"}) == e.model_dump(exclude={"received_at"})
    assert st.get_event(db, 1).dst_port == 445
    assert st.get_event(db, 2).dns_name == "long.example.com"
    assert st.get_event(db, 4).http_path == "/login"
    assert st.get_event(db, 999) is None


def test_details_json_roundtrip(db):
    ev = syn()
    ev.details = {"iface": "eth0", "ttl": 64, "ok": True, "none": None}
    e = st.insert_event(db, ev)
    assert st.get_event(db, e.id).details == ev.details


def test_batch_insert_is_atomic(db):
    class Boom:  # an object that explodes halfway through the batch
        def __iter__(self):
            yield syn()
            yield syn(port=81)
            raise RuntimeError("sensor died")

    with pytest.raises(RuntimeError):
        st.insert_events(db, Boom())
    assert st.count_events(db) == 0
    out = st.insert_events(db, [syn(port=p) for p in range(1, 6)])
    assert [e.dst_port for e in out] == [1, 2, 3, 4, 5]  # input order preserved
    assert [e.id for e in out] == sorted(e.id for e in out)
    assert st.count_events(db) == 5


def test_sql_injection_strings_are_stored_as_data(db):
    nasty = "x'; DROP TABLE events; --"
    e = st.insert_event(db, auth(nasty))
    assert st.get_event(db, e.id).username == nasty
    assert st.count_events(db, username=nasty) == 1
    assert st.list_events(db, src_ip="1.1.1.1' OR '1'='1") == []
    assert st.count_events(db) == 1


def test_list_events_filters_order_limit(db):
    st.insert_events(db, [syn(ip="10.0.0.1", at=ago(30)), syn(ip="10.0.0.2", at=ago(20)),
                          dns(ip="10.0.0.1", at=ago(10)), auth(at=ago(5))])
    assert [e.id for e in st.list_events(db)] == [4, 3, 2, 1]  # newest first
    assert len(st.list_events(db, type="network_connection")) == 2
    assert [e.id for e in st.list_events(db, src_ip="10.0.0.1")] == [3, 1]
    assert [e.id for e in st.list_events(db, since=ago(15), until=ago(7))] == [3]
    assert len(st.list_events(db, limit=2)) == 2
    assert [e.id for e in st.list_events(db, limit=2, offset=2)] == [2, 1]
    assert len(st.list_events(db, limit=10**9)) == 4  # clamped, no error
    assert len(st.list_events(db, limit=-5)) == 1  # clamped to 1


def test_get_events_by_ids_skips_missing_and_orders_by_time(db):
    st.insert_events(db, [syn(at=ago(3)), syn(at=ago(2)), syn(at=ago(1))])
    got = st.get_events_by_ids(db, [3, 1, 99, 1])
    assert [e.id for e in got] == [1, 3]


# ---- window / aggregate queries ----------------------------------------------
def test_events_in_window_bounds_and_order(db):
    st.insert_events(db, [syn(at=ago(40)), syn(at=ago(30)), syn(at=ago(10)), syn(at=NOW)])
    got = st.events_in_window(db, since=ago(30))
    assert [e.id for e in got] == [2, 3, 4]  # oldest first, 'since' inclusive
    assert [e.id for e in st.events_in_window(db, since=ago(30), until=ago(10))] == [2, 3]  # 'until' inclusive


def test_window_filters_by_type_ip_username(db):
    st.insert_events(db, [syn(ip="10.0.0.1"), syn(ip="10.0.0.2"), dns(ip="10.0.0.1"),
                          auth("alice", ip="10.0.0.1"), auth("bob", ip="10.0.0.1")])
    w = ago(60)
    assert len(st.events_in_window(db, since=w, type="network_connection")) == 2
    assert len(st.events_in_window(db, since=w, src_ip="10.0.0.1")) == 4
    assert len(st.events_in_window(db, since=w, type="auth_failure", username="alice")) == 1
    assert st.count_events(db, since=w, src_ip="10.0.0.1", type="auth_failure") == 2


def test_port_scan_style_distinct_count(db):
    st.insert_events(db, [syn(ip="10.0.0.5", port=p, at=ago(10)) for p in range(1, 26)]
                     + [syn(ip="10.0.0.5", port=5, at=ago(5))]  # repeat of port 5: must not add a distinct port
                     + [syn(ip="10.0.0.6", port=p, at=ago(10)) for p in range(1, 4)]
                     + [syn(ip="10.0.0.5", port=9999, at=ago(300))])  # outside window
    n = st.count_distinct(db, "dst_port", since=ago(30), type="network_connection", src_ip="10.0.0.5")
    assert n == 25
    assert st.count_distinct(db, "dst_port", since=ago(30), src_ip="10.0.0.6") == 3
    assert st.count_distinct(db, "dst_port", since=ago(30), src_ip="10.9.9.9") == 0


def test_count_distinct_rejects_unknown_field(db):
    with pytest.raises(ValueError):
        st.count_distinct(db, "id) FROM events; DROP TABLE events; --", since=ago(10))
    with pytest.raises(ValueError):
        st.count_distinct(db, "details", since=ago(10))


def test_auth_failures_by_username_across_ips(db):
    st.insert_events(db, [auth("admin", ip=f"10.0.0.{i}", at=ago(i)) for i in range(1, 6)])
    assert st.count_events(db, since=ago(300), type="auth_failure", username="admin") == 5
    assert st.count_distinct(db, "src_ip", since=ago(300), username="admin") == 5


def test_window_row_cap(db):
    st.insert_events(db, [syn(port=p) for p in range(1, 30)])
    assert len(st.events_in_window(db, since=ago(60), limit=10)) == 10


# ---- alerts ------------------------------------------------------------------
def test_insert_and_get_alert(db):
    a = st.insert_alert(db, alert(), now=NOW)
    assert (a.id, a.status, a.count) == (1, "new", 3)
    assert a.explanation["threshold"] == 20 and a.evidence_event_ids == [1, 2, 3]
    assert st.get_alert(db, 1).model_dump() == a.model_dump()
    assert st.get_alert(db, 42) is None


def test_upsert_creates_then_dedups_within_cooldown(db):
    a1, created1 = st.upsert_alert(db, alert(ids=(1, 2)), cooldown_seconds=300, now=NOW)
    a2, created2 = st.upsert_alert(db, alert(ids=(2, 3, 4)), cooldown_seconds=300, now=NOW + timedelta(seconds=60))
    assert created1 and not created2 and a1.id == a2.id
    assert a2.count == 4 and a2.evidence_event_ids == [1, 2, 3, 4]
    assert a2.updated_at > a2.created_at
    assert len(st.list_alerts(db)) == 1


def test_upsert_same_evidence_changes_nothing(db):
    a1, _ = st.upsert_alert(db, alert(ids=(1, 2)), cooldown_seconds=300, now=NOW)
    a2, created = st.upsert_alert(db, alert(ids=(1, 2)), cooldown_seconds=300, now=NOW + timedelta(seconds=30))
    assert not created and a2.count == 2 and a2.updated_at == a1.updated_at


def test_upsert_without_evidence_increments_count(db):
    st.upsert_alert(db, alert(ids=()), cooldown_seconds=300, now=NOW)
    a, created = st.upsert_alert(db, alert(ids=()), cooldown_seconds=300, now=NOW + timedelta(seconds=5))
    assert not created and a.count == 2


def test_upsert_after_cooldown_creates_new_alert(db):
    st.upsert_alert(db, alert(ids=(1,)), cooldown_seconds=60, now=NOW)
    a, created = st.upsert_alert(db, alert(ids=(2,)), cooldown_seconds=60, now=NOW + timedelta(seconds=61))
    assert created and a.id == 2


def test_upsert_different_rule_or_ip_is_separate(db):
    st.upsert_alert(db, alert(rule="port_scan", ip="10.0.0.5"), cooldown_seconds=300, now=NOW)
    _, c1 = st.upsert_alert(db, alert(rule="dns_anomaly", ip="10.0.0.5"), cooldown_seconds=300, now=NOW)
    _, c2 = st.upsert_alert(db, alert(rule="port_scan", ip="10.0.0.6"), cooldown_seconds=300, now=NOW)
    assert c1 and c2 and len(st.list_alerts(db)) == 3


def test_upsert_with_no_ip_dedups_on_null(db):
    a = alert(ip=None, ids=(1,))
    st.upsert_alert(db, a, cooldown_seconds=300, now=NOW)
    _, created = st.upsert_alert(db, alert(ip=None, ids=(2,)), cooldown_seconds=300, now=NOW)
    assert not created


def test_severity_only_escalates(db):
    st.upsert_alert(db, alert(ids=(1,), severity="medium"), cooldown_seconds=300, now=NOW)
    a, _ = st.upsert_alert(db, alert(ids=(2,), severity="critical"), cooldown_seconds=300, now=NOW)
    assert a.severity == "critical"
    a, _ = st.upsert_alert(db, alert(ids=(3,), severity="low"), cooldown_seconds=300, now=NOW)
    assert a.severity == "critical"


def test_upsert_escalates_severity_and_details_with_same_evidence(db):
    a1, created1 = st.upsert_alert(
        db,
        alert(ids=(1, 2), severity="low"),
        cooldown_seconds=300,
        now=NOW,
    )
    assert created1 and a1.severity == "low"

    # Re-evaluating same evidence with escalated severity and new explanation
    a2, created2 = st.upsert_alert(
        db,
        alert(ids=(1, 2), severity="critical"),
        cooldown_seconds=300,
        now=NOW + timedelta(seconds=10),
    )
    assert not created2 and a2.id == a1.id
    assert a2.severity == "critical"
    assert a2.count == 2  # count must not increment since no new evidence was added
    assert a2.updated_at > a1.updated_at

    # De-escalation attempt with same evidence should not change severity or updated_at
    a3, created3 = st.upsert_alert(
        db,
        alert(ids=(1, 2), severity="medium"),
        cooldown_seconds=300,
        now=NOW + timedelta(seconds=20),
    )
    assert not created3 and a3.severity == "critical"
    assert a3.count == 2
    assert a3.updated_at == a2.updated_at


def test_closed_alerts_do_not_absorb_new_activity(db):
    a, _ = st.upsert_alert(db, alert(ids=(1,)), cooldown_seconds=300, now=NOW)
    st.update_alert_status(db, a.id, AlertUpdate(status="resolved"), now=NOW)
    b, created = st.upsert_alert(db, alert(ids=(2,)), cooldown_seconds=300, now=NOW)
    assert created and b.id != a.id
    st.update_alert_status(db, b.id, AlertUpdate(status="investigating"), now=NOW)
    c, created = st.upsert_alert(db, alert(ids=(3,)), cooldown_seconds=300, now=NOW)
    assert not created and c.id == b.id and c.status == "investigating"  # open alerts keep absorbing


def test_evidence_list_is_capped_but_count_is_true(db):
    st.upsert_alert(db, alert(ids=range(1, 151)), cooldown_seconds=300, now=NOW)
    a, _ = st.upsert_alert(db, alert(ids=range(151, 301)), cooldown_seconds=300, now=NOW)
    assert a.count == 300 and len(a.evidence_event_ids) == 200 and a.evidence_event_ids[-1] == 300


def test_upsert_with_sliding_window_over_cap_does_not_inflate_count(db):
    # Initial alert filled to MAX_EVIDENCE_IDS (200 events)
    a1, created = st.upsert_alert(db, alert(ids=range(1, 201)), cooldown_seconds=300, now=NOW)
    assert created and a1.count == 200

    # Sliding window detector fires with event 201 added (window still has 1..201)
    a2, _ = st.upsert_alert(db, alert(ids=range(1, 202)), cooldown_seconds=300, now=NOW + timedelta(seconds=1))
    assert a2.count == 201
    assert a2.evidence_event_ids == list(range(2, 202))

    # Event 202 added: window has 1..202
    a3, _ = st.upsert_alert(db, alert(ids=range(1, 203)), cooldown_seconds=300, now=NOW + timedelta(seconds=2))
    assert a3.count == 202
    assert a3.evidence_event_ids == list(range(3, 203))

    # Event 203 added: window has 1..203
    a4, _ = st.upsert_alert(db, alert(ids=range(1, 204)), cooldown_seconds=300, now=NOW + timedelta(seconds=3))
    assert a4.count == 203
    assert a4.evidence_event_ids == list(range(4, 204))

    # Same window repeated with no new events: must not increment count or alter ordering
    a5, created = st.upsert_alert(db, alert(ids=range(1, 204)), cooldown_seconds=300, now=NOW + timedelta(seconds=4))
    assert not created
    assert a5.count == 203
    assert a5.evidence_event_ids == list(range(4, 204))


def test_update_status_persists_and_missing_returns_none(db):
    a = st.insert_alert(db, alert(), now=NOW)
    out = st.update_alert_status(db, a.id, AlertUpdate(status="false_positive"), now=NOW + timedelta(minutes=1))
    assert out.status == "false_positive" and out.updated_at > a.updated_at
    assert st.get_alert(db, a.id).status == "false_positive"
    assert st.update_alert_status(db, 999, AlertUpdate(status="resolved")) is None


def test_list_alerts_filters_and_order(db):
    st.insert_alert(db, alert(rule="port_scan", severity="low"), now=ago(30))
    st.insert_alert(db, alert(rule="dns_anomaly", severity="high", ip="10.0.0.7"), now=ago(20))
    b = st.insert_alert(db, alert(rule="port_scan", severity="high"), now=ago(10))
    st.update_alert_status(db, b.id, AlertUpdate(status="investigating"))
    assert [a.id for a in st.list_alerts(db)] == [3, 2, 1]
    assert [a.id for a in st.list_alerts(db, severity="high")] == [3, 2]
    assert [a.id for a in st.list_alerts(db, rule="port_scan")] == [3, 1]
    assert [a.id for a in st.list_alerts(db, status="investigating")] == [3]
    assert [a.id for a in st.list_alerts(db, src_ip="10.0.0.7")] == [2]
    assert [a.id for a in st.list_alerts(db, limit=1, offset=1)] == [2]
    with pytest.raises(ValueError):
        st.list_alerts(db, severity="urgent")
    with pytest.raises(ValueError):
        st.list_alerts(db, status="closed")


def test_alert_evidence_returns_events_and_tolerates_purged_ones(db):
    old = st.insert_event(db, syn(at=ago(days=40)))
    new = st.insert_event(db, syn(at=ago(5)))
    a = st.insert_alert(db, alert(ids=(old.id, new.id)), now=NOW)
    assert [e.id for e in st.get_alert_evidence(db, a.id)] == [old.id, new.id]
    st.purge_old_events(db, 30, now=NOW)
    assert [e.id for e in st.get_alert_evidence(db, a.id)] == [new.id]
    assert st.get_alert_evidence(db, 999) == []


def test_event_ids_are_never_reused_after_purge(db):
    st.insert_event(db, syn(at=ago(days=40)))
    st.purge_old_events(db, 30, now=NOW)
    assert st.insert_event(db, syn()).id == 2  # AUTOINCREMENT: old alert evidence can't point at new events


# ---- stats -------------------------------------------------------------------
def test_stats(db):
    st.insert_events(db, [syn(ip="10.0.0.5", at=ago(60))] * 3 + [syn(ip="10.0.0.6", at=ago(60))]
                     + [syn(ip="10.0.0.7", at=ago(days=3))])
    a = st.insert_alert(db, alert(severity="high"), now=NOW)
    st.insert_alert(db, alert(rule="dns_anomaly", severity="low"), now=NOW)
    st.update_alert_status(db, a.id, AlertUpdate(status="resolved"))
    s = st.stats(db, now=NOW)
    assert (s.events_total, s.events_today) == (5, 4)
    assert s.alerts_total == 2 and s.open_alerts == 1
    assert s.alerts_by_severity == {"low": 1, "medium": 0, "high": 1, "critical": 0}
    assert s.alerts_by_status == {"new": 1, "investigating": 0, "resolved": 1, "false_positive": 0}
    assert [(t.src_ip, t.count) for t in s.top_source_ips] == [("10.0.0.5", 3), ("10.0.0.6", 1)]


def test_stats_on_empty_database(db):
    s = st.stats(db, now=NOW)
    assert s.events_total == 0 and s.top_source_ips == [] and s.open_alerts == 0
    assert set(s.alerts_by_severity) == {"low", "medium", "high", "critical"}


# ---- retention ---------------------------------------------------------------
def test_purge_old_events(db):
    st.insert_events(db, [syn(at=ago(days=40)), syn(at=ago(days=31)), syn(at=ago(days=29)), syn(at=ago(10))])
    assert st.purge_old_events(db, 30, now=NOW) == 2
    assert st.count_events(db) == 2
    assert st.purge_old_events(db, 30, now=NOW) == 0


def test_purge_runs_in_chunks(db):
    st.insert_events(db, [syn(at=ago(days=60, seconds=i)) for i in range(25)])
    assert st.purge_old_events(db, 30, now=NOW, chunk_size=10) == 25
    assert st.count_events(db) == 0


def test_purge_rejects_nonpositive_retention(db):
    for bad in (0, -1):
        with pytest.raises(ValueError):
            st.purge_old_events(db, bad)


def test_purge_rejects_nonpositive_chunk_size(db):
    for bad in (0, -1, -50):
        with pytest.raises(ValueError, match="chunk_size must be positive"):
            st.purge_old_events(db, 30, chunk_size=bad)


def test_purge_keeps_alerts(db):
    st.insert_alert(db, alert(), now=ago(days=90))
    st.purge_old_events(db, 1, now=NOW)
    assert len(st.list_alerts(db)) == 1
