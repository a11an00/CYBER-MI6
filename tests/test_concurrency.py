"""API threads, the detection engine and the WebSocket broadcaster all touch the DB at once."""

import threading
from datetime import timedelta

from app import storage as st
from tests.conftest import NOW, alert, ago, syn


def run_threads(targets):
    errors: list[BaseException] = []

    def wrap(fn):
        def inner():
            try:
                fn()
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)
        return inner

    threads = [threading.Thread(target=wrap(t)) for t in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not any(t.is_alive() for t in threads), "a thread hung (deadlock?)"
    return errors


def test_parallel_writers_and_readers_no_lock_errors(db):
    writers, per_writer = 8, 150

    def writer(w):
        def go():
            for i in range(per_writer):
                st.insert_event(db, syn(ip=f"10.0.{w}.{i % 250 + 1}", port=i % 65000 + 1, at=ago(i % 50)))
        return go

    stop = threading.Event()
    reads = []

    def reader():
        while not stop.is_set():
            st.events_in_window(db, since=ago(60))
            st.stats(db, now=NOW)
            st.list_events(db, limit=50)
            reads.append(1)

    reader_threads = [threading.Thread(target=reader) for _ in range(3)]
    for t in reader_threads:
        t.start()
    errors = run_threads([writer(w) for w in range(writers)])
    stop.set()
    for t in reader_threads:
        t.join(timeout=30)

    assert errors == []
    assert st.count_events(db) == writers * per_writer
    assert len(reads) > 0  # readers really ran during the writes


def test_concurrent_upserts_create_exactly_one_alert(db):
    results = []

    def fire(i):
        def go():
            results.append(st.upsert_alert(db, alert(ids=(i,)), cooldown_seconds=300, now=NOW))
        return go

    errors = run_threads([fire(i) for i in range(1, 21)])
    assert errors == []
    assert sum(1 for _, created in results if created) == 1
    alerts = st.list_alerts(db)
    assert len(alerts) == 1 and alerts[0].count == 20
    assert sorted(alerts[0].evidence_event_ids) == list(range(1, 21))


def test_writes_during_purge_are_not_lost(db):
    st.insert_events(db, [syn(port=1 + i % 60000, at=ago(days=40, seconds=i)) for i in range(3000)])
    fresh = []

    def purger():
        st.purge_old_events(db, 30, now=NOW, chunk_size=200)

    def inserter():
        for i in range(200):
            fresh.append(st.insert_event(db, syn(port=1 + i, at=ago(i % 30))).id)

    assert run_threads([purger, inserter]) == []
    assert st.count_events(db) == 200
    assert len(st.get_events_by_ids(db, fresh)) == 200


def test_status_update_races_with_dedup(db):
    a, _ = st.upsert_alert(db, alert(ids=(1,)), cooldown_seconds=300, now=NOW)
    from app.models import AlertUpdate

    def resolve():
        st.update_alert_status(db, a.id, AlertUpdate(status="resolved"), now=NOW)

    def refire():
        for i in range(2, 30):
            st.upsert_alert(db, alert(ids=(i,)), cooldown_seconds=300, now=NOW + timedelta(seconds=i))

    assert run_threads([resolve, refire]) == []
    # whichever order the threads ran in, nothing is lost and no alert is double-counted
    alerts = st.list_alerts(db)
    assert sum(x.count for x in alerts) == 29
    assert all(x.status in {"new", "resolved"} for x in alerts)
