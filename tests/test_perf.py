"""Done-when check: window queries stay fast with 100k events.

Run with ``pytest tests/test_perf.py -s`` to see the timings.
"""

import random
import time
from datetime import timedelta

import pytest

from app import storage as st
from app.models import EventIn
from tests.conftest import NOW

N_EVENTS = 100_000
BUDGET_MS = 50  # per indexed window query; typical results are far below this


@pytest.fixture(scope="module")
def big_db(tmp_path_factory):
    from app.db import open_database

    db = open_database(tmp_path_factory.mktemp("perf") / "perf.db")
    rng = random.Random(42)
    ips = [f"10.1.{i // 250}.{i % 250 + 1}" for i in range(500)]
    batch, t0 = [], time.perf_counter()
    for i in range(N_EVENTS):
        kind = i % 4
        at = NOW - timedelta(seconds=rng.random() * 7 * 86400)  # spread over 7 days
        ip = rng.choice(ips)
        if kind == 0:
            batch.append(EventIn(type="network_connection", timestamp=at, source="s", src_ip=ip,
                                 dst_ip="10.0.0.1", dst_port=rng.randint(1, 65535)))
        elif kind == 1:
            batch.append(EventIn(type="dns_query", timestamp=at, source="s", src_ip=ip,
                                 dns_name=f"h{rng.randint(0, 9999)}.example.com"))
        elif kind == 2:
            batch.append(EventIn(type="auth_failure", timestamp=at, source="app", src_ip=ip,
                                 username=f"user{rng.randint(0, 200)}"))
        else:
            batch.append(EventIn(type="http_request", timestamp=at, source="app", src_ip=ip,
                                 http_method="GET", http_path=f"/p/{rng.randint(0, 500)}", http_status=200))
        if len(batch) == 500:
            st.insert_events(db, batch)
            batch = []
    db.perf_load_seconds = time.perf_counter() - t0
    # a live port scan right now: one attacker, 40 distinct ports, last 20 seconds
    st.insert_events(db, [EventIn(type="network_connection", timestamp=NOW - timedelta(seconds=p % 20),
                                  source="s", src_ip="192.168.9.9", dst_ip="10.0.0.1", dst_port=1000 + p)
                          for p in range(40)])
    yield db
    db.close()


@pytest.fixture
def big_db_copy(big_db, tmp_path):
    """A private copy of the big database for tests that INSERT or DELETE.

    ``big_db`` is built once per module (loading 100k events is slow) and shared, so tests
    that change it would make every other test's numbers depend on the order they ran in.
    """
    import shutil

    from app.db import open_database

    conn = big_db.connection()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # fold the WAL into the main file first
    source = conn.execute("PRAGMA database_list").fetchone()[2]
    target = tmp_path / "perf-copy.db"
    shutil.copyfile(source, target)
    db = open_database(target)
    yield db
    db.close()


def timed(fn, repeat=20):
    fn()  # warm the page cache
    samples = []
    for _ in range(repeat):
        t = time.perf_counter()
        out = fn()
        samples.append((time.perf_counter() - t) * 1000)
    samples.sort()
    return out, samples[len(samples) // 2], samples[-1]


def plan(db, sql, params=()):
    return " | ".join(r[3] for r in db.connection().execute("EXPLAIN QUERY PLAN " + sql, params))


def test_row_count(big_db):
    assert st.count_events(big_db) == N_EVENTS + 40
    print(f"\n  bulk insert of {N_EVENTS:,} events (incl. validation): {big_db.perf_load_seconds:.1f}s")


def test_port_scan_window_queries_are_fast(big_db):
    since = NOW - timedelta(seconds=30)
    n, med, worst = timed(lambda: st.count_distinct(big_db, "dst_port", since=since, type="network_connection", src_ip="192.168.9.9"))
    print(f"\n  count_distinct(dst_port, 30s, ip)      median {med:.2f} ms  worst {worst:.2f} ms  -> {n}")
    assert n == 40 and worst < BUDGET_MS
    rows, med, worst = timed(lambda: st.events_in_window(big_db, since=since, type="network_connection", src_ip="192.168.9.9"))
    print(f"  events_in_window(30s, ip, type)        median {med:.2f} ms  worst {worst:.2f} ms  -> {len(rows)} rows")
    assert len(rows) == 40 and worst < BUDGET_MS


def test_auth_and_dns_window_queries_are_fast(big_db):
    since = NOW - timedelta(minutes=5)
    _, med, worst = timed(lambda: st.count_events(big_db, since=since, type="auth_failure", username="user7"))
    print(f"\n  count_events(auth_failure, user, 5m)   median {med:.2f} ms  worst {worst:.2f} ms")
    assert worst < BUDGET_MS
    _, med, worst = timed(lambda: st.count_events(big_db, since=since, type="auth_failure", src_ip="10.1.0.5"))
    print(f"  count_events(auth_failure, ip, 5m)     median {med:.2f} ms  worst {worst:.2f} ms")
    assert worst < BUDGET_MS
    _, med, worst = timed(lambda: st.events_in_window(big_db, since=since, type="dns_query", src_ip="10.1.0.5"))
    print(f"  events_in_window(dns, ip, 5m)          median {med:.2f} ms  worst {worst:.2f} ms")
    assert worst < BUDGET_MS


def test_dashboard_queries_are_fast(big_db):
    _, med, worst = timed(lambda: st.list_events(big_db, limit=100))
    print(f"\n  list_events(newest 100)                median {med:.2f} ms  worst {worst:.2f} ms")
    assert worst < BUDGET_MS
    _, med, worst = timed(lambda: st.list_events(big_db, type="dns_query", limit=100))
    print(f"  list_events(type=dns_query, 100)       median {med:.2f} ms  worst {worst:.2f} ms")
    assert worst < BUDGET_MS
    _, med, worst = timed(lambda: st.list_events(big_db, src_ip="10.1.0.5", limit=100))
    print(f"  list_events(src_ip, 100)               median {med:.2f} ms  worst {worst:.2f} ms")
    assert worst < BUDGET_MS
    s, med, worst = timed(lambda: st.stats(big_db, now=NOW), repeat=10)
    print(f"  stats()                                median {med:.2f} ms  worst {worst:.2f} ms")
    assert s.events_total == N_EVENTS + 40 and worst < 250


def test_indexes_are_used_not_table_scans(big_db):
    ts = "2026-10-01T11:59:30.000000Z"
    cases = {
        "port scan window": ("SELECT dst_port FROM events WHERE type=? AND src_ip=? AND timestamp>=?",
                             ("network_connection", "10.1.0.5", ts)),
        "window by time":   ("SELECT id FROM events WHERE timestamp>=? ORDER BY timestamp", (ts,)),
        "window by type":   ("SELECT id FROM events WHERE type=? AND timestamp>=?", ("dns_query", ts)),
        "auth by username": ("SELECT id FROM events WHERE username=? AND timestamp>=?", ("user7", ts)),
        "newest first":     ("SELECT id FROM events ORDER BY timestamp DESC, id DESC LIMIT 100", ()),
    }
    for name, (sql, params) in cases.items():
        p = plan(big_db, sql, params)
        print(f"\n  {name:18s} -> {p}")
        # every query must go through one of our idx_events_* indexes (no bare table scan)
        assert "idx_events_" in p, f"{name}: {p}"


def test_flood_window_worst_case(big_db_copy):
    """A flood: 20k events from one IP in the same 30 s. Rules should use count_* here, not load rows."""
    st.insert_events(big_db_copy, [EventIn(type="network_connection", timestamp=NOW - timedelta(seconds=i % 30),
                                      source="s", src_ip="172.16.0.99", dst_ip="10.0.0.1", dst_port=1 + i % 60000)
                              for i in range(20_000)])
    since = NOW - timedelta(seconds=30)
    n, med, worst = timed(lambda: st.count_distinct(big_db_copy, "dst_port", since=since, src_ip="172.16.0.99"), repeat=5)
    print(f"\n  FLOOD count_distinct over 20k rows     median {med:.1f} ms  worst {worst:.1f} ms  -> {n}")
    assert worst < 250
    rows, med, worst = timed(lambda: st.events_in_window(big_db_copy, since=since, src_ip="172.16.0.99"), repeat=3)
    print(f"  FLOOD events_in_window loading {len(rows):,} rows median {med:.0f} ms  worst {worst:.0f} ms")


def test_retention_on_big_table(big_db_copy):
    t = time.perf_counter()
    removed = st.purge_old_events(big_db_copy, 3, now=NOW)
    ms = (time.perf_counter() - t) * 1000
    remaining = st.count_events(big_db_copy)
    print(f"\n  purge_old_events(3 days) removed {removed:,} rows in {ms:.0f} ms; {remaining:,} remain")
    assert removed > 0 and remaining > 0
    assert st.count_events(big_db_copy, until=NOW - timedelta(days=3, seconds=1)) == 0
