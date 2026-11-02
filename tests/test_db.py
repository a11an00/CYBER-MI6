import sqlite3
import threading

import pytest

from backend.db import Database, from_db_ts, open_database, to_db_ts
from tests.conftest import NOW


def test_wal_mode_and_pragmas(db):
    conn = db.connection()
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1


def test_tables_and_required_indexes_exist(db):
    conn = db.connection()
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"events", "alerts"} <= tables
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"idx_events_timestamp", "idx_events_type_ts", "idx_events_src_type_ts"} <= indexes


def test_alert_filter_indexes_eliminate_temp_btree_sort(db):
    conn = db.connection()
    queries = [
        ("SELECT id FROM alerts WHERE severity = ? ORDER BY created_at DESC, id DESC LIMIT 10", ("high",)),
        ("SELECT id FROM alerts WHERE status = ? ORDER BY created_at DESC, id DESC LIMIT 10", ("new",)),
    ]
    for sql, params in queries:
        plan = " | ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + sql, params))
        assert "USE TEMP B-TREE FOR ORDER BY" not in plan
        assert "idx_alerts_" in plan


def test_init_schema_is_idempotent_and_keeps_data(tmp_path):
    path = tmp_path / "x.db"
    db1 = open_database(path)
    db1.connection().execute("INSERT INTO alerts (created_at, updated_at, rule, severity, title) "
                             "VALUES ('a','a','r','low','t')")
    db1.close()
    db2 = open_database(path)  # second init must not wipe or fail
    assert db2.connection().execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    db2.close()


def test_parent_directory_is_created(tmp_path):
    db = open_database(tmp_path / "data" / "nested" / "cybermi6.db")
    assert (tmp_path / "data" / "nested" / "cybermi6.db").exists()
    db.close()


def test_memory_database_rejected(tmp_path):
    with pytest.raises(ValueError):
        Database(":memory:")


def test_newer_schema_version_refused(tmp_path):
    path = tmp_path / "x.db"
    open_database(path).close()
    raw = sqlite3.connect(path)
    raw.execute("PRAGMA user_version = 99")
    raw.commit()
    raw.close()
    with pytest.raises(RuntimeError, match="newer"):
        open_database(path)


def test_timestamp_roundtrip_and_ordering():
    assert from_db_ts(to_db_ts(NOW)) == NOW
    earlier = to_db_ts(NOW.replace(microsecond=5))
    later = to_db_ts(NOW.replace(microsecond=6))
    assert earlier < later and len(earlier) == len(later) == 27  # fixed width => text order == time order


def test_transaction_commits_and_rolls_back(db):
    with db.transaction() as conn:
        conn.execute("INSERT INTO alerts (created_at, updated_at, rule, severity, title) VALUES ('a','a','r','low','t')")
    with pytest.raises(RuntimeError):
        with db.transaction() as conn:
            conn.execute("INSERT INTO alerts (created_at, updated_at, rule, severity, title) VALUES ('b','b','r','low','t')")
            raise RuntimeError("boom")
    assert db.connection().execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1


def test_nested_transaction_joins_outer_and_rolls_back_together(db):
    with pytest.raises(RuntimeError):
        with db.transaction() as conn:
            conn.execute("INSERT INTO alerts (created_at, updated_at, rule, severity, title) VALUES ('a','a','r','low','t')")
            with db.transaction() as inner:
                assert inner is conn
                inner.execute("INSERT INTO alerts (created_at, updated_at, rule, severity, title) VALUES ('b','b','r','low','t')")
            raise RuntimeError("boom")
    assert db.connection().execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0


def test_write_inside_read_transaction_is_rejected(db):
    with db.transaction(write=False) as conn:
        with pytest.raises(RuntimeError, match="cannot start a write transaction inside an active read transaction"):
            with db.transaction(write=True):
                pass
    # Verify transaction depth and connection are cleaned up properly
    assert db._local.depth == 0


def test_read_inside_write_transaction_is_allowed(db):
    with db.transaction(write=True) as conn:
        conn.execute("INSERT INTO alerts (created_at, updated_at, rule, severity, title) VALUES ('a','a','r','low','t')")
        with db.transaction(write=False) as inner:
            assert inner is conn
            assert inner.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    assert db.connection().execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1


def test_each_thread_gets_its_own_connection(db):
    seen = {}

    def grab():
        seen["other"] = db.connection()

    t = threading.Thread(target=grab)
    t.start()
    t.join()
    assert seen["other"] is not db.connection()


def test_connections_cleaned_up_when_threads_exit(db):
    import gc

    db.connection()
    initial_count = len(db._all)

    def run_workers():
        for _ in range(10):
            t = threading.Thread(target=lambda: db.connection())
            t.start()
            t.join()

    run_workers()
    gc.collect()
    assert len(db._all) == initial_count
