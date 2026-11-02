"""SQLite connection handling and schema for CYBER-MI6.

Concurrency model
-----------------
* One connection per thread (``threading.local``). Connections are never shared
  between threads, so FastAPI's threadpool, the detection engine and the
  retention job can all use the same ``Database`` object safely.
* WAL mode: readers never block the writer and the writer never blocks readers.
* Writers are serialised with ``BEGIN IMMEDIATE`` plus a busy timeout, so two
  threads that write at once wait for each other instead of failing with
  "database is locked".
* ``transaction()`` is re-entrant: a storage function called inside another
  transaction joins it instead of starting a new one.

``:memory:`` databases are not supported (each thread would get its own empty
database). Use a temporary file in tests.
"""

import sqlite3
import threading
import weakref
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = 1
DEFAULT_BUSY_TIMEOUT_MS = 5000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL,   -- event time, UTC, fixed-width ISO 8601 (see to_db_ts)
    received_at TEXT    NOT NULL,   -- when the API stored it
    source      TEXT    NOT NULL,
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT,
    dst_port    INTEGER,
    protocol    TEXT,
    dns_name    TEXT,
    username    TEXT,
    http_method TEXT,
    http_path   TEXT,
    http_status INTEGER,
    user_agent  TEXT,
    details     TEXT                -- JSON object or NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp    ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type_ts      ON events (type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_type_ts  ON events (src_ip, type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_username_ts  ON events (username, timestamp)
    WHERE username IS NOT NULL;

CREATE TABLE IF NOT EXISTS alerts (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at         TEXT    NOT NULL,
    updated_at         TEXT    NOT NULL,
    rule               TEXT    NOT NULL,
    severity           TEXT    NOT NULL,
    title              TEXT    NOT NULL,
    status             TEXT    NOT NULL DEFAULT 'new',
    src_ip             TEXT,
    evidence_event_ids TEXT    NOT NULL DEFAULT '[]',  -- JSON array of event ids
    count              INTEGER NOT NULL DEFAULT 1,
    explanation        TEXT    NOT NULL DEFAULT '{}'   -- JSON object: rule, thresholds, numbers
);

CREATE INDEX IF NOT EXISTS idx_alerts_dedup      ON alerts (rule, src_ip, updated_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts (status, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts (severity, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at);
"""


# --------------------------------------------------------------------------
# Timestamp helpers: one fixed-width UTC format so text comparison == time order
# --------------------------------------------------------------------------
_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def to_db_ts(dt: datetime) -> str:
    """datetime -> 'YYYY-MM-DDTHH:MM:SS.ffffffZ' (UTC). Naive datetimes are treated as UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(_TS_FORMAT)


def from_db_ts(text: str) -> datetime:
    # fromisoformat handles the trailing 'Z' on Python 3.11+ (our minimum) and is ~15x faster
    # than strptime, which matters when a rule loads thousands of rows.
    return datetime.fromisoformat(text)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
class Database:
    def __init__(self, path: str | Path, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS):
        if str(path) == ":memory:":
            raise ValueError("':memory:' is not supported; use a file path (a temp file in tests)")
        self.path = Path(path)
        self.busy_timeout_ms = busy_timeout_ms
        self._local = threading.local()
        self._all: set[sqlite3.Connection] = set()
        self._all_lock = threading.Lock()

    def _cleanup_conn(self, conn: sqlite3.Connection) -> None:
        with self._all_lock:
            self._all.discard(conn)
        try:
            conn.close()
        except sqlite3.Error:
            pass

    # -- connections ---------------------------------------------------------
    def connection(self) -> sqlite3.Connection:
        """The calling thread's connection (created on first use)."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                self.path,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level=None,  # autocommit; transactions are explicit
                check_same_thread=False,  # only so close() can run from another thread
            )
            conn.row_factory = sqlite3.Row
            conn.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_ms)}")
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA synchronous = NORMAL")  # safe with WAL, much faster than FULL
            conn.execute("PRAGMA temp_store = MEMORY")
            self._local.conn = conn
            self._local.depth = 0
            self._local.is_write = False
            with self._all_lock:
                self._all.add(conn)
            try:
                weakref.finalize(threading.current_thread(), self._cleanup_conn, conn)
            except (TypeError, ValueError):
                pass
        return conn

    @contextmanager
    def transaction(self, write: bool = True) -> Iterator[sqlite3.Connection]:
        """Run a block atomically. Re-entrant: nested calls join the outer transaction.

        ``write=True`` takes the write lock up front (BEGIN IMMEDIATE) so a
        read-then-write sequence can't be interleaved with another writer.
        """
        conn = self.connection()
        if self._local.depth > 0:
            if write and not self._local.is_write:
                raise RuntimeError("cannot start a write transaction inside an active read transaction")
            self._local.depth += 1
            try:
                yield conn
            finally:
                self._local.depth -= 1
            return
        conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        self._local.depth = 1
        self._local.is_write = write
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")
        finally:
            self._local.depth = 0
            self._local.is_write = False

    # -- schema --------------------------------------------------------------
    def init_schema(self) -> None:
        """Create tables/indexes and switch to WAL mode. Safe to call repeatedly."""
        conn = self.connection()
        mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            raise RuntimeError(f"could not enable WAL mode (got {mode!r})")
        with self.transaction():
            # executescript() would COMMIT our transaction, so run statements one by one
            # (_SCHEMA must therefore not contain ';' inside comments or strings)
            for statement in _split_statements(_SCHEMA):
                conn.execute(statement)
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema v{version} is newer than this code (v{SCHEMA_VERSION})"
                )

    def close(self) -> None:
        """Close every connection opened through this object (call at shutdown / in tests)."""
        with self._all_lock:
            conns, self._all = list(self._all), set()
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._local = threading.local()


def _split_statements(script: str) -> list[str]:
    return [s.strip() for s in script.split(";") if s.strip()]


def open_database(path: str | Path, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS) -> Database:
    """Create the Database, make sure the schema exists, and return it."""
    db = Database(path, busy_timeout_ms)
    db.init_schema()
    return db
