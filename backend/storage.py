"""Storage contract for CYBER-MI6 - the only module that writes SQL.

Every function takes the ``Database`` first, is synchronous, and is safe to call
from any thread (see db.py). Inside FastAPI use plain ``def`` endpoints, or wrap
calls with ``run_in_threadpool`` from ``async def`` endpoints.

Contract summary
----------------
Events   insert_event, insert_events, get_event, get_events_by_ids, list_events
Windows  events_in_window, count_events, count_distinct
Alerts   insert_alert, upsert_alert, get_alert, list_alerts, update_alert_status,
         get_alert_evidence
Dash     stats
Upkeep   purge_old_events

All times are UTC. Arguments named ``since`` / ``until`` / ``now`` are datetimes
(naive values are treated as UTC); ``since`` is inclusive and ``until`` is inclusive.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .db import Database, from_db_ts, to_db_ts
from .models import (
    MAX_EVIDENCE_IDS,
    OPEN_STATUSES,
    SEVERITIES,
    ALERT_STATUSES,
    SEVERITY_RANK,
    Alert,
    AlertIn,
    AlertUpdate,
    Event,
    EventIn,
    Stats,
    TopSource,
    utcnow,
)

MAX_LIST_LIMIT = 1000
DEFAULT_LIST_LIMIT = 100
MAX_WINDOW_ROWS = 50_000  # hard cap for events_in_window so a bad rule can't load the table
_ID_CHUNK = 500  # keeps "IN (?, ?, ...)" well under SQLite's variable limit

_EVENT_COLUMNS = (
    "id, type, timestamp, received_at, source, src_ip, dst_ip, dst_port, protocol, "
    "dns_name, username, http_method, http_path, http_status, user_agent, details"
)
_ALERT_COLUMNS = (
    "id, created_at, updated_at, rule, severity, title, status, src_ip, "
    "evidence_event_ids, count, explanation"
)

# Columns count_distinct() may be asked about (whitelist: never interpolate user input).
DISTINCT_FIELDS = frozenset(
    {"src_ip", "dst_ip", "dst_port", "dns_name", "username", "http_path", "source"}
)


# --------------------------------------------------------------------------
# Row <-> model helpers
# --------------------------------------------------------------------------
def _row_to_event(row) -> Event:
    # Rows come from our own validated inserts, so skip re-validation (fast on big windows).
    return Event.model_construct(
        id=row["id"],
        type=row["type"],
        timestamp=from_db_ts(row["timestamp"]),
        received_at=from_db_ts(row["received_at"]),
        source=row["source"],
        src_ip=row["src_ip"],
        dst_ip=row["dst_ip"],
        dst_port=row["dst_port"],
        protocol=row["protocol"],
        dns_name=row["dns_name"],
        username=row["username"],
        http_method=row["http_method"],
        http_path=row["http_path"],
        http_status=row["http_status"],
        user_agent=row["user_agent"],
        details=json.loads(row["details"]) if row["details"] else None,
    )


def _row_to_alert(row) -> Alert:
    return Alert.model_construct(
        id=row["id"],
        created_at=from_db_ts(row["created_at"]),
        updated_at=from_db_ts(row["updated_at"]),
        rule=row["rule"],
        severity=row["severity"],
        title=row["title"],
        status=row["status"],
        src_ip=row["src_ip"],
        evidence_event_ids=json.loads(row["evidence_event_ids"]),
        count=row["count"],
        explanation=json.loads(row["explanation"]),
    )


def _clamp_limit(limit: int) -> int:
    return max(1, min(int(limit), MAX_LIST_LIMIT))


def _event_filters(
    *,
    since: datetime | None,
    until: datetime | None,
    type: str | None,
    src_ip: str | None,
    username: str | None,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if type is not None:
        clauses.append("type = ?")
        params.append(type)
    if src_ip is not None:
        clauses.append("src_ip = ?")
        params.append(src_ip)
    if username is not None:
        clauses.append("username = ?")
        params.append(username)
    if since is not None:
        clauses.append("timestamp >= ?")
        params.append(to_db_ts(since))
    if until is not None:
        clauses.append("timestamp <= ?")
        params.append(to_db_ts(until))
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------
def _insert_event_row(conn, ev: EventIn, received: str) -> int:
    cur = conn.execute(
        "INSERT INTO events (type, timestamp, received_at, source, src_ip, dst_ip, dst_port, "
        "protocol, dns_name, username, http_method, http_path, http_status, user_agent, details) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            ev.type,
            to_db_ts(ev.timestamp),
            received,
            ev.source,
            ev.src_ip,
            ev.dst_ip,
            ev.dst_port,
            ev.protocol,
            ev.dns_name,
            ev.username,
            ev.http_method,
            ev.http_path,
            ev.http_status,
            ev.user_agent,
            json.dumps(ev.details, separators=(",", ":")) if ev.details is not None else None,
        ),
    )
    return cur.lastrowid


def _stored_event(ev: EventIn, event_id: int, received: datetime) -> Event:
    # ``ev`` was already validated as an EventIn, so don't validate it a second time.
    return Event.model_construct(**ev.model_dump(), id=event_id, received_at=received)


def insert_event(db: Database, ev: EventIn, *, now: datetime | None = None) -> Event:
    """Store one validated event and return it with its new id."""
    received = now or utcnow()
    with db.transaction() as conn:
        event_id = _insert_event_row(conn, ev, to_db_ts(received))
    return _stored_event(ev, event_id, received)


def insert_events(db: Database, events: Iterable[EventIn], *, now: datetime | None = None) -> list[Event]:
    """Store a batch atomically (all or nothing). Returns events in input order."""
    received = now or utcnow()
    received_text = to_db_ts(received)
    stored: list[Event] = []
    with db.transaction() as conn:
        for ev in events:
            stored.append(_stored_event(ev, _insert_event_row(conn, ev, received_text), received))
    return stored


def get_event(db: Database, event_id: int) -> Event | None:
    row = db.connection().execute(
        f"SELECT {_EVENT_COLUMNS} FROM events WHERE id = ?", (event_id,)
    ).fetchone()
    return _row_to_event(row) if row else None


def get_events_by_ids(db: Database, ids: Iterable[int]) -> list[Event]:
    """Events that still exist for the given ids, oldest first (missing ids are skipped)."""
    id_list = list(dict.fromkeys(int(i) for i in ids))
    conn = db.connection()
    found: list[Event] = []
    for start in range(0, len(id_list), _ID_CHUNK):
        chunk = id_list[start : start + _ID_CHUNK]
        marks = ",".join("?" * len(chunk))
        rows = conn.execute(
            f"SELECT {_EVENT_COLUMNS} FROM events WHERE id IN ({marks})", chunk
        ).fetchall()
        found.extend(_row_to_event(r) for r in rows)
    found.sort(key=lambda e: (e.timestamp, e.id))
    return found


def list_events(
    db: Database,
    *,
    type: str | None = None,
    src_ip: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
) -> list[Event]:
    """GET /api/events: newest first, optional filters, limit clamped to 1..1000."""
    where, params = _event_filters(since=since, until=until, type=type, src_ip=src_ip, username=None)
    rows = db.connection().execute(
        f"SELECT {_EVENT_COLUMNS} FROM events{where} "
        "ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
        [*params, _clamp_limit(limit), max(0, int(offset))],
    ).fetchall()
    return [_row_to_event(r) for r in rows]


# --------------------------------------------------------------------------
# Time-window and aggregate queries (what the detection rules use)
# --------------------------------------------------------------------------
def events_in_window(
    db: Database,
    *,
    since: datetime,
    until: datetime | None = None,
    type: str | None = None,
    src_ip: str | None = None,
    username: str | None = None,
    limit: int = MAX_WINDOW_ROWS,
) -> list[Event]:
    """Events with since <= timestamp <= until, OLDEST first (evidence order)."""
    where, params = _event_filters(since=since, until=until, type=type, src_ip=src_ip, username=username)
    limit = max(1, min(int(limit), MAX_WINDOW_ROWS))
    rows = db.connection().execute(
        f"SELECT {_EVENT_COLUMNS} FROM events{where} ORDER BY timestamp ASC, id ASC LIMIT ?",
        [*params, limit],
    ).fetchall()
    return [_row_to_event(r) for r in rows]


def count_events(
    db: Database,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    type: str | None = None,
    src_ip: str | None = None,
    username: str | None = None,
) -> int:
    where, params = _event_filters(since=since, until=until, type=type, src_ip=src_ip, username=username)
    return db.connection().execute(f"SELECT COUNT(*) FROM events{where}", params).fetchone()[0]


def count_distinct(
    db: Database,
    field: str,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    type: str | None = None,
    src_ip: str | None = None,
    username: str | None = None,
) -> int:
    """Number of distinct non-null values of ``field`` in the window.

    Port scan: ``count_distinct(db, "dst_port", since=now-30s, type="network_connection", src_ip=ip)``.
    """
    if field not in DISTINCT_FIELDS:
        raise ValueError(f"cannot count distinct {field!r}; allowed: {sorted(DISTINCT_FIELDS)}")
    where, params = _event_filters(since=since, until=until, type=type, src_ip=src_ip, username=username)
    sql = f"SELECT COUNT(DISTINCT {field}) FROM events{where}"  # field is whitelisted above
    return db.connection().execute(sql, params).fetchone()[0]


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------
def _dedupe_ids(ids: Iterable[int]) -> list[int]:
    return list(dict.fromkeys(ids))


def _insert_alert_row(conn, a: AlertIn, now: datetime) -> int:
    ids = _dedupe_ids(a.evidence_event_ids)
    stamp = to_db_ts(now)
    cur = conn.execute(
        "INSERT INTO alerts (created_at, updated_at, rule, severity, title, status, src_ip, "
        "evidence_event_ids, count, explanation) VALUES (?, ?, ?, ?, ?, 'new', ?, ?, ?, ?)",
        (
            stamp,
            stamp,
            a.rule,
            a.severity,
            a.title,
            a.src_ip,
            json.dumps(ids[-MAX_EVIDENCE_IDS:], separators=(",", ":")),
            max(1, len(ids)),
            json.dumps(a.explanation, separators=(",", ":")),
        ),
    )
    return cur.lastrowid


def _fetch_alert(conn, alert_id: int) -> Alert | None:
    row = conn.execute(f"SELECT {_ALERT_COLUMNS} FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_alert(row) if row else None


def insert_alert(db: Database, a: AlertIn, *, now: datetime | None = None) -> Alert:
    """Always create a new alert (status 'new'). Detection normally uses upsert_alert."""
    when = now or utcnow()
    with db.transaction() as conn:
        alert_id = _insert_alert_row(conn, a, when)
        return _fetch_alert(conn, alert_id)  # type: ignore[return-value]


def upsert_alert(
    db: Database,
    a: AlertIn,
    *,
    cooldown_seconds: int,
    now: datetime | None = None,
) -> tuple[Alert, bool]:
    """Deduplicating alert creation. Returns ``(alert, created)``.

    If an OPEN alert (status new/investigating) with the same rule and src_ip was
    updated within ``cooldown_seconds``, it is updated instead of creating a new one:
      * new evidence ids are merged and ``count`` grows by the number of NEW ids
        (or by 1 when the caller passes no evidence ids)
      * severity can only escalate, title/explanation take the latest values
      * ``updated_at`` moves forward only if something new was added
    Resolved / false_positive alerts never absorb new activity - a fresh alert is created.
    The whole lookup+write is one write transaction, so concurrent callers can't
    create duplicates.
    """
    when = now or utcnow()
    cutoff = to_db_ts(when - timedelta(seconds=cooldown_seconds))
    open_marks = ",".join("?" * len(OPEN_STATUSES))
    with db.transaction() as conn:
        row = conn.execute(
            f"SELECT {_ALERT_COLUMNS} FROM alerts "
            f"WHERE rule = ? AND src_ip IS ? AND status IN ({open_marks}) AND updated_at >= ? "
            "ORDER BY updated_at DESC, id DESC LIMIT 1",
            (a.rule, a.src_ip, *OPEN_STATUSES, cutoff),
        ).fetchone()
        if row is None:
            return _fetch_alert(conn, _insert_alert_row(conn, a, when)), True  # type: ignore[arg-type]

        existing = _row_to_alert(row)
        incoming = _dedupe_ids(a.evidence_event_ids)
        seen = set(existing.evidence_event_ids)
        min_seen = (
            min(existing.evidence_event_ids)
            if (existing.evidence_event_ids and existing.count > len(existing.evidence_event_ids))
            else None
        )
        new_ids = [
            i for i in incoming
            if i not in seen and (min_seen is None or i > min_seen)
        ]
        severity = max(existing.severity, a.severity, key=lambda s: SEVERITY_RANK[s])
        escalated = SEVERITY_RANK[a.severity] > SEVERITY_RANK[existing.severity]
        details_changed = (a.title != existing.title) or (a.explanation != existing.explanation)

        if incoming and not new_ids and not escalated and not details_changed:
            return existing, False

        added = len(new_ids) if incoming else 1
        merged = (existing.evidence_event_ids + new_ids)[-MAX_EVIDENCE_IDS:]
        conn.execute(
            "UPDATE alerts SET updated_at = ?, severity = ?, title = ?, evidence_event_ids = ?, "
            "count = count + ?, explanation = ? WHERE id = ?",
            (
                to_db_ts(when),
                severity,
                a.title,
                json.dumps(merged, separators=(",", ":")),
                added,
                json.dumps(a.explanation, separators=(",", ":")),
                existing.id,
            ),
        )
        return _fetch_alert(conn, existing.id), False  # type: ignore[return-value]


def get_alert(db: Database, alert_id: int) -> Alert | None:
    return _fetch_alert(db.connection(), alert_id)


def list_alerts(
    db: Database,
    *,
    severity: str | None = None,
    status: str | None = None,
    rule: str | None = None,
    src_ip: str | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
) -> list[Alert]:
    """GET /api/alerts: newest first (by creation time)."""
    if severity is not None and severity not in SEVERITIES:
        raise ValueError(f"unknown severity {severity!r}")
    if status is not None and status not in ALERT_STATUSES:
        raise ValueError(f"unknown status {status!r}")
    clauses, params = [], []
    for column, value in (("severity", severity), ("status", status), ("rule", rule), ("src_ip", src_ip)):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = db.connection().execute(
        f"SELECT {_ALERT_COLUMNS} FROM alerts{where} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
        [*params, _clamp_limit(limit), max(0, int(offset))],
    ).fetchall()
    return [_row_to_alert(r) for r in rows]


def update_alert_status(
    db: Database, alert_id: int, update: AlertUpdate, *, now: datetime | None = None
) -> Alert | None:
    """PATCH /api/alerts/{id}. Returns the updated alert, or None if it doesn't exist."""
    with db.transaction() as conn:
        cur = conn.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
            (update.status, to_db_ts(now or utcnow()), alert_id),
        )
        if cur.rowcount == 0:
            return None
        return _fetch_alert(conn, alert_id)


def get_alert_evidence(db: Database, alert_id: int) -> list[Event]:
    """Evidence events for an alert. Events removed by retention are silently absent."""
    alert = get_alert(db, alert_id)
    return get_events_by_ids(db, alert.evidence_event_ids) if alert else []


# --------------------------------------------------------------------------
# Dashboard stats
# --------------------------------------------------------------------------
def stats(
    db: Database,
    *,
    now: datetime | None = None,
    top_n: int = 5,
    top_window_hours: int = 24,
) -> Stats:
    """GET /api/stats. ``events_today`` counts since 00:00 UTC; top IPs cover the last 24 h."""
    when = now or utcnow()
    midnight = when.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    top_since = to_db_ts(when - timedelta(hours=top_window_hours))
    with db.transaction(write=False) as conn:  # one consistent snapshot
        events_total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        events_today = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (to_db_ts(midnight),)
        ).fetchone()[0]
        by_severity = {s: 0 for s in SEVERITIES}
        by_severity.update(
            {r[0]: r[1] for r in conn.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")}
        )
        by_status = {s: 0 for s in ALERT_STATUSES}
        by_status.update(
            {r[0]: r[1] for r in conn.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status")}
        )
        top = conn.execute(
            "SELECT src_ip, COUNT(*) AS c FROM events WHERE timestamp >= ? "
            "GROUP BY src_ip ORDER BY c DESC, src_ip ASC LIMIT ?",
            (top_since, max(1, int(top_n))),
        ).fetchall()
    return Stats(
        events_today=events_today,
        events_total=events_total,
        alerts_total=sum(by_status.values()),
        open_alerts=sum(by_status[s] for s in OPEN_STATUSES),
        alerts_by_severity=by_severity,
        alerts_by_status=by_status,
        top_source_ips=[TopSource(src_ip=r["src_ip"], count=r["c"]) for r in top],
    )


# --------------------------------------------------------------------------
# Retention
# --------------------------------------------------------------------------
def purge_old_events(
    db: Database,
    retention_days: float,
    *,
    now: datetime | None = None,
    chunk_size: int = 10_000,
) -> int:
    """Delete events older than ``retention_days``; returns how many were removed.

    Deletes in chunks, each in its own short transaction, so API writes and the
    detection engine are never blocked for long. Alerts are kept; their evidence
    ids may point at deleted events (get_alert_evidence skips those).
    """
    if retention_days <= 0:
        raise ValueError("retention_days must be positive")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    cutoff = to_db_ts((now or utcnow()) - timedelta(days=retention_days))
    total = 0
    while True:
        with db.transaction() as conn:
            deleted = conn.execute(
                "DELETE FROM events WHERE id IN "
                "(SELECT id FROM events WHERE timestamp < ? ORDER BY timestamp LIMIT ?)",
                (cutoff, chunk_size),
            ).rowcount
        total += deleted
        if deleted < chunk_size:
            return total
