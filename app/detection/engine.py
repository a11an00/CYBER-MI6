"""Detection engine (``app/detection/engine.py``).

Runs every rule on each newly stored event, turns matches into alerts and
de-duplicates them. The rules themselves are pure functions; this module is the
only detection code that touches the database.

Typical use, in the ingestion route, after the event(s) are stored::

    events = await run_in_threadpool(storage.insert_events, db, batch)
    results = await run_in_threadpool(engine.process_events, db, events, settings)
    for r in results:                       # r.created tells new alert from updated alert
        await manager.broadcast({"kind": "alert", "data": r.alert.model_dump(mode="json")})

(``process_event`` is synchronous and quick; call it from a worker thread, as above, or from a
plain ``def`` endpoint, never straight from ``async def`` code.)

What happens for one event
--------------------------
1. Skip entirely when its source IP is in ``detection_ignore_ips``.
2. For each enabled rule (``detection_disabled_rules`` switches rules off by name):
   a. ask the rule which earlier events it needs (``history_query``) and load them with
      ``storage.events_in_window``;
   b. call ``rule.evaluate(event, recent_events, settings)``;
   c. if it returns an alert, store it with ``storage.upsert_alert``: the same rule +
      source IP inside ``alert_cooldown_seconds`` updates one alert (count and evidence
      grow, severity can only escalate) instead of creating many. With a cooldown of 0
      every match creates its own alert.
3. A rule that raises is logged and skipped; the other rules and ingestion carry on.

Windows are anchored on the EVENT's timestamp, not the wall clock, so late or replayed
events are judged against the traffic around them. The cooldown uses the wall clock.

Settings used here (all optional)
---------------------------------
``alert_cooldown_seconds``   de-duplication window, 0 turns it off      (default 300)
``detection_ignore_ips``     comma-separated IPs / CIDR ranges to skip  (default none)
``detection_disabled_rules`` comma-separated rule names to switch off   (default none)

To add a rule: create the module in this package with ``RULE_NAME`` and ``evaluate`` (and
``history_query`` if it needs earlier events), import it below and add it to ``RULES``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app import storage
from app.db import Database
from app.detection import auth_failures, dns_anomaly, portscan, web_paths
from app.detection.common import csv_setting, int_setting, is_ignored_ip, valid_id
from app.models import Alert, AlertIn, Event

log = logging.getLogger(__name__)

__all__ = ["RULES", "AlertResult", "process_event", "process_events"]

RULES: tuple[Any, ...] = (portscan, dns_anomaly, auth_failures, web_paths)

DEFAULT_COOLDOWN_SECONDS = 300


@dataclass(frozen=True)
class AlertResult:
    """One alert produced or updated by an event."""

    rule: str
    alert: Alert
    created: bool  # True = brand new alert, False = an existing open alert was updated


def _load_history(db: Database, rule: Any, event: Event, settings: Any) -> list[Event]:
    """Events the rule asked for (``history_query``), de-duplicated by id."""
    query_for = getattr(rule, "history_query", None)
    if query_for is None:
        return []
    queries = query_for(event, settings)
    if not queries:
        return []
    if isinstance(queries, dict):
        queries = [queries]
    found: dict[int, Event] = {}
    for query in queries:
        for e in storage.events_in_window(db, **query):
            found[e.id] = e
    return sorted(found.values(), key=lambda e: (e.timestamp, e.id))


def _store(db: Database, candidate: AlertIn, cooldown: int, now: datetime | None) -> tuple[Alert, bool]:
    if cooldown <= 0:  # de-duplication switched off
        return storage.insert_alert(db, candidate, now=now), True
    return storage.upsert_alert(db, candidate, cooldown_seconds=cooldown, now=now)


def process_event(
    db: Database,
    event: Event,
    settings: Any = None,
    *,
    rules: Sequence[Any] | None = None,
    now: datetime | None = None,
) -> list[AlertResult]:
    """Run all rules on one stored event. Returns the alerts created or updated (usually none)."""
    if not valid_id(getattr(event, "id", None)):
        raise ValueError("process_event needs a stored Event (with an id); store it first")
    if is_ignored_ip(event.src_ip, settings):
        return []

    disabled = set(csv_setting(settings, "detection_disabled_rules"))
    cooldown = int_setting(settings, "alert_cooldown_seconds", DEFAULT_COOLDOWN_SECONDS, minimum=0)
    results: list[AlertResult] = []

    for rule in RULES if rules is None else rules:
        name = rule.RULE_NAME
        if name in disabled:
            continue
        try:
            recent = _load_history(db, rule, event, settings)
            candidate = rule.evaluate(event, recent, settings)
            if candidate is None:
                continue
            alert, created = _store(db, candidate, cooldown, now)
        except Exception:  # one broken rule must not stop the others or event ingestion
            log.exception("detection rule %r failed on event %s; skipping it", name, event.id)
            continue
        log.info("rule %s %s alert %s (%s, count %s)", name, "created" if created else "updated",
                 alert.id, alert.severity, alert.count)
        results.append(AlertResult(rule=name, alert=alert, created=created))
    return results


def process_events(
    db: Database,
    events: Iterable[Event],
    settings: Any = None,
    *,
    rules: Sequence[Any] | None = None,
    now: datetime | None = None,
) -> list[AlertResult]:
    """Run the rules over a batch of stored events, in order. Returns all results, in order."""
    results: list[AlertResult] = []
    for event in events:
        results.extend(process_event(db, event, settings, rules=rules, now=now))
    return results
