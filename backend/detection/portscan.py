"""Possible port scan rule (``backend/detection/portscan.py``).

Idea: one source touching many different destination ports in a short time is
what a port scan looks like from the outside. The Scapy sensor reports initial
TCP SYN packets as ``network_connection`` events, so we count DISTINCT
destination ports per source IP inside a sliding window.

Interface (shared by all rules; see ``backend/detection/__init__.py``)::

    evaluate(event, recent_events=None, settings=None) -> AlertIn | None
    history_query(event, settings) -> dict | None

How it decides
--------------
1. Take the events from the same source IP, of type ``network_connection``, whose
   timestamp is inside ``[event.timestamp - window, event.timestamp]``.
2. Count distinct destination ports. Repeating the same port does not count.
3. Fire when the count reaches the threshold. Severity grows with the count.

Settings (all optional; names match ``.env``)
---------------------------------------------
``port_scan_ports``             threshold: distinct ports            (default 20)
``port_scan_window_seconds``    sliding window length                (default 30)
``port_scan_per_destination``   count ports per destination host instead of across all
                                destinations (default False). Turn it on if a busy
                                client (or a scanner you run on purpose) causes false
                                positives: only many ports on ONE host will then count.

Severity: ``medium`` at the threshold, ``high`` at 5x, ``critical`` at 50x.

Known limitations
-----------------
* A heuristic, not proof of intent. Legitimate tools (vulnerability scanners,
  service discovery, some games and P2P clients) look the same. Use
  ``detection_ignore_ips`` for hosts you know.
* Only sees SYNs the sensor can observe; packet loss or interface visibility
  changes the count. Slow scans that stay under the threshold per window are missed.
* In a flood the engine loads at most ``HISTORY_LIMIT`` events, so the count is then a
  lower bound (``history_capped`` is true in the explanation).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from typing import Any

from backend.detection.common import (
    HISTORY_LIMIT,
    MAX_EVIDENCE,
    bool_setting,
    evidence_ids,
    fit_explanation,
    int_setting,
    iso,
    merge_events,
    severity_for_ratio,
    span_seconds,
)
from backend.models import AlertIn

__all__ = ["RULE_NAME", "evaluate", "history_query"]

RULE_NAME = "port_scan"
EVENT_TYPE = "network_connection"

DEFAULT_PORTS = 20
DEFAULT_WINDOW_SECONDS = 30
# (observed / threshold, severity), highest first.
SEVERITY_STEPS = ((50, "critical"), (5, "high"), (1, "medium"))
SAMPLE_PORTS = 20
TOP_DESTINATIONS = 5


def _window(settings: Any) -> int:
    return int_setting(settings, "port_scan_window_seconds", DEFAULT_WINDOW_SECONDS, minimum=1)


def history_query(event: Any, settings: Any = None) -> dict[str, Any] | None:
    """Earlier events this rule needs: same source, SYN events, inside the window."""
    if getattr(event, "type", None) != EVENT_TYPE:
        return None
    return {
        "since": event.timestamp - timedelta(seconds=_window(settings)),
        "until": event.timestamp,
        "type": EVENT_TYPE,
        "src_ip": event.src_ip,
        "limit": HISTORY_LIMIT,
    }


def evaluate(event: Any, recent_events: Sequence[Any] | None = None, settings: Any = None) -> AlertIn | None:
    if getattr(event, "type", None) != EVENT_TYPE or getattr(event, "dst_port", None) is None:
        return None

    threshold = int_setting(settings, "port_scan_ports", DEFAULT_PORTS, minimum=2)
    window = _window(settings)
    per_destination = bool_setting(settings, "port_scan_per_destination", False)

    since = event.timestamp - timedelta(seconds=window)
    attempts = [
        e
        for e in merge_events(event, recent_events)
        if e.type == EVENT_TYPE
        and e.src_ip == event.src_ip
        and e.dst_port is not None
        and since <= e.timestamp <= event.timestamp
    ]

    ports_by_destination: dict[str | None, dict[int, Any]] = {}
    for e in attempts:  # oldest first, so setdefault keeps the first attempt per (destination, port)
        ports_by_destination.setdefault(e.dst_ip, {}).setdefault(e.dst_port, e)

    if per_destination:
        target, first_per_port = max(ports_by_destination.items(), key=lambda kv: (len(kv[1]), str(kv[0])))
        counted = [e for e in attempts if e.dst_ip == target]
    else:
        target, first_per_port = None, {}
        for e in attempts:
            first_per_port.setdefault(e.dst_port, e)
        counted = attempts

    observed = len(first_per_port)
    if observed < threshold:
        return None

    first_events = sorted(first_per_port.values(), key=lambda e: (e.timestamp, getattr(e, "id", None) or 0))
    top = sorted(ports_by_destination.items(), key=lambda kv: (-len(kv[1]), str(kv[0])))[:TOP_DESTINATIONS]
    explanation = {
        "description": (
            "Many distinct destination ports were contacted from one source in a short time"
            + (" (counted per destination host)" if per_destination else "")
        ),
        "threshold": threshold,
        "window_seconds": window,
        "observed": observed,
        "observed_window_seconds": span_seconds(counted),
        "counting": "per destination host" if per_destination else "across all destinations",
        "connection_attempts": len(counted),
        "distinct_destinations": len(ports_by_destination),
        "top_destinations": [{"dst_ip": ip, "distinct_ports": len(ports)} for ip, ports in top],
        "sample_ports": sorted(first_per_port)[:SAMPLE_PORTS],
        "first_seen": iso(counted[0].timestamp),
        "last_seen": iso(counted[-1].timestamp),
        "history_capped": len(recent_events or ()) >= HISTORY_LIMIT,
    }
    scope = f" on {target}" if per_destination else ""
    return AlertIn(
        rule=RULE_NAME,
        severity=severity_for_ratio(observed / threshold, SEVERITY_STEPS),
        title=f"Possible port scan from {event.src_ip}{scope}: {observed} distinct ports in {window}s",
        src_ip=event.src_ip,
        evidence_event_ids=evidence_ids(first_events, MAX_EVIDENCE),
        explanation=fit_explanation(explanation),
    )
