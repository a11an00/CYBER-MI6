"""Repeated authentication failures rule (``backend/detection/auth_failures.py``).

Idea: many failed logins in a short time means password guessing. Two angles,
both counted in the same sliding window:

* by IP        many failures from one source IP        (brute force from one host)
* by username  many failures against one account       (also catches attacks spread
                                                        over many IPs)

Events come from OUR OWN instrumented web app (``auth_failure`` events); packet capture
cannot see failed logins on encrypted connections.

Interface (shared by all rules)::

    evaluate(event, recent_events=None, settings=None) -> AlertIn | None
    history_query(event, settings) -> list[dict] | None

Settings (all optional; names match ``.env``)
---------------------------------------------
``auth_fail_count``            threshold: failures                     (default 5)
``auth_fail_window_seconds``   sliding window length                   (default 300)

Severity: ``medium`` at the threshold, ``high`` at 3x or when one account is attacked from
3 or more different IPs, ``critical`` at 10x.

Alert identity: the alert's source IP is the IP of the failure that triggered it, so the
engine's de-duplication (rule + source IP + cooldown) keeps one alert per attacking IP.
``explanation["triggers"]`` says whether the IP count, the username count or both fired.

Known limitations
-----------------
* A user who forgets their password triggers it. Raise ``auth_fail_count`` or add trusted
  office/VPN addresses to ``detection_ignore_ips`` if that is noisy.
* Usernames are compared exactly (``Admin`` and ``admin`` are different accounts here).
* Attackers who stay under the threshold per window ("low and slow") are missed.
* A source behind a shared address (NAT, proxy) is counted as one source.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from typing import Any

from backend.detection.common import (
    HISTORY_LIMIT,
    MAX_EVIDENCE,
    evidence_ids,
    fit_explanation,
    int_setting,
    iso,
    merge_events,
    severity_for_ratio,
    span_seconds,
)
from backend.models import MAX_TITLE_LEN, AlertIn

__all__ = ["RULE_NAME", "evaluate", "history_query"]

RULE_NAME = "auth_failures"
EVENT_TYPE = "auth_failure"

DEFAULT_COUNT = 5
DEFAULT_WINDOW_SECONDS = 300
SEVERITY_STEPS = ((10, "critical"), (3, "high"), (1, "medium"))
DISTRIBUTED_MIN_IPS = 3  # one account attacked from this many IPs counts as "high"
MAX_USERNAME_IN_TITLE = 60


def _window(settings: Any) -> int:
    return int_setting(settings, "auth_fail_window_seconds", DEFAULT_WINDOW_SECONDS, minimum=1)


def history_query(event: Any, settings: Any = None) -> list[dict[str, Any]] | None:
    """Two small queries: failures from this IP, and failures against this username."""
    if getattr(event, "type", None) != EVENT_TYPE:
        return None
    base = {
        "since": event.timestamp - timedelta(seconds=_window(settings)),
        "until": event.timestamp,
        "type": EVENT_TYPE,
        "limit": HISTORY_LIMIT,
    }
    return [{**base, "src_ip": event.src_ip}, {**base, "username": event.username}]


def evaluate(event: Any, recent_events: Sequence[Any] | None = None, settings: Any = None) -> AlertIn | None:
    if getattr(event, "type", None) != EVENT_TYPE:
        return None

    threshold = int_setting(settings, "auth_fail_count", DEFAULT_COUNT, minimum=2)
    window = _window(settings)
    since = event.timestamp - timedelta(seconds=window)

    failures = [
        e
        for e in merge_events(event, recent_events)
        if e.type == EVENT_TYPE and since <= e.timestamp <= event.timestamp
    ]
    by_ip = [e for e in failures if e.src_ip == event.src_ip]
    username = getattr(event, "username", None)
    by_user = [e for e in failures if username is not None and e.username == username]

    ip_fired = len(by_ip) >= threshold
    user_fired = len(by_user) >= threshold
    if not (ip_fired or user_fired):
        return None

    triggers = (["ip"] if ip_fired else []) + (["username"] if user_fired else [])
    # ``failures`` is already unique and oldest-first; keep the ones behind a trigger that fired.
    matched = [
        e
        for e in failures
        if (ip_fired and e.src_ip == event.src_ip) or (user_fired and username is not None and e.username == username)
    ]

    ip_count, user_count = len(by_ip), len(by_user)
    # Headline = the stronger trigger (the IP wins ties); the dashboard reads ``observed`` and ``username``.
    headline_is_user = user_fired and (not ip_fired or user_count > ip_count)
    observed = user_count if headline_is_user else ip_count
    user_ips = sorted({e.src_ip for e in by_user})

    severity = severity_for_ratio(max(ip_count if ip_fired else 0, user_count if user_fired else 0) / threshold, SEVERITY_STEPS)
    if user_fired and len(user_ips) >= DISTRIBUTED_MIN_IPS and severity == "medium":
        severity = "high"

    explanation: dict[str, Any] = {
        "description": "Repeated failed logins within a short time",
        # Keys below are read by the dashboard's "Why this fired" panel.
        "threshold": threshold,
        "window_seconds": window,
        "observed": observed,
        "observed_window_seconds": span_seconds(by_user if headline_is_user else by_ip),
        # Extra detail.
        "triggers": triggers,
        "failures_from_ip": {"ip": event.src_ip, "count": ip_count},
        "first_seen": iso(matched[0].timestamp),
        "last_seen": iso(matched[-1].timestamp),
        "history_capped": ip_count >= HISTORY_LIMIT or user_count >= HISTORY_LIMIT,  # each query is capped
    }
    if username is not None:
        explanation["failures_for_username"] = {"username": username, "count": user_count, "distinct_ips": len(user_ips)}
    if headline_is_user:
        explanation["username"] = username  # makes the dashboard say "for <username>" instead of "from <ip>"

    if headline_is_user:
        shown = username if len(username) <= MAX_USERNAME_IN_TITLE else username[: MAX_USERNAME_IN_TITLE - 3] + "..."
        title = f"Repeated authentication failures for '{shown}': {user_count} in {window}s (from {event.src_ip})"
    else:
        title = f"Repeated authentication failures from {event.src_ip}: {ip_count} in {window}s"
    return AlertIn(
        rule=RULE_NAME,
        severity=severity,
        title=title[:MAX_TITLE_LEN],
        src_ip=event.src_ip,
        evidence_event_ids=evidence_ids(matched[-MAX_EVIDENCE:]),
        explanation=fit_explanation(explanation),
    )
