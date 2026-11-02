"""Helpers shared by the detection rules and the engine.

Pure functions only: no database, no network, no clock, no FastAPI.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from functools import lru_cache
from typing import Any

from backend.models import MAX_EXPLANATION_BYTES

log = logging.getLogger(__name__)

# How many earlier events a rule may ask the engine to load. A flood from one source can
# produce tens of thousands of events per window; counting stops being exact beyond this cap
# (rules record ``history_capped`` in the explanation when that happens).
HISTORY_LIMIT = 2000
# Evidence ids stored per alert by a rule (storage keeps at most models.MAX_EVIDENCE_IDS).
MAX_EVIDENCE = 100


# --------------------------------------------------------------------------
# Settings access (works with the pydantic Settings object, a dict, or a namespace)
# --------------------------------------------------------------------------
def get_setting(settings: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` from a mapping or an object (lower- or upper-case). None means 'unset'."""
    if settings is None:
        return default
    for key in (name, name.upper()):
        if isinstance(settings, Mapping):
            if settings.get(key) is not None:
                return settings[key]
        else:
            value = getattr(settings, key, None)
            if value is not None:
                return value
    return default


def int_setting(settings: Any, name: str, default: int, *, minimum: int = 1) -> int:
    """An integer setting; bad values fall back to ``default`` and low values are raised to ``minimum``."""
    raw = get_setting(settings, name, default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        log.warning("setting %s=%r is not an integer; using %s", name, raw, default)
        value = default
    return max(value, minimum)


def float_setting(settings: Any, name: str, default: float, *, minimum: float = 0.0) -> float:
    raw = get_setting(settings, name, default)
    try:
        value = float(raw)
    except (TypeError, ValueError):
        log.warning("setting %s=%r is not a number; using %s", name, raw, default)
        value = default
    return max(value, minimum)


def bool_setting(settings: Any, name: str, default: bool = False) -> bool:
    raw = get_setting(settings, name, default)
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return bool(raw)


def csv_setting(settings: Any, name: str, *, lower: bool = True) -> tuple[str, ...]:
    """A list setting given as 'a, b, c' (env var style) or as a real list/tuple/set."""
    raw = get_setting(settings, name, ())
    items: Iterable[Any] = raw.split(",") if isinstance(raw, str) else raw
    cleaned = (str(i).strip() for i in items)
    return tuple((c.lower() if lower else c) for c in cleaned if c)


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------
def valid_id(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def merge_events(event: Any, recent_events: Sequence[Any] | None) -> list[Any]:
    """``recent_events`` plus ``event`` itself, de-duplicated by id, oldest first.

    The engine runs after the event is stored, so it is normally already in
    ``recent_events``; in unit tests it may be missing or have no id at all.
    """
    seen: set[int] = set()
    merged: list[Any] = []
    for e in (*(recent_events or ()), event):
        eid = getattr(e, "id", None)
        if valid_id(eid):
            if eid in seen:
                continue
            seen.add(eid)
        elif any(e is m for m in merged):
            continue
        merged.append(e)
    merged.sort(key=lambda e: (e.timestamp, getattr(e, "id", None) or 0))
    return merged


def evidence_ids(events: Iterable[Any], limit: int = MAX_EVIDENCE) -> list[int]:
    """Ids of the given events (in order, unique, valid only), at most ``limit``."""
    ids = list(dict.fromkeys(e.id for e in events if valid_id(getattr(e, "id", None))))
    return ids[:limit]


def span_seconds(events: Sequence[Any]) -> int:
    """Seconds between the first and last event (0 for fewer than two)."""
    if len(events) < 2:
        return 0
    times = [e.timestamp for e in events]
    return int(round((max(times) - min(times)).total_seconds()))


def iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------
def severity_for_ratio(ratio: float, steps: Sequence[tuple[float, str]]) -> str:
    """Pick a severity from ``observed / threshold``. ``steps`` = ((min_ratio, severity), ...) high to low."""
    for min_ratio, severity in steps:
        if ratio >= min_ratio:
            return severity
    return steps[-1][1]


# --------------------------------------------------------------------------
# Explanation size guard
# --------------------------------------------------------------------------
def fit_explanation(explanation: dict[str, Any]) -> dict[str, Any]:
    """Make sure the explanation fits models.MAX_EXPLANATION_BYTES (shrinks lists, then long strings)."""

    def size() -> int:
        return len(json.dumps(explanation).encode())

    while size() > MAX_EXPLANATION_BYTES:
        lists = [k for k, v in explanation.items() if isinstance(v, list) and v]
        if lists:
            longest = max(lists, key=lambda k: len(json.dumps(explanation[k])))
            explanation[longest].pop()
            continue
        strings = [k for k, v in explanation.items() if isinstance(v, str) and len(v) > 40]
        if not strings:
            break
        longest = max(strings, key=lambda k: len(explanation[k]))
        explanation[longest] = explanation[longest][:40]
    return explanation


# --------------------------------------------------------------------------
# Source-IP ignore list (used by the engine)
# --------------------------------------------------------------------------
@lru_cache(maxsize=16)
def _networks(entries: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    nets = []
    for entry in entries:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            log.warning("detection_ignore_ips: %r is not an IP address or CIDR range; ignored", entry)
    return tuple(nets)


def is_ignored_ip(ip: str | None, settings: Any) -> bool:
    """True when ``ip`` is inside ``detection_ignore_ips`` (comma-separated IPs / CIDR ranges)."""
    entries = csv_setting(settings, "detection_ignore_ips", lower=False)
    if not entries or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == net.version and addr in net for net in _networks(entries))
