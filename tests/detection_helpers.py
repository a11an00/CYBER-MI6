"""Builders shared by the detection tests (not a test module itself)."""

from datetime import datetime, timedelta, timezone

from app.models import Event, EventIn

T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)  # fixed, safely in the past


def at(seconds: float = 0) -> datetime:
    return T0 + timedelta(seconds=seconds)


def syn(port, *, ip="10.0.0.5", dst="10.0.0.1", t=0.0) -> EventIn:
    return EventIn(type="network_connection", timestamp=at(t), source="sensor-1",
                   src_ip=ip, dst_ip=dst, dst_port=port)


def dns(name, *, ip="10.0.0.5", t=0.0) -> EventIn:
    return EventIn(type="dns_query", timestamp=at(t), source="sensor-1", src_ip=ip, dns_name=name)


def login_fail(user="admin", *, ip="10.0.0.9", t=0.0) -> EventIn:
    return EventIn(type="auth_failure", timestamp=at(t), source="webapp", src_ip=ip, username=user)


def request(path="/", *, ip="10.0.0.9", t=0.0) -> EventIn:
    return EventIn(type="http_request", timestamp=at(t), source="webapp", src_ip=ip,
                   http_method="GET", http_path=path, http_status=200)


def stored(event: EventIn, event_id: int) -> Event:
    """Turn an EventIn into a stored Event with the given id (no database needed)."""
    return Event.model_construct(**event.model_dump(), id=event_id, received_at=T0)


def with_ids(events, start=1) -> list[Event]:
    return [stored(e, start + i) for i, e in enumerate(events)]


def scan(ports, *, ip="10.0.0.5", dst="10.0.0.1", start=0.0, step=0.5) -> list[EventIn]:
    """One SYN per port, ``step`` seconds apart."""
    return [syn(p, ip=ip, dst=dst, t=start + i * step) for i, p in enumerate(ports)]
