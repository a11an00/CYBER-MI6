import json
from types import SimpleNamespace

import pytest

from backend.detection import portscan
from backend.detection.portscan import RULE_NAME, evaluate, history_query
from backend.models import MAX_EXPLANATION_BYTES, AlertIn
from tests.detection_helpers import at, dns, scan, syn, with_ids

S = SimpleNamespace(port_scan_ports=20, port_scan_window_seconds=30)


def run(events, settings=S):
    """Evaluate the LAST event with all the others as history (what the engine does)."""
    stored = with_ids(events)
    return evaluate(stored[-1], stored, settings)


# ---- should NOT fire ---------------------------------------------------------
def test_one_below_threshold_does_not_fire():
    assert run(scan(range(1, 20))) is None  # 19 distinct ports


def test_same_port_repeated_does_not_fire():
    assert run([syn(443, t=i * 0.1) for i in range(200)]) is None


def test_ports_outside_the_window_do_not_count():
    old = scan(range(1, 20), start=0, step=0.1)  # 19 ports at t = 0..1.8
    assert run(old + [syn(9000, t=100)]) is None  # the 20th port arrives 100 s later


def test_other_sources_are_not_mixed_in():
    mixed = scan(range(1, 11), ip="10.0.0.5") + scan(range(11, 21), ip="10.0.0.6", start=5)
    assert run(mixed) is None


def test_other_event_types_are_ignored():
    assert evaluate(with_ids([dns("example.com")])[0], None, S) is None
    assert history_query(with_ids([dns("example.com")])[0], S) is None


def test_future_events_relative_to_this_one_are_not_counted():
    # this event is at t=0; the other 19 ports only appear after it (out-of-order arrival)
    events = with_ids([syn(1, t=0)] + scan(range(2, 21), start=5))
    assert evaluate(events[0], events, S) is None


# ---- should fire -------------------------------------------------------------
def test_fires_at_threshold_with_explanation():
    alert = run(scan(range(1, 21)))  # exactly 20 distinct ports in 9.5 s
    assert isinstance(alert, AlertIn) and alert.rule == RULE_NAME == "port_scan"
    assert alert.severity == "medium" and alert.src_ip == "10.0.0.5"
    e = alert.explanation
    # keys the dashboard reads
    assert (e["observed"], e["threshold"], e["window_seconds"]) == (20, 20, 30)
    assert e["observed_window_seconds"] == 10  # 9.5 s rounded
    assert e["sample_ports"][:3] == [1, 2, 3] and e["connection_attempts"] == 20
    assert e["top_destinations"] == [{"dst_ip": "10.0.0.1", "distinct_ports": 20}]
    assert e["history_capped"] is False
    assert "20 distinct ports in 30s" in alert.title


def test_evidence_is_one_event_per_distinct_port():
    events = scan(list(range(1, 21)) + [1, 2, 3])  # three repeats at the end
    alert = run(events)
    assert alert.evidence_event_ids == list(range(1, 21))  # first sighting of each port, repeats excluded


def test_evidence_is_capped_and_explanation_stays_small():
    alert = run(scan(range(1, 1001), step=0.01), SimpleNamespace(port_scan_ports=20, port_scan_window_seconds=30))
    assert len(alert.evidence_event_ids) == 100
    assert len(json.dumps(alert.explanation).encode()) <= MAX_EXPLANATION_BYTES
    assert len(alert.explanation["sample_ports"]) == 20


@pytest.mark.parametrize("ports,expected", [(20, "medium"), (99, "medium"), (100, "high"), (999, "high"), (1000, "critical")])
def test_severity_grows_with_count(ports, expected):
    assert run(scan(range(1, ports + 1), step=0.01)).severity == expected


def test_event_without_id_still_works_for_unit_use():
    events = scan(range(1, 21))
    alert = evaluate(events[-1], events[:-1], S)  # plain EventIn objects, no ids
    assert alert is not None and alert.evidence_event_ids == []


def test_current_event_counts_even_if_missing_from_history():
    stored = with_ids(scan(range(1, 21)))
    assert evaluate(stored[-1], stored[:-1], S) is not None  # 19 in history + the event itself


# ---- tuning without code changes ---------------------------------------------
def test_threshold_and_window_come_from_settings():
    events = scan(range(1, 6), step=1)
    assert run(events, SimpleNamespace(port_scan_ports=5, port_scan_window_seconds=30)) is not None
    assert run(events, SimpleNamespace(port_scan_ports=6, port_scan_window_seconds=30)) is None
    assert run(events, SimpleNamespace(port_scan_ports=5, port_scan_window_seconds=2)) is None  # too slow for a 2 s window


def test_settings_may_be_a_dict_or_none_and_defaults_apply():
    assert run(scan(range(1, 21)), {"PORT_SCAN_PORTS": 5}) is not None
    assert run(scan(range(1, 21)), None) is not None  # defaults: 20 ports / 30 s
    assert run(scan(range(1, 20)), None) is None


def test_bad_setting_values_fall_back_safely():
    # not a number -> the default threshold (20) applies
    assert run(scan(range(1, 21)), SimpleNamespace(port_scan_ports="lots")) is not None
    assert run(scan(range(1, 20)), SimpleNamespace(port_scan_ports="lots")) is None
    # a threshold below 2 would fire on every single event; it is raised to 2
    assert run([syn(80)], SimpleNamespace(port_scan_ports=0)) is None
    assert run(scan([80, 81]), SimpleNamespace(port_scan_ports=0)) is not None


def test_per_destination_mode_needs_many_ports_on_one_host():
    spread = []
    for i, dst in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]):
        spread += scan(range(i * 6 + 1, i * 6 + 7), dst=dst, start=i * 3)  # 24 ports, 6 per host
    assert run(spread, S) is not None  # across all destinations: 24 distinct ports
    per_host = SimpleNamespace(port_scan_ports=20, port_scan_window_seconds=30, port_scan_per_destination=True)
    assert run(spread, per_host) is None
    focused = scan(range(1, 21), dst="10.0.0.7")
    alert = run(focused, per_host)
    assert alert is not None and "on 10.0.0.7" in alert.title and alert.explanation["counting"] == "per destination host"


# ---- history query (what the engine loads) -----------------------------------
def test_history_query_asks_for_same_source_syn_events_in_the_window():
    ev = with_ids([syn(80, t=100)])[0]
    q = history_query(ev, S)
    assert q["type"] == "network_connection" and q["src_ip"] == "10.0.0.5"
    assert q["since"] == at(70) and q["until"] == at(100) and q["limit"] == portscan.HISTORY_LIMIT


def test_history_capped_flag_is_set_when_the_cap_is_hit():
    events = with_ids(scan([1 + i % 50 for i in range(portscan.HISTORY_LIMIT)], step=0.001))
    assert evaluate(events[-1], events, S).explanation["history_capped"] is True
