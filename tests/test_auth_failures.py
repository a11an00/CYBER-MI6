import json
from types import SimpleNamespace

import pytest

from backend.detection import auth_failures
from backend.detection.auth_failures import RULE_NAME, evaluate, history_query
from backend.models import MAX_EXPLANATION_BYTES, MAX_TITLE_LEN, AlertIn
from tests.detection_helpers import at, login_fail, syn, with_ids

S = SimpleNamespace(auth_fail_count=5, auth_fail_window_seconds=300)


def run(events, settings=S):
    """Evaluate the LAST event with all of them as history (what the engine does)."""
    stored = with_ids(events)
    return evaluate(stored[-1], stored, settings)


def fails(n, *, user="admin", ip="10.0.0.9", start=0.0, step=10.0):
    return [login_fail(user, ip=ip, t=start + i * step) for i in range(n)]


# ---- should NOT fire ---------------------------------------------------------
def test_one_below_threshold_does_not_fire():
    assert run(fails(4)) is None


def test_failures_outside_the_window_do_not_count():
    assert run(fails(4, start=0) + [login_fail(t=1000)]) is None  # 4 old + 1 new, 1000 s later


def test_different_ips_and_different_users_are_not_mixed():
    mixed = (fails(2, user="a", ip="10.0.0.1") + fails(2, user="b", ip="10.0.0.2", start=1)
             + fails(2, user="c", ip="10.0.0.3", start=2))
    assert run(mixed) is None


def test_other_event_types_are_ignored():
    ev = with_ids([syn(80)])[0]
    assert evaluate(ev, None, S) is None and history_query(ev, S) is None


# ---- should fire -------------------------------------------------------------
def test_fires_at_threshold_by_ip():
    alert = run(fails(5))  # 5 failures from one IP and for one username
    assert isinstance(alert, AlertIn) and alert.rule == RULE_NAME == "auth_failures"
    assert alert.severity == "medium" and alert.src_ip == "10.0.0.9"
    assert alert.evidence_event_ids == [1, 2, 3, 4, 5]
    e = alert.explanation
    # keys the dashboard reads
    assert (e["observed"], e["threshold"], e["window_seconds"], e["observed_window_seconds"]) == (5, 5, 300, 40)
    assert "username" not in e  # IP wins ties, so the dashboard says "from <ip>"
    assert e["triggers"] == ["ip", "username"] and e["failures_for_username"]["username"] == "admin"
    assert "from 10.0.0.9" in alert.title and "5 in 300s" in alert.title


def test_fires_by_username_when_attack_is_spread_over_many_ips():
    spread = [login_fail("root", ip=f"10.0.0.{i}", t=i) for i in range(1, 6)]  # 1 failure per IP
    alert = run(spread)
    e = alert.explanation
    assert alert is not None and e["triggers"] == ["username"]
    assert e["username"] == "root" and e["observed"] == 5  # dashboard says "for root"
    assert e["failures_for_username"] == {"username": "root", "count": 5, "distinct_ips": 5}
    assert e["failures_from_ip"]["count"] == 1
    assert alert.severity == "high"  # one account attacked from >= 3 IPs
    assert "'root'" in alert.title
    assert alert.src_ip == "10.0.0.5"  # the IP of the failure that triggered it


def test_fires_by_ip_when_attacker_tries_many_usernames():
    guessing = [login_fail(f"user{i}", t=i) for i in range(6)]
    alert = run(guessing)
    assert alert.explanation["triggers"] == ["ip"] and alert.explanation["observed"] == 6
    assert "username" not in alert.explanation


def test_ip_that_is_stronger_than_username_is_the_headline():
    events = fails(3, user="admin") + [login_fail(f"u{i}", t=40 + i) for i in range(4)] + [login_fail("admin", t=60)]
    alert = run(events)  # 8 failures from the IP, 4 for 'admin'
    assert alert.explanation["triggers"] == ["ip"] and alert.explanation["observed"] == 8


@pytest.mark.parametrize("count,expected", [(5, "medium"), (14, "medium"), (15, "high"), (49, "high"), (50, "critical")])
def test_severity_grows_with_count(count, expected):
    assert run(fails(count, step=1)).severity == expected


def test_evidence_is_capped_to_the_latest_100():
    alert = run(fails(150, step=1))
    assert len(alert.evidence_event_ids) == 100 and alert.evidence_event_ids[-1] == 150


def test_hostile_username_keeps_title_and_explanation_within_limits():
    nasty = "x" * 128
    alert = run([login_fail(nasty, ip=f"10.0.1.{i}", t=i) for i in range(1, 6)])
    assert len(alert.title) <= MAX_TITLE_LEN and "..." in alert.title
    assert len(json.dumps(alert.explanation).encode()) <= MAX_EXPLANATION_BYTES


def test_event_without_id_still_works_for_unit_use():
    events = fails(5)
    alert = evaluate(events[-1], events[:-1], S)
    assert alert is not None and alert.evidence_event_ids == []


def test_usernames_are_compared_exactly():
    mixed = [login_fail(u, ip=f"10.0.0.{i}", t=i) for i, u in enumerate(["Admin", "admin", "ADMIN", "admin ", "Admin"], 1)]
    assert run(mixed) is None  # no single spelling reaches 5


# ---- tuning without code changes ---------------------------------------------
def test_threshold_and_window_come_from_settings():
    assert run(fails(3), SimpleNamespace(auth_fail_count=3, auth_fail_window_seconds=300)) is not None
    assert run(fails(3), SimpleNamespace(auth_fail_count=4, auth_fail_window_seconds=300)) is None
    assert run(fails(3, step=100), SimpleNamespace(auth_fail_count=3, auth_fail_window_seconds=100)) is None  # span 200 s
    assert run(fails(5), None) is not None  # defaults: 5 failures / 300 s
    assert run(fails(4), None) is None


def test_bad_values_fall_back_safely():
    assert run(fails(5), SimpleNamespace(auth_fail_count="many")) is not None  # default 5
    assert run([login_fail()], SimpleNamespace(auth_fail_count=0)) is None  # raised to 2


# ---- history query (what the engine loads) -----------------------------------
def test_history_query_asks_for_this_ip_and_this_username():
    ev = with_ids([login_fail("alice", ip="10.0.0.9", t=400)])[0]
    by_ip, by_user = history_query(ev, S)
    assert by_ip["src_ip"] == "10.0.0.9" and "username" not in by_ip
    assert by_user["username"] == "alice" and "src_ip" not in by_user
    for q in (by_ip, by_user):
        assert q["type"] == "auth_failure" and q["since"] == at(100) and q["until"] == at(400)
        assert q["limit"] == auth_failures.HISTORY_LIMIT
