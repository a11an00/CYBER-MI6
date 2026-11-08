import json
import math
import random
from types import SimpleNamespace

import pytest

from app.detection.dns_anomaly import RULE_NAME, evaluate, inspect_name, shannon_entropy
from app.models import MAX_EXPLANATION_BYTES, MAX_TITLE_LEN, AlertIn
from tests.detection_helpers import dns, login_fail, with_ids

S = SimpleNamespace(dns_max_label_length=40, dns_min_entropy=3.8, dns_entropy_min_label_length=16)
RANDOM_ALNUM = "x9f3k2q8z7w1m5v4b6n0c8d2"  # 24 random-looking letters+digits
LONG_WORDS = "a" * 45  # long but perfectly regular


def run(name, settings=S, **kw):
    return evaluate(with_ids([dns(name, **kw)])[0], None, settings)


# ---- entropy -----------------------------------------------------------------
def test_entropy_known_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy("aabb") == pytest.approx(1.0)


def test_entropy_cannot_exceed_log2_of_length():
    rng = random.Random(1)
    for length in (4, 8, 16, 32):
        text = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(length))
        assert shannon_entropy(text) <= math.log2(length) + 1e-9


# ---- should NOT fire ---------------------------------------------------------
@pytest.mark.parametrize("name", [
    "example.com", "www.google.com", "mail.kabarak.ac.ke", "login.microsoftonline.com",
    "telemetry-prod-eu-west-1.example.com",          # long-ish but ordinary (entropy 3.49)
    "internationalization.example.org",              # 20 letters, entropy 2.95
    "a" * 39 + ".example.com",                        # one under the length limit
])
def test_ordinary_names_do_not_fire(name):
    assert run(name) is None


@pytest.mark.parametrize("name", [
    "1.0.0.127.in-addr.arpa", "b._dns-sd._udp.0.1.168.192.in-addr.arpa", "printer.local",
    "x9f3k2q8z7w1m5v4b6n0c8d2.local", "host.localdomain", "e.f.ip6.arpa",
])
def test_reverse_lookups_and_local_names_are_skipped(name):
    assert run(name) is None


def test_service_labels_starting_with_underscore_are_skipped():
    assert run("_x9f3k2q8z7w1m5v4b6n0c8d2._tcp.example.com") is None


def test_short_random_labels_do_not_trigger_entropy():
    assert run("x9f3k2.example.com") is None  # random but only 6 characters


def test_punycode_labels_are_not_judged_by_entropy():
    assert run("xn--80ak6aa92e.example.com") is None


def test_other_event_types_and_empty_names_are_ignored():
    assert evaluate(with_ids([login_fail()])[0], None, S) is None
    # EventIn refuses empty names, but the rule must still cope with any object it is handed
    for bad in ("", None, "."):
        ev = SimpleNamespace(type="dns_query", dns_name=bad, src_ip="10.0.0.5", id=1)
        assert evaluate(ev, None, S) is None


# ---- should fire -------------------------------------------------------------
def test_random_looking_label_fires_low():
    alert = run(f"{RANDOM_ALNUM}.example.net")
    assert isinstance(alert, AlertIn) and alert.rule == RULE_NAME == "dns_anomaly"
    assert alert.severity == "low" and alert.src_ip == "10.0.0.5" and alert.evidence_event_ids == [1]
    e = alert.explanation
    # keys the dashboard reads
    assert e["label"] == RANDOM_ALNUM and e["max_label_length"] == 40 and e["min_entropy"] == 3.8
    assert e["entropy"] >= 3.8 and e["reasons"] == ["high_entropy"]
    assert RANDOM_ALNUM in alert.title


def test_long_regular_label_fires_low_on_length_alone():
    alert = run(f"{LONG_WORDS}.example.com")
    assert alert.severity == "low" and alert.explanation["reasons"] == ["long_label"]


def test_long_and_random_label_is_medium():
    alert = run(f"{RANDOM_ALNUM}{RANDOM_ALNUM}.example.com")  # 48 chars, high entropy
    assert alert.severity == "medium" and set(alert.explanation["reasons"]) == {"long_label", "high_entropy"}


def test_label_over_the_dns_limit_is_medium():
    alert = run("a" * 64 + ".example.com", SimpleNamespace(dns_max_label_length=63))
    assert alert.severity == "medium" and "exceeds_dns_label_limit" in alert.explanation["reasons"]


def test_boundary_is_inclusive():
    assert run("a" * 40 + ".example.com") is not None
    assert run("a" * 39 + ".example.com") is None


def test_case_and_trailing_dot_are_normalised():
    alert = run(f"{RANDOM_ALNUM.upper()}.Example.NET.")
    assert alert is not None and alert.explanation["label"] == RANDOM_ALNUM


def test_worst_label_is_the_headline_and_all_are_listed():
    alert = run(f"{RANDOM_ALNUM}.{LONG_WORDS}.example.com")
    assert len(alert.explanation["flagged_labels"]) == 2
    assert alert.explanation["label"] in {RANDOM_ALNUM, LONG_WORDS}


def test_hostile_input_keeps_explanation_and_title_within_limits():
    name = ".".join(["q9w8e7r6t5y4u3i2o1p0a9s8d7f6g5h4j3k2l1"] * 6)[:253]
    alert = run(name)
    assert len(alert.explanation["flagged_labels"]) == 5
    assert len(json.dumps(alert.explanation).encode()) <= MAX_EXPLANATION_BYTES
    assert len(alert.title) <= MAX_TITLE_LEN


# ---- tuning without code changes ---------------------------------------------
def test_thresholds_come_from_settings():
    name = "a" * 25 + ".example.com"
    assert run(name, SimpleNamespace(dns_max_label_length=30)) is None
    assert run(name, SimpleNamespace(dns_max_label_length=25)) is not None
    assert run(f"{RANDOM_ALNUM}.example.net", SimpleNamespace(dns_min_entropy=4.5)) is None
    assert run("0123456789abcdef0123.example.net", SimpleNamespace(dns_min_entropy=3.0, dns_max_label_length=63)) is not None


def test_entropy_min_label_length_setting():
    name = f"{RANDOM_ALNUM}.example.net"
    assert run(name, SimpleNamespace(dns_entropy_min_label_length=30)) is None  # label has 24 chars
    assert run(name, SimpleNamespace(dns_entropy_min_label_length=20)) is not None


def test_allowlist_skips_a_domain_and_everything_below_it():
    settings = SimpleNamespace(dns_allowlist="cdn.example.net, Other.org")
    assert run(f"{RANDOM_ALNUM}.cdn.example.net", settings) is None
    assert run(f"{RANDOM_ALNUM}.sub.other.org", settings) is None
    assert run(f"{RANDOM_ALNUM}.example.net", settings) is not None   # parent domain is not allowlisted
    assert run(f"{RANDOM_ALNUM}.evilcdn.example.net", settings) is not None  # suffix must match a whole label
    assert run(f"{RANDOM_ALNUM}.cdn.example.net", {"DNS_ALLOWLIST": ["cdn.example.net"]}) is None


def test_defaults_apply_without_settings():
    assert run(f"{RANDOM_ALNUM}.example.net", None) is not None
    assert run("example.com", None) is None


# ---- inspect_name (used for tuning against real data) ------------------------
def test_inspect_name_reports_every_flagged_label():
    findings = inspect_name(f"{RANDOM_ALNUM}.{LONG_WORDS}.example.com")
    assert {f["label"] for f in findings} == {RANDOM_ALNUM, LONG_WORDS}
    assert all(set(f) == {"label", "length", "entropy", "reasons"} for f in findings)
    assert inspect_name("www.example.com") == []
