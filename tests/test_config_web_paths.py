"""Checks that backend/config.py and backend/detection/web_paths.py work together."""

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from backend.config import Settings, _load_web_path_patterns
from backend.detection.web_paths import DEFAULT_WEB_PATH_PATTERNS, evaluate
from backend.models import Event

NOW = datetime(2026, 10, 19, 9, 0, tzinfo=timezone.utc)


def ev(path):
    return Event(id=1, received_at=NOW, type="http_request", timestamp=NOW, source="webapp-1",
                 src_ip="198.51.100.23", http_method="GET", http_path=path)


def settings(**kw):
    return Settings(_env_file=None, **kw)


def write_json(tmp_path, data, name="patterns.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def test_defaults_when_nothing_configured():
    s = settings()
    assert s.web_path_patterns is None
    assert s.web_path_disabled_categories == []
    assert evaluate(ev("/.env"), settings=s) is not None


def test_pattern_file_replaces_defaults(tmp_path):
    f = write_json(tmp_path, {"secret_area": {"severity": "critical", "label": "secret area",
                                              "patterns": [r"^/internal-only(?:/|$)"]}})
    s = settings(web_path_patterns_file=f)
    alert = evaluate(ev("/internal-only/x"), settings=s)
    assert alert.severity == "critical"
    assert evaluate(ev("/.env"), settings=s) is None  # defaults replaced


def test_exported_defaults_file_behaves_like_builtin_defaults(tmp_path):
    f = write_json(tmp_path, DEFAULT_WEB_PATH_PATTERNS)
    s = settings(web_path_patterns_file=f)
    for path in ["/.env", "/a/../b", "/phpmyadmin/", "/x union select y", "/x/${jndi:ldap://a/b}"]:
        assert evaluate(ev(path), settings=s).severity == evaluate(ev(path)).severity


def test_disabled_categories_parsed_from_comma_separated_text():
    s = settings(web_path_disabled=" Admin_Panel_Probe , xss ,,")
    assert s.web_path_disabled_categories == ["admin_panel_probe", "xss"]
    assert evaluate(ev("/wp-login.php"), settings=s) is None
    assert evaluate(ev("/.env"), settings=s) is not None


def test_disabled_categories_from_environment_variable(monkeypatch):
    monkeypatch.setenv("WEB_PATH_DISABLED", "admin_panel_probe")
    s = Settings(_env_file=None)
    assert evaluate(ev("/wp-login.php"), settings=s) is None


@pytest.mark.parametrize(
    "content, fragment",
    [
        ("not json", "cannot be loaded"),
        ("[]", "non-empty JSON object"),
        ('{"c": "text"}', "must be an object"),
        ('{"c": {"severity": "huge", "patterns": ["x"]}}', "severity"),
        ('{"c": {"patterns": []}}', "patterns"),
        ('{"c": {"patterns": ["([bad"]}}', "invalid regex"),
    ],
)
def test_bad_pattern_file_fails_at_startup(tmp_path, content, fragment):
    p = tmp_path / "bad.json"
    p.write_text(content, encoding="utf-8")
    with pytest.raises(ValidationError, match=fragment):
        settings(web_path_patterns_file=str(p))


def test_missing_pattern_file_fails_at_startup(tmp_path):
    with pytest.raises(ValidationError, match="cannot be loaded"):
        settings(web_path_patterns_file=str(tmp_path / "nope.json"))


def test_file_is_read_once_and_cached(tmp_path):
    f = write_json(tmp_path, {"c": {"patterns": [r"^/x$"]}})
    _load_web_path_patterns.cache_clear()
    s = settings(web_path_patterns_file=f)
    first = s.web_path_patterns
    assert s.web_path_patterns is first  # same object, no re-read per event


@pytest.mark.parametrize(
    "field, value",
    [("port_scan_ports", 1), ("port_scan_window_seconds", 0), ("dns_max_label_length", 5),
     ("dns_max_label_length", 64), ("dns_min_entropy", -1), ("dns_min_entropy", 9),
     ("auth_fail_count", 1), ("alert_cooldown_seconds", -1), ("ingest_max_batch", 501)],
)
def test_threshold_bounds_are_enforced(field, value):
    with pytest.raises(ValidationError):
        settings(**{field: value})


def test_original_defaults_are_unchanged():
    s = settings()
    assert (s.port_scan_ports, s.port_scan_window_seconds, s.dns_max_label_length, s.dns_min_entropy,
            s.auth_fail_count, s.auth_fail_window_seconds, s.alert_cooldown_seconds) == (20, 30, 40, 3.8, 5, 300, 300)
    assert s.origins_list == []