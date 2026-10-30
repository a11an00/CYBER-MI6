"""Suspicious web request path rule (``app/detection/web_paths.py``).

A single-event rule: every ``http_request`` event is checked on its own, so no
time window or recent-event history is needed. It is pure logic: no database,
no network, no clock, and no FastAPI imports.

Interface (shared by all detection rules)::

    evaluate(event, recent_events=None, settings=None) -> AlertIn | None

* ``event``          an ``Event`` (stored, has ``id``) or an ``EventIn``.
* ``recent_events``  accepted for interface uniformity, unused by this rule.
* ``settings``       an object with attributes or a mapping (see "Settings").
* returns            ``None`` when nothing matched, otherwise one ``AlertIn``
                     candidate. The engine applies severity escalation and
                     de-duplication (rule + source IP + cooldown).

How matching works
------------------
1. ``normalize_path`` turns the stored path into a canonical form so that
   common evasion tricks do not hide an attack: repeated percent-decoding
   (``%252e`` -> ``%2e`` -> ``.``), IIS ``%uXXXX`` escapes, NFKC Unicode
   folding (full-width characters), backslashes, ``+`` as space, NUL and
   control characters, doubled slashes and ``/./`` segments, lower-casing.
2. Every enabled pattern is searched in the normalized path. All matching
   categories are listed in the explanation; the alert severity is the highest
   severity among them.

Settings (names for ``config.py``; all optional)
------------------------------------------------
``web_path_patterns``             dict ``{category: {"severity", "label", "patterns"}}``.
                                  Replaces the built-in defaults when provided.
                                  Env vars cannot hold this nicely, so load it
                                  from a JSON file in ``config.py``.
``web_path_disabled_categories``  list of category names to switch off (for example
                                  ``["admin_panel_probe"]`` on a WordPress site).

``DEFAULT_WEB_PATH_PATTERNS`` below exists only so the rule works before
``config.py`` is ready. Once settings exist, move it into the JSON file and the
module falls back to it only if the setting is missing.

Known limitations (also documented in docs/ARCHITECTURE.md)
------------------------------------------------------------
* ``EventIn`` removes the query string and fragment before storage, so attacks
  that live only in ``?query=...`` are invisible to this rule. Only attack text
  that appears inside the path itself can match.
* Pattern matching is heuristic. Expect false positives (for example a real
  WordPress site triggers ``admin_panel_probe``, a site that serves ``.sql``
  downloads triggers ``sensitive_file``).
* HTTPS packet capture cannot reveal paths; events must come from our own app.
"""

from __future__ import annotations

import json
import logging
import re
import unicodedata
from collections.abc import Mapping, Sequence
from functools import lru_cache
from typing import Any
from urllib.parse import unquote

from backend.models import MAX_EXPLANATION_BYTES, MAX_TITLE_LEN, SEVERITIES, SEVERITY_RANK, AlertIn

logger = logging.getLogger(__name__)

__all__ = [
    "RULE_NAME",
    "DEFAULT_WEB_PATH_PATTERNS",
    "evaluate",
    "inspect_path",
    "normalize_path",
]

RULE_NAME = "web_paths"

# Normalisation limits (hard caps so hostile input cannot cost much CPU/memory).
MAX_DECODE_ROUNDS = 3
MAX_NORMALIZED_LEN = 4096
# Explanation limits.
MAX_MATCHES_IN_EXPLANATION = 5
MAX_PATH_IN_EXPLANATION = 200
MAX_MATCH_TEXT = 80

# ---------------------------------------------------------------------------
# Built-in default patterns (fallback only; see module docstring).
# Patterns run case-insensitively against the NORMALIZED path (lower-case,
# decoded, forward slashes, '+' turned into a space). Keep them simple and
# bounded: no nested quantifiers, so hostile input cannot cause slow matching.
# ---------------------------------------------------------------------------
DEFAULT_WEB_PATH_PATTERNS: dict[str, dict[str, Any]] = {
    "path_traversal": {
        "severity": "high",
        "label": "path traversal",
        "patterns": [
            r"(?:^|/)\.\.(?:;[^/]*)?(?:/|$)",
            r"/etc/(?:passwd|shadow|group|hosts|sudoers)\b",
            r"/proc/self/(?:environ|cmdline|fd)",
            r"(?:^|/)(?:boot|win)\.ini(?:$|/)",
            r"windows/(?:system32|win\.ini)",
        ],
    },
    "sensitive_file": {
        "severity": "high",
        "label": "sensitive file probe",
        "patterns": [
            r"(?:^|/)\.env(?:\.[a-z0-9_-]+)?(?:$|/)",
            r"(?:^|/)\.(?:git|svn|hg)(?:$|/)",
            r"(?:^|/)\.(?:htaccess|htpasswd|ds_store|bash_history|aws|ssh)(?:$|/)",
            r"(?:^|/)wp-config\.php(?:\.[a-z0-9~]+)?$",
            r"(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$",
            r"\.(?:sql|bak|old|orig|swp|sqlite3?|dump)$",
        ],
    },
    "admin_panel_probe": {
        "severity": "medium",
        "label": "admin panel probe",
        "patterns": [
            r"(?:^|/)(?:phpmyadmin|pma|myadmin|adminer)(?:\.php)?(?:$|/)",
            r"(?:^|/)(?:wp-admin|wp-login\.php|xmlrpc\.php)(?:$|/)",
            r"(?:^|/)manager/html(?:$|/)",
            r"(?:^|/)(?:server-status|server-info)(?:$|/)",
            r"(?:^|/)actuator/(?:env|heapdump|beans|mappings|configprops)(?:$|/)",
            r"(?:^|/)cgi-bin/",
        ],
    },
    "sql_injection": {
        "severity": "high",
        "label": "SQL injection pattern",
        "patterns": [
            r"['\"`]\s*(?:or|and)\s+[\w'\"`]+\s*(?:=|like)\s*[\w'\"`]+",
            r"\bunion[\s/*]+(?:all[\s/*]+)?select\b",
            r"\b(?:or|and)\s+\d+\s*=\s*\d+\b",
            r"(?:;\s*|--\s+|/\*\s*)(?:drop|delete\s+from|insert\s+into|update\s+\w+\s+set|truncate|alter\s+table|exec(?:ute)?)\b",
            r"\b(?:sleep|benchmark|pg_sleep)\s*\(\s*['\"\d]|\bwaitfor\s+delay\b",
            r"\binformation_schema\b|\bxp_cmdshell\b|\bload_file\s*\(|\binto\s+(?:out|dump)file\b",
        ],
    },
    "xss": {
        "severity": "high",
        "label": "cross-site scripting pattern",
        "patterns": [
            r"<\s*/?\s*script\b",
            r"\bjavascript\s*:",
            r"\bon(?:error|load|click|mouseover|focus|toggle|submit)\s*=",
            r"<\s*(?:iframe|svg|object|embed|img|body)\b",
            r"\bdocument\.(?:cookie|location|write)\b",
        ],
    },
    "command_injection": {
        "severity": "critical",
        "label": "command/code injection pattern",
        "patterns": [
            r"(?:;|\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|zsh|python3?|perl|php|powershell|cmd)(?:\s|$|/|\)|;)",
            r"/bin/(?:ba|z|da|k)?sh\b",
            r"\b(?:cmd|powershell)\.exe\b",
            r"\$\{\s*(?:jndi|env|sys|lower|upper)\s*:",
            r"\(\)\s*\{\s*[:;]",
        ],
    },
}

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_IIS_UNICODE = re.compile(r"%u([0-9a-fA-F]{4})")
_MULTI_SLASH = re.compile(r"/{2,}")


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
def _iis_unicode(match: re.Match[str]) -> str:
    return chr(int(match.group(1), 16))


def normalize_path(path: str | None) -> str:
    """Return the canonical form of ``path`` used for matching (never raises)."""
    if not isinstance(path, str) or not path:
        return ""
    p = path[:MAX_NORMALIZED_LEN]
    # Repeated percent-decoding catches double/triple encoding (%252e%252e).
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = unquote(_IIS_UNICODE.sub(_iis_unicode, p))
        if decoded == p:
            break
        p = decoded[:MAX_NORMALIZED_LEN]
    p = unicodedata.normalize("NFKC", p)  # full-width '<' etc. become ASCII
    p = _CONTROL.sub("", p)  # %00 truncation tricks, stray control characters
    p = p.replace("\\", "/").replace("+", " ")
    p = _MULTI_SLASH.sub("/", p)
    for _ in range(8):  # collapse /./ segments (bounded, so no endless loop)
        collapsed = p.replace("/./", "/")
        if collapsed == p:
            break
        p = collapsed
    return p.lower()[:MAX_NORMALIZED_LEN]


# ---------------------------------------------------------------------------
# Settings helpers
# ---------------------------------------------------------------------------
def _get_setting(settings: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` from a mapping or an object (lower- or upper-case)."""
    if settings is None:
        return default
    for key in (name, name.upper()):
        if isinstance(settings, Mapping):
            if key in settings and settings[key] is not None:
                return settings[key]
        else:
            value = getattr(settings, key, None)
            if value is not None:
                return value
    return default


def _freeze(spec: Mapping[str, Any], disabled: frozenset[str]) -> tuple:
    """Turn the pattern config into a hashable value (so compiled regexes can be cached)."""
    items = []
    for name, cfg in spec.items():
        if str(name).lower() in disabled or not isinstance(cfg, Mapping):
            continue
        patterns = cfg.get("patterns") or ()
        if isinstance(patterns, str):
            patterns = (patterns,)
        severity = cfg.get("severity", "medium")
        if severity not in SEVERITIES:
            logger.warning("web_paths: category %r has invalid severity %r; using 'medium'", name, severity)
            severity = "medium"
        label = _CONTROL.sub(" ", str(cfg.get("label") or str(name).replace("_", " ")))
        items.append((str(name), severity, label, tuple(str(p) for p in patterns)))
    return tuple(items)


@lru_cache(maxsize=16)
def _compile(frozen: tuple) -> tuple:
    """Compile every pattern once. Invalid regexes are skipped, never fatal."""
    compiled = []
    for name, severity, label, patterns in frozen:
        rxs = []
        for pat in patterns:
            try:
                rxs.append((pat, re.compile(pat, re.IGNORECASE)))
            except re.error as exc:
                logger.warning("web_paths: skipping invalid pattern in %r: %s (%s)", name, pat, exc)
        if rxs:
            compiled.append((name, severity, label, tuple(rxs)))
    return tuple(compiled)


def _compiled_for(settings: Any) -> tuple:
    spec = _get_setting(settings, "web_path_patterns")
    if not isinstance(spec, Mapping) or not spec:
        if spec not in (None, {}, ()):
            logger.warning("web_paths: web_path_patterns must be a mapping; using built-in defaults")
        spec = DEFAULT_WEB_PATH_PATTERNS
    disabled = _get_setting(settings, "web_path_disabled_categories", ())
    if isinstance(disabled, str):
        disabled = (disabled,)
    disabled_set = frozenset(str(d).lower() for d in disabled) if isinstance(disabled, Sequence) else frozenset()
    return _compile(_freeze(spec, disabled_set))


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
def inspect_path(path: str | None, settings: Any = None) -> tuple[str, list[dict[str, Any]]]:
    """Return ``(normalized_path, matches)``.

    Each match is ``{"category", "severity", "label", "pattern", "matched_text"}``.
    Useful on its own for tests and for tuning patterns against real data.
    """
    normalized = normalize_path(path)
    if not normalized:
        return "", []
    matches: list[dict[str, Any]] = []
    for name, severity, label, rxs in _compiled_for(settings):
        for pattern, rx in rxs:
            m = rx.search(normalized)
            if m:
                matches.append(
                    {
                        "category": name,
                        "severity": severity,
                        "label": label,
                        "pattern": pattern,
                        "matched_text": m.group(0)[:MAX_MATCH_TEXT],
                    }
                )
    return normalized, matches


def _build_explanation(event: Any, raw_path: str, normalized: str, matches: list[dict[str, Any]]) -> dict[str, Any]:
    categories = list(dict.fromkeys(m["category"] for m in matches))
    explanation: dict[str, Any] = {
        "description": "Request path matched one or more suspicious-path patterns",
        "threshold": 1,  # a single matching pattern is enough (no counting window)
        "observed_count": len(matches),  # number of patterns that matched
        "matched_categories": categories,
        "matches": [
            {k: m[k] for k in ("category", "pattern", "matched_text")}
            for m in matches[:MAX_MATCHES_IN_EXPLANATION]
        ],
        "http_method": getattr(event, "http_method", None),
        "http_status": getattr(event, "http_status", None),
        "path": raw_path[:MAX_PATH_IN_EXPLANATION],
        "normalized_path": normalized[:MAX_PATH_IN_EXPLANATION],
        "was_normalized": normalized != raw_path.lower(),
        "note": "Query strings are removed before storage; only the path itself is inspected.",
    }
    # Guarantee the AlertIn size limit even for hostile, very long input.
    while len(json.dumps(explanation).encode()) > MAX_EXPLANATION_BYTES and explanation["matches"]:
        explanation["matches"].pop()
    if len(json.dumps(explanation).encode()) > MAX_EXPLANATION_BYTES:
        explanation["path"] = explanation["path"][:50]
        explanation["normalized_path"] = explanation["normalized_path"][:50]
    return explanation


def _title(src_ip: str | None, matches: list[dict[str, Any]]) -> str:
    labels = ", ".join(dict.fromkeys(m["label"] for m in matches))
    title = f"Suspicious web request path from {src_ip or 'unknown source'}: {labels}"
    return _CONTROL.sub(" ", title)[:MAX_TITLE_LEN]


# ---------------------------------------------------------------------------
# Rule entry point
# ---------------------------------------------------------------------------
def evaluate(event: Any, recent_events: Sequence[Any] | None = None, settings: Any = None) -> AlertIn | None:
    """Check one ``http_request`` event. ``recent_events`` is unused (single-event rule)."""
    if getattr(event, "type", None) != "http_request":
        return None
    raw_path = getattr(event, "http_path", None)
    if not isinstance(raw_path, str) or not raw_path:
        return None

    normalized, matches = inspect_path(raw_path, settings)
    if not matches:
        return None

    severity = max((m["severity"] for m in matches), key=lambda s: SEVERITY_RANK[s])
    event_id = getattr(event, "id", None)
    evidence = [event_id] if isinstance(event_id, int) and not isinstance(event_id, bool) and event_id >= 1 else []
    src_ip = getattr(event, "src_ip", None)

    return AlertIn(
        rule=RULE_NAME,
        severity=severity,
        title=_title(src_ip, matches),
        src_ip=src_ip,
        evidence_event_ids=evidence,
        explanation=_build_explanation(event, raw_path, normalized, matches),
    )