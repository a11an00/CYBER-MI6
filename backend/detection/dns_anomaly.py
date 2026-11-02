"""Unusual DNS label rule (``backend/detection/dns_anomaly.py``).

Idea: malware that tunnels data over DNS, or uses generated domain names (DGA),
produces labels (the dot-separated parts of a name) that are long and/or look
random. Two simple, explainable checks per label:

* length    label length >= ``dns_max_label_length``
* entropy   Shannon entropy of the label's characters >= ``dns_min_entropy``,
            counted only for labels of at least ``dns_entropy_min_label_length``
            characters (a short label cannot be "random enough" to mean anything:
            entropy can never exceed log2(length))

A single-event rule: each ``dns_query`` is judged on its own, so there is no
``history_query``. Repeated hits from one source are merged by the engine's
de-duplication (same rule + source IP inside the cooldown).

Interface (shared by all rules)::

    evaluate(event, recent_events=None, settings=None) -> AlertIn | None

Settings (all optional; names match ``.env``)
---------------------------------------------
``dns_max_label_length``          default 40
``dns_min_entropy``               default 3.8 (bits per character)
``dns_entropy_min_label_length``  default 16
``dns_allowlist``                 comma-separated domains to skip, e.g.
                                  ``"akamaiedge.net, cloudfront.net"`` (matches the
                                  domain and everything below it)

Always skipped: reverse lookups and local names (``*.arpa``, ``*.local``,
``*.localhost``, ``*.localdomain``), labels starting with ``_`` (service records
such as ``_dmarc``) and ``xn--`` labels for the entropy check (internationalised names).

Severity: ``low`` when one indicator fires; ``medium`` when a label is both long and
high-entropy, or longer than the 63 characters DNS allows.

Known limitations
-----------------
* CDNs, tracking domains and some cloud services use long random-looking labels;
  expect false positives. Add them to ``dns_allowlist`` or raise the thresholds.
* Entropy depends on the alphabet and length (measured on random labels): letters+digits
  (base32/base36, typical for DGAs and tunnels) reach the default 3.8 at about 20 characters;
  random HEX scores only about 3.6 at 32 and 3.7 at 40 characters, so hex labels are caught
  by the length check (40+) rather than entropy. Lower ``dns_min_entropy`` to about 3.4 to
  catch 24-32 character hex labels, at the cost of more false positives.
* Low-and-slow tunnelling with short labels is not detected.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from typing import Any

from backend.detection.common import (
    csv_setting,
    evidence_ids,
    fit_explanation,
    float_setting,
    int_setting,
)
from backend.models import MAX_TITLE_LEN, AlertIn

__all__ = ["RULE_NAME", "evaluate", "inspect_name", "shannon_entropy"]

RULE_NAME = "dns_anomaly"
EVENT_TYPE = "dns_query"

DEFAULT_MAX_LABEL_LENGTH = 40
DEFAULT_MIN_ENTROPY = 3.8
DEFAULT_ENTROPY_MIN_LABEL_LENGTH = 16
DNS_LABEL_LIMIT = 63  # the DNS protocol maximum for one label
BUILTIN_IGNORED_SUFFIXES = ("arpa", "local", "localhost", "localdomain")
MAX_LABEL_SHOWN = 80
MAX_FLAGGED_LABELS = 5


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0.0 for an empty string)."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def _under(name: str, domains: Sequence[str]) -> bool:
    return any(name == d or name.endswith("." + d) for d in domains)


def inspect_name(
    name: str,
    *,
    max_label_length: int = DEFAULT_MAX_LABEL_LENGTH,
    min_entropy: float = DEFAULT_MIN_ENTROPY,
    entropy_min_label_length: int = DEFAULT_ENTROPY_MIN_LABEL_LENGTH,
) -> list[dict[str, Any]]:
    """Return one finding per suspicious label: ``{label, length, entropy, reasons}``.

    Useful on its own for tuning thresholds against real DNS data.
    """
    findings = []
    for label in name.lower().split("."):
        if not label or label.startswith("_"):
            continue
        entropy = shannon_entropy(label)
        reasons = []
        if len(label) >= max_label_length:
            reasons.append("long_label")
        if len(label) >= entropy_min_label_length and entropy >= min_entropy and not label.startswith("xn--"):
            reasons.append("high_entropy")
        if len(label) > DNS_LABEL_LIMIT:
            reasons.append("exceeds_dns_label_limit")
        if reasons:
            findings.append(
                {"label": label[:MAX_LABEL_SHOWN], "length": len(label), "entropy": round(entropy, 2), "reasons": reasons}
            )
    return findings


def _severity(findings: list[dict[str, Any]]) -> str:
    for f in findings:
        if "exceeds_dns_label_limit" in f["reasons"] or {"long_label", "high_entropy"} <= set(f["reasons"]):
            return "medium"
    return "low"


def evaluate(event: Any, recent_events: Sequence[Any] | None = None, settings: Any = None) -> AlertIn | None:
    """Check one ``dns_query`` event. ``recent_events`` is unused (single-event rule)."""
    if getattr(event, "type", None) != EVENT_TYPE:
        return None
    name = getattr(event, "dns_name", None)
    if not isinstance(name, str) or not name:
        return None
    name = name.lower().rstrip(".")

    if _under(name, BUILTIN_IGNORED_SUFFIXES) or _under(name, csv_setting(settings, "dns_allowlist")):
        return None

    max_len = int_setting(settings, "dns_max_label_length", DEFAULT_MAX_LABEL_LENGTH, minimum=2)
    min_entropy = float_setting(settings, "dns_min_entropy", DEFAULT_MIN_ENTROPY)
    entropy_min_len = int_setting(settings, "dns_entropy_min_label_length", DEFAULT_ENTROPY_MIN_LABEL_LENGTH, minimum=2)

    findings = inspect_name(
        name, max_label_length=max_len, min_entropy=min_entropy, entropy_min_label_length=entropy_min_len
    )
    if not findings:
        return None

    # Headline label: the one with most reasons, then the longest.
    worst = max(findings, key=lambda f: (len(f["reasons"]), f["length"]))
    explanation = {
        "description": "A DNS name contains a label that is unusually long or looks randomly generated",
        # Keys below are read by the dashboard's "Why this fired" panel.
        "label": worst["label"],
        "entropy": worst["entropy"],
        "max_label_length": max_len,
        "min_entropy": min_entropy,
        # Extra detail.
        "entropy_min_label_length": entropy_min_len,
        "reasons": worst["reasons"],
        "dns_name": name[:253],
        "flagged_labels": findings[:MAX_FLAGGED_LABELS],
    }
    shown = worst["label"] if len(worst["label"]) <= 40 else worst["label"][:37] + "..."
    title = f"Unusual DNS label from {event.src_ip}: {shown}"
    return AlertIn(
        rule=RULE_NAME,
        severity=_severity(findings),
        title=title[:MAX_TITLE_LEN],
        src_ip=event.src_ip,
        evidence_event_ids=evidence_ids([event]),
        explanation=fit_explanation(explanation),
    )
