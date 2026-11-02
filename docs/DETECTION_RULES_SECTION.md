<!--
PASTE GUIDE
Part A replaces the "## Detection rules" section of docs/ARCHITECTURE.md (from that heading down to the
line before "## Architectural decisions"). Part B is for config.py / .env.example / the events route.
Delete this comment when pasting.
-->

# Part A: replacement for the "Detection rules" section of docs/ARCHITECTURE.md

## Detection rules

Rules are transparent: each alert states which rule fired, the threshold, the numbers that triggered it and the evidence events. Thresholds are starting values stored in config (`.env`) and tuned with real data; none of them needs a code change.

| Rule | File | How it works (default values) | Severity | Known false positives |
|---|---|---|---|---|
| **Possible port scan** (`port_scan`) | `backend/detection/portscan.py` | ≥ 20 distinct destination ports from one source IP within 30 s (sliding window, repeats of a port don't count) | medium at 20 ports, high at 100, critical at 1000 | Vulnerability scanners, service discovery, P2P/game clients. Slow scans below the threshold are missed |
| **DNS anomaly** (`dns_anomaly`) | `backend/detection/dns_anomaly.py` | A label ≥ 40 characters, or Shannon entropy ≥ 3.8 bits/char on a label ≥ 16 characters | low for one indicator; medium if both, or a label over 63 characters | CDNs, tracking domains, cloud services with generated names. Random hex needs ≥ 40 characters to be caught (see below) |
| **Repeated auth failures** (`auth_failures`) | `backend/detection/auth_failures.py` | ≥ 5 failures from one IP **or** against one username within 300 s | medium at 5, high at 15 (or one account attacked from ≥ 3 IPs), critical at 50 | A user who forgot their password; many users behind one NAT address |
| **Suspicious web path** (`web_paths`) | `backend/detection/web_paths.py` | Pattern matching on the normalised request path (traversal, sensitive files, admin panels, SQL/script/command injection) | highest severity among matched categories | WordPress sites trigger `admin_panel_probe`; sites serving `.sql` downloads trigger `sensitive_file`. Query strings are removed before storage, so attacks only in `?x=` are invisible |

**How the engine works** (`backend/detection/engine.py`)
1. After an event is stored, `process_event` runs every enabled rule on it.
2. A rule that needs history (port scan, auth failures) says what it needs via `history_query`; the engine loads those events with `storage.events_in_window`. Windows end at the **event's own timestamp**, so delayed or replayed events are judged against the traffic around them.
3. A rule returns an alert candidate or `None`. Candidates are stored with `storage.upsert_alert`: the same rule + source IP inside `ALERT_COOLDOWN_SECONDS` updates one open alert (count and evidence grow, severity can only go up) instead of creating many. Resolved and false-positive alerts are not reopened; new activity creates a fresh alert.
4. A rule that crashes is logged and skipped; the other rules and ingestion carry on.

**What every alert stores** (the "explanation")
- Port scan and auth failures: `threshold`, `window_seconds`, `observed`, `observed_window_seconds`, plus the sample ports / triggers / counts. Auth failures adds `username` only when the account count was the stronger trigger.
- DNS anomaly: `label`, `entropy`, `max_label_length`, `min_entropy`, `reasons`, and up to 5 flagged labels.
- Web paths: `matched_categories`, `matches`, `path`, `normalized_path`.
- Evidence: `evidence_event_ids` (port scan: the first event for each distinct port, at most 100; auth failures: the latest 100 matching failures).

**Tuning guide** (week 6)
- Too many port-scan alerts from a busy client: raise `PORT_SCAN_PORTS`, or set `PORT_SCAN_PER_DESTINATION=true` so only many ports on one host count. Known scanners: `DETECTION_IGNORE_IPS`.
- DNS false positives from a CDN: add the domain to `DNS_ALLOWLIST`. Random-looking labels are judged by entropy, which depends on the alphabet and length (measured on random labels: letters+digits reach 3.8 at about 20 characters; hex only about 3.6 at 32 and 3.7 at 40). Lower `DNS_MIN_ENTROPY` to about 3.4 to catch shorter hex labels.
- Auth-failure noise from real users: raise `AUTH_FAIL_COUNT` or lengthen the window; add trusted office/VPN ranges to `DETECTION_IGNORE_IPS`.
- Switch a rule off entirely with `DETECTION_DISABLED_RULES=dns_anomaly,...`.
- To see what a threshold would do on real data, call `dns_anomaly.inspect_name(name)` or `web_paths.inspect_path(path)` on stored events and look at the numbers.

**Known limits of this design**
- In a flood, the engine loads at most 2000 earlier events per query, so counts are then a lower bound (`history_capped: true`). Measured cost: about 3 ms per event while a scan is in progress.
- Heuristics, not proof. Every alert is an indicator for a human to look at.

To add a rule: create a module in `backend/detection/` with `RULE_NAME` and `evaluate(event, recent_events, settings)` (plus `history_query` if it needs earlier events), add it to `RULES` in `engine.py`, and write a unit test with a should-fire and a should-not-fire case.

---

# Part B: wiring notes (for config.py, .env.example and the events route)

## Settings the rules already read (already in `backend/config.py`)
`port_scan_ports`, `port_scan_window_seconds`, `dns_max_label_length`, `dns_min_entropy`, `auth_fail_count`, `auth_fail_window_seconds`, `alert_cooldown_seconds`, `web_path_patterns`, `web_path_disabled_categories`.

## New optional settings (add to `Settings`; every one has a safe default inside the rules, so nothing breaks if you skip this)

```python
    # Detection tuning (all optional)
    port_scan_per_destination: bool = False       # count ports per destination host instead of across all hosts
    dns_entropy_min_label_length: int = Field(default=16, ge=2)   # shorter labels are never judged by entropy
    dns_allowlist: str = ""                       # comma-separated domains to skip, e.g. "cloudfront.net,akamaiedge.net"
    detection_ignore_ips: str = ""                # comma-separated IPs / CIDR ranges the rules skip, e.g. "10.0.0.2,192.168.1.0/24"
    detection_disabled_rules: str = ""            # comma-separated rule names to switch off, e.g. "dns_anomaly"
```

`.env.example` additions:

```
PORT_SCAN_PER_DESTINATION=false
DNS_ENTROPY_MIN_LABEL_LENGTH=16
DNS_ALLOWLIST=
DETECTION_IGNORE_IPS=
DETECTION_DISABLED_RULES=
```

## Calling the engine from the events route

```python
from starlette.concurrency import run_in_threadpool
from backend import storage
from backend.detection import engine

# after validating the batch in POST /api/events:
events = await run_in_threadpool(storage.insert_events, db, batch)
try:
    results = await run_in_threadpool(engine.process_events, db, events, settings)
except Exception:                      # never fail ingestion because detection failed
    log.exception("detection failed")
    results = []
for r in results:                      # r.created: True = new alert, False = existing alert updated
    await manager.broadcast({"kind": "alert", "data": r.alert.model_dump(mode="json")})
```

`settings` is the object from `get_settings()`; the rules read it by attribute name, so the pydantic `Settings` object works as is.

## One thing to check in `web_paths.py` (not changed here)
The dashboard's explanation panel (`frontend/src/lib/explain.ts`) reads `explanation.category` for web-path alerts, but `web_paths.py` writes `matched_categories` (a list) and no `category`. Without it the panel shows the path but no "Pattern category" line. One line in `_build_explanation` fixes it: add `"category": categories[0],` to the explanation dict.
