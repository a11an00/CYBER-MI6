# CYBER-MI6 — Architecture

## Data flow

```
Windows/Linux computer                         Team-owned web application
  Scapy sensor                                  security-event helper
  (TCP SYN + DNS metadata)                       (auth failures, HTTP metadata)
           |                                                |
           +---------------------- HTTPS/HTTP API -----------+
                                  |
                           FastAPI ingestion
                                  |
                         Event validation/storage
                                  |
                          Rule-based detection
                                  |
                            SQLite database
                                  |
                    WebSocket + REST API endpoints
                                  |
                        Browser security dashboard
```

1. The Scapy sensor (network) and the web app helper (application) send events to `POST /api/events`.
2. FastAPI validates each event with Pydantic and stores it in SQLite.
3. The rule engine evaluates the new event against recent events. A match creates an alert.
4. New events and alerts are pushed to connected dashboards over WebSocket. The dashboard also reads history through REST endpoints.

---

## Event format

Every event shares common fields; the `type` decides which extra fields are used.

| Field | Description |
|---|---|
| `type` | `network_connection`, `dns_query`, `auth_failure`, `http_request` |
| `timestamp` | UTC, ISO 8601 |
| `source` | Name of the sensor or application that reported it |
| `src_ip` | Source IP |
| `dst_ip` | Destination IP (network events) |
| `dst_port` | Destination port (`network_connection`) |
| `protocol` | `tcp` for the SYN sensor |
| `dns_name` | Queried name (`dns_query`) |
| `username` | Account name or identifier (`auth_failure`) |
| `http_method`, `http_path`, `http_status` | Request metadata (`http_request`) |
| `user_agent` | Optional |
| `details` | Optional small object for extra context |

Rules for events:
- **No packet payloads, request bodies, passwords, cookies, or tokens.** Metadata only.
- Reject oversized or malformed events with a clear 422 response.
- Redact query strings from `http_path` before sending.

---

## Database schema (SQLite)

| Table | Key columns |
|---|---|
| `events` | id, type, timestamp, source, src_ip, dst_ip, dst_port, dns_name, username, http_path, details (JSON) |
| `alerts` | id, created_at, rule, severity, title, status, src_ip, evidence_event_ids (JSON), count, updated_at |
| `alert_notes` (optional) | id, alert_id, note, created_at |

- Add indexes on `timestamp`, `src_ip`, and `type`.
- Enable WAL mode for better concurrent reads while writing.
- Add a retention job that deletes events older than a configured number of days.

---

## WebSocket message format

```json
{ "kind": "alert", "data": { "id": 17, "rule": "port_scan", "severity": "medium",
  "title": "Possible port scan from 192.168.1.25", "status": "new" } }
```

```json
{ "kind": "event", "data": { ... event object ... } }
```

---

## Detection rules

Rules are transparent: each alert states which rule fired, the threshold, and the evidence events. Thresholds are starting values stored in config and tuned with real data.

| Rule | File | How it works (starting values) | Known limitation |
|---|---|---|---|
| **Possible port scan** | `backend/detection/portscan.py` | Many distinct destination ports (≥20) from one source within a time window (30 s) | Heuristic, not proof of malice. Packet loss or interface visibility can affect results |
| **DNS anomaly** | `backend/detection/dns_anomaly.py` | Flags unusually long (≥40 chars) or high-entropy DNS labels | CDNs and legitimate encoded names can trigger false positives |
| **Repeated auth failures** | `backend/detection/auth_failures.py` | ≥5 failures for one IP or username within 5 minutes | Requires events sent by our own instrumented application |
| **Suspicious web path** | `backend/detection/web_paths.py` | Pattern matching on `../`, `/etc/passwd`, `/.env`, `/phpmyadmin`, common injection fragments | Requires application events. HTTPS capture alone cannot reveal encrypted paths |

**Alert behaviour**
- **Severity:** low, medium, high, critical — assigned per rule and escalated by count.
- **Deduplication:** same rule + source IP within a cooldown window updates one alert (count increases) rather than creating many.
- **Status:** `new`, `investigating`, `resolved`, `false_positive`.
- **Explainability:** every alert stores the rule name, the numbers that triggered it, and the supporting event IDs.

To add a rule: create a new file in `backend/detection/`, import it in `engine.py`, and add a unit test (fire case + no-fire case).

---

## Architectural decisions

| Date | Decision | Rationale |
|---|---|---|
| 2026-10 | `app/` renamed to `backend/` | Cleaner namespace; avoids collision with Python stdlib `app` patterns; aligns with `frontend/` naming |
| 2026-10 | Svelte 5 + Vite for dashboard | TypeScript, reactive state, component model; faster than plain JS for the dashboard complexity |
| 2026-10 | SQLite over PostgreSQL | No separate server; WAL mode handles the expected read/write concurrency at demo scale |
| 2026-10 | Sliding-window rate limiter (in-process) | Simple, zero dependencies; sufficient for one team sensor set. Keys never evicted — acceptable at demo scale, would be a leak at internet scale |

Record new decisions here when they affect more than one person or module.
