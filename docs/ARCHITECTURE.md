# CYBER-MI6 — Architecture

## Data flow

```
Event sources (they send the ingestion API key)
  Scapy sensor (planned)   web-app helper (planned)   tools/send_demo_events.py
           |                        |                        |
           +------------ POST /api/events -------------------+
                                  |
              backend/  FastAPI: rate limit, API key, validation
                                  |
              app/      storage (SQLite) -> detection engine -> alerts
                                  |
              backend/  WebSocket push + REST endpoints (JWT login required)
                                  |
                        Browser security dashboard
```

1. Event sources send events to `POST /api/events`. Today the demo generator is the only source that is built; the Scapy sensor and web-app helper are planned.
2. The API checks the rate limit, then the API key, then validates the body with Pydantic and stores the events.
3. The detection engine evaluates the new events against recent events. A match creates or updates an alert (deduplicated by rule + source IP within a cooldown).
4. New events and each changed alert (once, in its final state) are pushed to logged-in dashboards over WebSocket. The dashboard reads history through the REST endpoints.

---

## Code layout: two layers

| Layer | Folder | Contains | May import |
|---|---|---|---|
| Core | `app/` | `models`, `config`, `db`, `storage`, `passwords`, `manage`, `detection/` | Python libraries and Pydantic only |
| API | `backend/` | `main`, `auth`, `security`, `ratelimit`, `deps`, `routes/` | `app/` and the web framework |

`app/` never imports `backend/` or FastAPI (`tests/test_architecture.py` fails the build if it does). `storage.py` is the only module that writes SQL. `models.py` is the single contract the frontend's TypeScript types mirror.

---

## Authentication

There are two separate kinds of caller:

| Caller | Credential | Used for |
|---|---|---|
| Sensors, tools, apps | Ingestion API key in the `X-API-Key` header | `POST /api/events` only |
| People using the dashboard | Username and password, exchanged at `POST /api/token` for a JWT sent as `Authorization: Bearer <token>` | Every other route and the WebSocket |

- Passwords are hashed with argon2id. Login answers the same way and takes about the same time for an unknown user and a wrong password.
- The JWT holds only the user id and an expiry (`JWT_EXPIRE_MINUTES`, default 60). Role and account status are read from the database on every request, so disabling a user or changing their role takes effect immediately.
- Roles: `admin` (everything, including `/api/users*`) and `analyst` (read data, change alert status). Permissions are derived from the role on the server and never taken from a request.
- The system refuses to disable or demote the last active admin.
- Login and ingestion are rate limited per client IP.
- With no `JWT_SECRET` configured, login and all dashboard routes answer 503 (fail closed), the same way ingestion does without `API_KEY`.

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
| `events` | id, type, timestamp, received_at, source, src_ip, dst_ip, dst_port, protocol, dns_name, username, http_method, http_path, http_status, user_agent, details (JSON) |
| `alerts` | id, created_at, updated_at, rule, severity, title, status, src_ip, evidence_event_ids (JSON), count, explanation (JSON) |
| `users` | id (uuid), username (unique, case-insensitive), password_hash (argon2id), role, status, created_at, updated_at, last_login |
| `blocklist` | ip (canonical form, primary key), alert_id, reason, blocked_at, blocked_by. **Record only**: nothing refuses traffic from a listed address |

- Indexes cover time, type + time, source IP + type + time, and username + time on events, and rule/IP, status, severity and creation time on alerts.
- WAL mode is on for concurrent reads while writing.
- An hourly retention job deletes events older than `EVENT_RETENTION_DAYS`. Alerts are kept; evidence events that were purged are simply missing from an alert's detail.
- Schema version 2 added `users` and version 3 added `blocklist`. An older database upgrades itself on startup and keeps its data.
- An `alert_notes` table was considered and is not built.

---

## WebSocket

**Handshake.** Browsers cannot set an `Authorization` header on a WebSocket, and a token in the URL ends up in logs, so the client's first message must be:

```json
{ "type": "auth", "token": "<JWT from /api/token>" }
```

The server starts streaming only after the token checks out. A bad or missing token, or no message within 5 seconds, closes the socket with code `4401`; the frontend then returns to the login screen. A socket is authorised once, when it connects (see `docs/FUTURE_CHANGES.md`).

**Message format**

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
| **Possible port scan** | `app/detection/portscan.py` | Many distinct destination ports (≥20) from one source within a time window (30 s) | Heuristic, not proof of malice. Packet loss or interface visibility can affect results |
| **DNS anomaly** | `app/detection/dns_anomaly.py` | Flags unusually long (≥40 chars) or high-entropy DNS labels | CDNs and legitimate encoded names can trigger false positives |
| **Repeated auth failures** | `app/detection/auth_failures.py` | ≥5 failures for one IP or username within 5 minutes | Requires events sent by our own instrumented application |
| **Suspicious web path** | `app/detection/web_paths.py` | Pattern matching on `../`, `/etc/passwd`, `/.env`, `/phpmyadmin`, common injection fragments | Requires application events. HTTPS capture alone cannot reveal encrypted paths |

**Alert behaviour**
- **Severity:** low, medium, high, critical — assigned per rule and escalated by count.
- **Deduplication:** same rule + source IP within a cooldown window updates one alert (count increases) rather than creating many.
- **Status:** `new`, `investigating`, `resolved`, `false_positive`.
- **Explainability:** every alert stores the rule name, the numbers that triggered it, and the supporting event IDs.

To add a rule: create a new file in `app/detection/`, import it in `engine.py`, and add a unit test (fire case + no-fire case).

---

## Architectural decisions

| Date | Decision | Rationale |
|---|---|---|
| 2026-10 | `app/` renamed to `backend/` | Cleaner namespace; aligns with `frontend/` naming. **Superseded by the 2026-11 split below** |
| 2026-11 | Split into `app/` (core) and `backend/` (HTTP API); old `app/` copy removed | The detection engine, storage and user logic are needed by more than the web server (CLI, demo tool, future sensor). Keeping them free of FastAPI makes that possible; the one-way import rule is tested |
| 2026-11 | Dashboard login: argon2id + JWT (HS256, 60 min), read routes and WebSocket require it | A SOC dashboard should not show alerts to anyone on the network. JWT keeps the API stateless; the user is re-read from the database per request so revocation by disabling is immediate |
| 2026-11 | WebSocket authenticates with a first message, not a URL token | Tokens in URLs leak through logs and history; browsers cannot set headers on WebSockets |
| 2026-11 | Any alert status may move to any other (for now) | The spec defines no workflow; revisit when one is agreed (`docs/FUTURE_CHANGES.md`) |
| 2026-11 | Blocklist is record only | The dashboard needs somewhere to mark an address; real enforcement (what refuses the traffic, and where) is a separate design. Listed addresses can still send events |
| 2026-11 | `POST /api/events` accepts one event or `{"events": [...]}` | The sensor example posts single events; batching is cheaper for busy sources |
| 2026-10 | Svelte 5 + Vite for dashboard | TypeScript, reactive state, component model; faster than plain JS for the dashboard complexity |
| 2026-10 | SQLite over PostgreSQL | No separate server; WAL mode handles the expected read/write concurrency at demo scale |
| 2026-10 | Sliding-window rate limiter (in-process) | Simple, zero dependencies; sufficient for one team sensor set. Keys never evicted — acceptable at demo scale, would be a leak at internet scale |

Record new decisions here when they affect more than one person or module.
