# CYBER-MI6 — Team Structure and Tasks

## Team (6 members): 4 backend, 2 frontend

| # | Role | Side | Owns |
|---|---|---|---|
| 1 | API and Storage Lead | Backend | `backend/` (main, models, db, storage, routes, websocket), `.env.example`, `requirements.txt` |
| 2 | Sensor Engineer | Backend | `collectors/scapy_collector.py`, `sensor/` |
| 3 | Detection Engineer | Backend | `backend/detection/` and detection tests |
| 4 | Integration and Test Engineer | Backend | `tools/`, `examples/`, `tests/`, sample web app for testing |
| 5 | Dashboard Lead | Frontend | `frontend/` (Svelte components, views, lib) |
| 6 | UI/UX and Documentation | Frontend | Canva designs, `frontend/src/styles/`, `docs/`, README, demo and slides |

---

## Member 1: API and Storage Lead (Backend)
**Goal:** a stable ingestion API and data layer everyone builds on.
- [ ] Set up repo, `requirements.txt`, `.env.example`, `.gitignore`, and the folder structure
- [ ] Define Pydantic models for events, alerts, and updates in `models.py` (agree on fields with the team in week 1)
- [ ] Create SQLite tables, indexes, and WAL mode in `db.py`; write insert/query functions in `storage.py`
- [ ] Implement `POST /api/events` with validation, size limits, and API key check
- [ ] Implement `GET /api/events`, `GET /api/alerts`, `GET /api/alerts/{id}`, `PATCH /api/alerts/{id}`, `GET /api/stats`
- [ ] Implement the WebSocket endpoint and connection manager; broadcast new events and alerts
- [ ] Call the detection engine after each stored event and save/broadcast the alerts it returns
- [ ] Add rate limiting on ingestion and an event retention cleanup job
- **Deliverable:** by end of week 1–2, a running API with `/docs` and demo data so frontend and detection can start.

## Member 2: Sensor Engineer (Backend)
**Goal:** reliable, safe network metadata from a real Windows or Linux computer.
- [ ] Build `collectors/scapy_collector.py`: interface selection, `--list-ifaces`, BPF filter
- [ ] Capture initial TCP SYN packets and DNS query names; convert to the event format
- [ ] Guarantee no payloads are stored or sent
- [ ] Batch and send events to the API with API key, timeouts, retry, backoff, and a bounded buffer
- [ ] Handle errors cleanly (missing Npcap, no privileges, wrong interface) with helpful messages
- [ ] Test on both Windows (Npcap, Administrator) and Linux (libpcap, sudo or `CAP_NET_RAW`)
- [ ] Write setup instructions for both platforms in `docs/SENSOR_SETUP.md`
- [ ] Optional after the sensor works: Zeek JSON log forwarder in `sensor/`
- **Deliverable:** run the sensor on a team laptop, scan a team-owned test machine, and see events arrive in the API.

## Member 3: Detection Engineer (Backend)
**Goal:** explainable, tunable rules.
- [ ] Build `engine.py`: receive a new event, run relevant rules against recent events, create or update alerts, deduplicate with a cooldown
- [ ] Implement `portscan.py` (distinct ports per source in a time window)
- [ ] Implement `dns_anomaly.py` (label length and Shannon entropy)
- [ ] Implement `auth_failures.py` (failures per IP or username in a window)
- [ ] Implement `web_paths.py` (pattern list for traversal, sensitive files, admin panels, injection fragments)
- [ ] Put all thresholds and patterns in config so they can be tuned without code changes
- [ ] Store the explanation (rule, thresholds, counts) and evidence event IDs in every alert
- [ ] Write unit tests: each rule has a should-fire case and a should-not-fire case
- [ ] Document each rule, its thresholds, and known false positives in `docs/ARCHITECTURE.md`
- **Deliverable:** four working rules with tests by week 4; tuned thresholds by week 6.

## Member 4: Integration and Test Engineer (Backend)
**Goal:** safe, repeatable testing and the web app event source.
- [ ] Build `tools/send_demo_events.py`: normal traffic plus scenarios (port scan, long DNS label, repeated login failures, suspicious paths) with options for rate and scenario
- [ ] Build `examples/webapp_event_reporting.py`: a helper that reports auth failures and HTTP metadata without blocking the app and with path redaction
- [ ] Build a tiny team-owned test web app (login form plus a few routes) that uses the helper
- [ ] Write API tests (valid, invalid, oversized, missing key) and end-to-end tests: event in, alert out, WebSocket message received
- [ ] Set up CI (GitHub Actions) to run lint and tests
- [ ] Create the final demo scenario script for the presentation
- [ ] Track false positives from real test runs and feed them to Member 3
- **Deliverable:** one command that produces a full demo of all four detections.

## Member 5: Dashboard Lead (Frontend)
**Goal:** the live dashboard.
- [ ] Build the API client (`frontend/src/lib/api/`) and WebSocket client (`frontend/src/lib/ws.ts`) with auto-reconnect and polling fallback
- [ ] Build the stat tiles and the live activity feed
- [ ] Build the alert history table with filters (severity, status, rule) and pagination
- [ ] Build alert detail: explanation, thresholds, evidence events, status buttons that call `PATCH`
- [ ] Build the recent events table with a type filter
- [ ] Render all data with `textContent`; add loading, empty, and error states
- [ ] Show WebSocket connection status in the header
- [ ] Work against demo data from week 1
- **Deliverable:** full dashboard working on demo data by week 3, then on real sensor data.

## Member 6: UI/UX and Documentation (Frontend)
**Goal:** a consistent design and a clear presentation.
- [ ] Define the style kit (colors, font, spacing, severity palette) and make Canva mockups for the dashboard and alert detail
- [ ] Write `frontend/src/styles/tokens.css` (layout, cards, badges, tables, buttons, dark theme) for Member 5 to use
- [ ] Responsive and accessibility checks (contrast, labels, keyboard navigation)
- [ ] Write and maintain `docs/ARCHITECTURE.md` and `docs/TEAM_TASKS.md`
- [ ] Write setup guides (`docs/SENSOR_SETUP.md`) for Windows and Linux; keep the README current
- [ ] Prepare the slides, demo script, and screenshots
- **Deliverable:** style kit and mockups in week 1–2, CSS by week 2, docs and slides by week 7.

---

## Cross-team responsibilities
- Every pull request gets one review from another member.
- Everyone writes tests for their own code.
- Weekly 30-minute sync: demo, blockers, next steps.
- **Week 1 agreements:** event format and API contract (Members 1, 2, 3, 4, 5) and the style kit (Members 5, 6).

## Dependencies

```
Week 1:  M1 API + demo data ──────────► M5 dashboard starts
         M1 models agreed ────────────► M2 sensor, M3 rules, M4 tools
         M6 style kit ────────────────► M5 CSS
Week 2+: M4 demo events ──► M3 tunes rules ──► M1 alerts ──► M5 live feed
         M2 real sensor events ───────────────► final demo
```

---

## Timeline

About 8 weeks. The MVP is demonstrable by week 5.

| Week | Milestone |
|---|---|
| 1 | Repo, structure, event format, API contract, models, demo events, style kit |
| 2 | `POST /api/events` and SQLite working, sensor prints events, dashboard skeleton, demo generator |
| 3 | WebSocket live feed, port scan and DNS rules, dashboard feed and alert table |
| 4 | Auth failure and web path rules, web app helper and test app, alert detail and status actions |
| 5 | **MVP demo:** real sensor on a team laptop plus the test web app, alerts live on the dashboard |
| 6 | Tune thresholds, fix false positives, retention job, rate limiting, UI polish |
| 7 | Windows and Linux testing, docs, setup guides, optional Zeek forwarder |
| 8 | Final testing, slides, rehearsal, final demo |

---

## Definition of done

- Merged through a reviewed pull request
- Tests added and passing in CI
- Docs updated if behavior, config, or API changed
- No secrets or database files committed
- Works with demo events and with real sensor events

## MVP acceptance checklist

- [ ] `POST /api/events` validates and stores events; bad input returns a clear error
- [ ] A simulated port scan creates a "possible port scan" alert
- [ ] A long or high-entropy DNS label creates a DNS anomaly alert
- [ ] Repeated login failures on the test web app create an alert
- [ ] A suspicious path request creates a web path alert
- [ ] Alerts and events appear live on the dashboard without refreshing
- [ ] An alert's status can be changed from the dashboard and persists
- [ ] The sensor runs on both Windows and Linux without storing payloads
- [ ] Requests without a valid API key are rejected
