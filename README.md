# CYBER-MI6

**Detect. Analyze. Respond. Secure.**

CYBER-MI6 is a network and web-application threat detection prototype. It ingests metadata from authorized network observations and security events from our own instrumented web application, evaluates transparent detection rules, stores events and alerts, and presents them in a real-time dashboard.

> **Authorized use only:** use only networks and applications the team owns or has explicit permission to monitor. Detections are indicators of possible threats, not proof of an attack.

---

## Goals

- Collect a small, documented set of network and application security events.
- Detect suspicious patterns with **explainable rules before introducing machine learning**.
- Show events, alerts, severity, evidence, and alert status in a browser dashboard behind a login.
- Keep the prototype portable across Windows, macOS and Linux.

---

## Status

| Piece | State |
|---|---|
| Ingestion API (`POST /api/events`, single event or batch, API key, rate limit) | Built, tested |
| Detection engine and all four rules (`port_scan`, `dns_anomaly`, `auth_failures`, `web_paths`) | Built, tested through the API |
| Dashboard routes (events, alerts, alert detail and status changes, stats) | Built, tested |
| Dashboard login (JWT), user accounts, admin-only user management | Built, tested |
| Live WebSocket feed (login token required) | Built, tested |
| Demo event generator (`tools/send_demo_events.py`) | Built, tested |
| Svelte dashboard | Built; type-checks, builds, and passes a real-browser run against the live backend (login, live updates, alert detail, status changes, blocklist, admin page, logout) |
| Setup script (macOS, Windows, Linux) | Not built yet |
| Blocklist (`/api/blocklist`, record only: addresses are listed, nothing is actually blocked) | Built, tested |
| Scapy network sensor (`collectors/`) | Not built yet |
| Web-app event helper, test web app, CI | Not built yet |

Known shortcuts and planned work are tracked in [docs/FUTURE_CHANGES.md](docs/FUTURE_CHANGES.md).

---

## Technology stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| API | FastAPI + Uvicorn |
| Validation | Pydantic |
| Passwords and login | argon2id (`argon2-cffi`), JWT (`PyJWT`) |
| Storage | SQLite (WAL mode) |
| Frontend | Svelte 5, TypeScript, Vite |
| Packet capture (planned) | Scapy; Npcap on Windows, libpcap on Linux/macOS |

---

## Architecture

```
Scapy sensor / web-app helper / tools/send_demo_events.py     (event sources, API key)
        |
        +── HTTP POST /api/events ──► backend/ (FastAPI)
                                          |   validates, rate limits, then calls the core in app/
                                          v
                                    app/ (core: storage, detection engine, users)
                                          |
                          alerts + events stored in SQLite, pushed over WebSocket
                                          |
                          REST + WebSocket (JWT login) ──► Svelte dashboard (browser)
```

The code is split in two layers, and the dependency only goes one way:

- **`app/`** is the core: models, settings, database, storage, detection, password hashing and the admin command. It has no web code, so the command line, demo tool and future sensor can use it.
- **`backend/`** is the HTTP API only: the FastAPI app, routes, login checks, API key check and rate limiting. It imports `app/`; `app/` never imports `backend/` (a test enforces this).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the data flow, event format, database schema, WebSocket messages, rules and design decisions.

---

## Repository structure

```
CYBER-MI6/
├── app/                    # CORE (no web code)
│   ├── models.py           # Pydantic models: events, alerts, users, API shapes
│   ├── config.py           # Settings from .env
│   ├── db.py               # SQLite connection and schema (v3: events, alerts, users, blocklist)
│   ├── storage.py          # The only module that writes SQL
│   ├── passwords.py        # argon2id hashing
│   ├── manage.py           # python -m app.manage create-admin | reset-password
│   └── detection/          # engine.py + portscan, dns_anomaly, auth_failures, web_paths
├── backend/                # HTTP API (imports app/)
│   ├── main.py             # App factory, CORS, error format, static files
│   ├── auth.py             # JWT creation and the login checks (HTTP + WebSocket)
│   ├── security.py         # Ingestion API key check
│   ├── ratelimit.py        # Sliding-window rate limiter
│   ├── deps.py             # FastAPI dependency helpers
│   └── routes/             # events, alerts, stats, blocklist, auth (/token), users, websocket
├── frontend/               # Svelte 5 dashboard
├── tools/                  # send_demo_events.py
├── tests/                  # pytest suite
├── web/                    # Fallback HTML page when the dashboard is not built
├── docs/                   # Architecture, specs, task lists, future changes
├── .env.example
└── requirements.txt
```

Do not commit the SQLite database file, `.env`, or virtual environments.

---

## Getting started

### Prerequisites
- Python 3.11+
- Node.js 20+ (for the dashboard)
- Later, for the sensor: Npcap (Windows) or libpcap with capture permission (Linux/macOS)

### 1. Install and configure

```bash
git clone <repo-url> CYBER-MI6
cd CYBER-MI6

python -m venv .venv
# Windows (PowerShell):  .venv\Scripts\Activate.ps1
# macOS / Linux:         source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env          # Windows: copy .env.example .env
```

Edit `.env` and set two secrets (never commit them):

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"    # run twice
```

- `API_KEY`: what sensors and tools send in the `X-API-Key` header.
- `JWT_SECRET`: signs dashboard login tokens (at least 32 characters). Without it, login and every dashboard route answer 503.

### 2. Create the first admin account

```bash
python -m app.manage create-admin        # prompts for username and password
```

The password is prompted, so it never lands in your shell history. If you are ever locked out: `python -m app.manage reset-password <username>`.

### 3. Run the API

```bash
uvicorn backend.main:app --reload
```

API docs: http://localhost:8000/docs

### 4. Open the dashboard

Build it once and the API serves it at http://localhost:8000:

```bash
cd frontend && npm install && npm run build
```

Or develop against the real API with hot reload (the dev server proxies `/api` and `/ws` to port 8000):

```bash
cd frontend && npm install && npm run dev:live      # http://localhost:5173
```

`npm run dev` (without `:live`) shows built-in **mock data** and never contacts the backend. Log in with the admin account from step 2.

### 5. Send demo events

```bash
python tools/send_demo_events.py                       # normal traffic + all four attacks
python tools/send_demo_events.py --scenario port_scan  # one attack
python tools/send_demo_events.py --help
```

It reads `API_KEY` from `.env`. Alerts appear in the dashboard as the events arrive.

### Run the tests

```bash
python -m pytest -q        # about 500 tests, ~30 s; test dependencies are in requirements.txt
```

There is also a real-browser check that starts the backend on a throwaway database and drives the dashboard in headless Chrome (login, live updates, alerts, blocklist, admin page, logout):

```bash
python tests/e2e_browser/run.py     # needs Node.js; set CHROME_PATH to use your own Chrome
```

---

## Security and privacy rules

- Monitor **only** systems and networks the team owns or has explicit permission to monitor.
- **Metadata only**: no payloads, bodies, cookies, passwords, or tokens.
- Redact query strings from `http_path` before sending.
- Sensors authenticate with the ingestion API key; people log in with a username and password (argon2id) and receive a short-lived JWT. The API key must never be put in frontend code.
- Keep keys in `.env`, not in code. Validate all input with Pydantic; use parameterized SQL only.
- Treat all event fields as untrusted. The dashboard must use `textContent`, not `innerHTML`.
- Bind the API to `localhost` by default; use HTTPS before exposing it on a network (passwords and tokens are otherwise sent in clear text).

---

## Git workflow

- **Branches:** `main` is protected. Use `feature/<area>-<description>` and `fix/<description>`.
- **Commits:** conventional style, e.g. `feat(detection): add dns anomaly rule`.
- **Pull requests:** one purpose, one reviewer from another member, CI green.
- **Code style:** Python `ruff`; TypeScript `svelte-check`.
- **Decisions:** record anything affecting more than one person in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Further reading

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Data flow, event format, DB schema, WebSocket messages, detection rules, decisions |
| [docs/BACKEND_SPEC.md](docs/BACKEND_SPEC.md) | API reference, tools spec, configuration variables |
| [docs/apilayer.md](docs/apilayer.md) | How the HTTP layer (`backend/`) is built and tested |
| [docs/FUTURE_CHANGES.md](docs/FUTURE_CHANGES.md) | Known shortcuts, deferred features, hardening list |
| [docs/FRONTEND_SPEC.md](docs/FRONTEND_SPEC.md) | Dashboard sections, UI rules, file layout |
| [docs/DETECTION_RULES_SECTION.md](docs/DETECTION_RULES_SECTION.md) | Each rule, thresholds, false positives |
| [docs/TEAM_TASKS.md](docs/TEAM_TASKS.md) | Per-member tasks, timeline, MVP checklist |
