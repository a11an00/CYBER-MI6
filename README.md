# CYBER-MI6

**Detect. Analyze. Respond. Secure.**

CYBER-MI6 is a network and web-application threat detection prototype. It ingests metadata from authorized live network observations and security events from our own instrumented web application, evaluates transparent detection rules, stores events and alerts, and presents them in a real-time dashboard.

> **Authorized use only:** use only networks and applications the team owns or has explicit permission to monitor. Detections are indicators of possible threats, not proof of an attack.

---

## Goals

- Collect a small, documented set of network and application security events.
- Detect suspicious patterns with **explainable rules before introducing machine learning**.
- Show events, alerts, severity, evidence, and alert status in a browser dashboard.
- Keep the prototype portable across Windows and Linux.

---

## Technology stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| API | FastAPI + Uvicorn |
| Validation | Pydantic |
| Storage | SQLite (WAL mode) |
| Frontend | Svelte 5, TypeScript, Vite |
| Packet capture | Scapy (cross-platform) |
| Windows capture backend | Npcap |
| Linux capture backend | libpcap + appropriate privileges |

---

## Architecture

```
Scapy sensor / web-app helper
        |
        +── HTTPS POST /api/events ──► FastAPI validation + SQLite storage
                                               |
                                        Detection engine
                                               |
                              WebSocket broadcast + REST endpoints
                                               |
                                    Svelte dashboard (browser)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full data-flow description, event format, database schema, WebSocket message format, and per-rule details.

---

## Repository structure

```
CYBER-MI6/
├── backend/                # FastAPI app (Python package)
│   ├── main.py             # App factory and entry point
│   ├── config.py           # Settings from .env
│   ├── models.py           # Pydantic models
│   ├── db.py               # SQLite connection and schema
│   ├── storage.py          # insert/query helpers
│   ├── deps.py             # FastAPI dependency injectors
│   ├── security.py         # API key auth
│   ├── ratelimit.py        # Sliding-window rate limiter
│   ├── routes/
│   │   ├── websocket.py    # WS /ws + ConnectionManager
│   │   ├── events.py       # POST/GET /api/events
│   │   ├── alerts.py       # GET/PATCH /api/alerts
│   │   └── stats.py        # GET /api/stats
│   └── detection/
│       ├── engine.py
│       ├── portscan.py
│       ├── dns_anomaly.py
│       ├── auth_failures.py
│       └── web_paths.py
├── frontend/               # Svelte 5 dashboard
│   └── src/
│       ├── components/
│       ├── views/
│       └── lib/
├── app/                    # Legacy package (being migrated to backend/)
├── tests/                  # pytest suite
├── web/                    # Legacy HTML placeholder
├── docs/                   # Architecture, specs, task lists
├── .env.example
└── requirements.txt
```

Do not commit the SQLite database file, `.env`, or virtual environments.

---

## Getting started

### Prerequisites
- Python 3.11+
- Windows: [Npcap](https://npcap.com) (WinPcap API-compatible mode)
- Linux: libpcap and capture permission (`sudo` or `CAP_NET_RAW`)
- Node.js 20+ (for the frontend)

### Install and run

```bash
git clone <repo-url> CYBER-MI6
cd CYBER-MI6

python -m venv .venv
# Windows:  .venv\Scripts\Activate.ps1
# Linux:    source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
uvicorn backend.main:app --reload
```

API docs: http://localhost:8000/docs

### Build the dashboard (optional — falls back to `web/index.html` if skipped)

```bash
cd frontend && npm install && npm run build
```

### Run the Scapy sensor (own computer/network only)

```bash
# Linux
sudo .venv/bin/python collectors/scapy_collector.py --iface eth0 --api-url http://localhost:8000

# Windows (Administrator terminal, Npcap installed)
python collectors\scapy_collector.py --iface "Wi-Fi" --api-url http://localhost:8000
```

See [docs/SENSOR_SETUP.md](docs/SENSOR_SETUP.md) for platform-specific setup.

---

## Security and privacy rules

- Monitor **only** systems and networks the team owns or has explicit permission to monitor.
- **Metadata only** — no payloads, bodies, cookies, passwords, or tokens.
- Redact query strings from `http_path` before sending.
- Require an API key on ingestion; keep keys in `.env`, not in code.
- Validate all input with Pydantic; use parameterized SQL only.
- Treat all event fields as untrusted. The dashboard must use `textContent`, not `innerHTML`.
- Bind the API to `localhost` by default; use HTTPS if exposing it on a network.

---

## Git workflow

- **Branches:** `main` is protected. Use `feature/<area>-<description>` and `fix/<description>`.
- **Commits:** conventional style — e.g. `feat(detection): add dns anomaly rule`.
- **Pull requests:** one purpose, one reviewer from another member, CI green.
- **Code style:** Python — `ruff` + `black`; TypeScript — `eslint` + `prettier`.
- **Decisions:** record anything affecting more than one person in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Further reading

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Data flow, event format, DB schema, WS messages, detection rules, ADRs |
| [docs/TEAM_TASKS.md](docs/TEAM_TASKS.md) | Per-member tasks, timeline, dependencies, MVP checklist |
| [docs/BACKEND_SPEC.md](docs/BACKEND_SPEC.md) | Full API reference, sensor design, tools/examples spec, config variables |
| [docs/FRONTEND_SPEC.md](docs/FRONTEND_SPEC.md) | Dashboard sections, UI rules, file layout, build instructions |
| [docs/SENSOR_SETUP.md](docs/SENSOR_SETUP.md) | Windows (Npcap) and Linux (libpcap) sensor setup steps |
