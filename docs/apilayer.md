# The HTTP layer (`backend/`)

How the API is built, how to test it, and what is still open. The core logic it calls (storage, detection, users, settings) lives in `app/`; see [ARCHITECTURE.md](ARCHITECTURE.md) for the whole picture and [BACKEND_SPEC.md](BACKEND_SPEC.md) for the endpoint reference.

`backend/` imports `app/`, never the other way round. Add a new endpoint here; add new logic in `app/` and call it from the route.

## Status

| Component | File | State |
|---|---|---|
| App factory, error format, CORS, static files, startup and retention job | `backend/main.py` | Done |
| Dependency helpers (database, rate limiters) | `backend/deps.py` | Done |
| Ingestion API key check | `backend/security.py` | Done |
| Sliding-window rate limiter | `backend/ratelimit.py` | Done |
| Login: JWT creation, `require_user`, `require_admin`, WebSocket handshake | `backend/auth.py` | Done |
| `POST /api/events`, `GET /api/events` | `backend/routes/events.py` | Done |
| `GET /api/alerts`, `GET`/`PATCH /api/alerts/{id}` | `backend/routes/alerts.py` | Done |
| `GET /api/stats` | `backend/routes/stats.py` | Done |
| `POST /api/token` | `backend/routes/auth.py` | Done |
| `/api/users*` (admin only) | `backend/routes/users.py` | Done |
| `/ws` and the connection manager | `backend/routes/websocket.py` | Done |
| `/api/blocklist` (record only) | `backend/routes/blocklist.py` | Done |

## Files

### `main.py`
`create_app()` builds the FastAPI app. It opens the database and starts the hourly retention job in the lifespan, returns every error as `{"error": ..., "detail": ...}`, adds CORS only when `ALLOWED_ORIGINS` is set, and mounts the built frontend last so it cannot hide API routes. A new router must be included before the static mount. It logs a warning at startup when `JWT_SECRET` is empty.

### `security.py`
`require_api_key` reads `X-API-Key` and compares it to `API_KEY` in constant time. Missing or wrong key: 401. `API_KEY` not configured: 503. Used only by `POST /api/events`.

### `ratelimit.py`
`SlidingWindowLimiter` allows a fixed number of calls per key (the client IP) in a time window. Thread-safe. Two instances exist: ingestion and login. Idle keys are never removed, and behind a reverse proxy every client shares one address (both listed in [FUTURE_CHANGES.md](FUTURE_CHANGES.md)).

### `auth.py`
- `create_access_token` signs a JWT (HS256) holding the user id, issuer, issued-at and expiry.
- `require_user` is the dependency for every dashboard route. It rejects a missing, malformed, expired or wrongly signed token, then loads the user and rejects unknown or disabled accounts. No `JWT_SECRET`: 503.
- `require_admin` adds the admin role check (403).
- `authenticate_websocket` runs the first-message handshake on `/ws` and closes the socket with code 4401 on any failure.
- `to_profile` is the only way a user leaves the API: it strips the password hash.

### `routes/events.py`
`POST /api/events` runs the rate limit, then the API key, then validation (one event or `{"events": [...]}`), enforces `INGEST_MAX_BATCH`, stores the events, runs detection, and broadcasts. Storage and detection run in a worker thread so the server stays responsive. If detection raises, the events stay stored and the request still succeeds (a retry would create duplicates). An alert updated several times by one batch is broadcast once, in its final state. `GET /api/events` maps `from`/`to` onto the storage `since`/`until` arguments.

### `routes/alerts.py`, `routes/stats.py`
Thin wrappers over `app/storage.py`. Unknown filter values are 422; an unknown alert id is 404.

### `routes/blocklist.py`
List, add and remove blocked addresses, matching the contract in `frontend/src/lib/api/client.ts`. Addresses are validated and stored in canonical form; adding one twice is idempotent; each entry records who added it (`blocked_by`). **Record only**: no other code reads this list.

### `routes/auth.py`, `routes/users.py`
Login (`POST /api/token`) and admin user management. Login rate limits per IP, always runs one argon2 verification even for an unknown username, and gives one error for every failure. User routes ignore client-supplied `permissions` and refuse to remove the last active admin.

### `routes/websocket.py`
`ConnectionManager` tracks live clients; `broadcast` drops any client that fails or takes more than two seconds, so one slow browser cannot hold up the rest. Sockets join the manager only after authenticating.

## Tests

Run from the folder that contains `pytest.ini`:

```bash
python -m pytest -q
```

Tests never touch the real `data/` folder. Route tests start the whole app on a temporary database through the `api` (logged in as an analyst) and `anon` (not logged in) fixtures in `tests/conftest.py`.

| File | What it checks |
|---|---|
| `test_routes_events.py`, `test_routes_alerts_stats.py`, `test_routes_blocklist.py` | Every events, alerts, stats and blocklist route: success, validation, 401/404/413/422/429/503, broadcasting |
| `test_auth_routes.py`, `test_passwords.py` | Login, token tampering, route protection, user administration, last-admin rule, WebSocket handshake |
| `test_detectors_via_api.py` | Each of the four rules, end to end through the HTTP API |
| `test_demo_tool.py` | The demo generator against a real server |
| `test_architecture.py` | `app/` never imports `backend/` or a web framework |
| `test_auth.py`, `test_ratelimit.py`, `test_ws.py`, `test_app.py` | API key, rate limiter, WebSocket transport, app skeleton |
| `tests/e2e_browser/run.py` | Not part of pytest. Starts the backend and drives the real dashboard in headless Chrome: login, live WebSocket updates, alert detail, status change, blocklist, admin page, logout (23 checks) |
| `test_perf.py` | Window queries stay fast with 100,000 events (each mutating test uses its own copy of the data) |
| other `test_*.py` | Core: models, database, storage, detection rules, concurrency |

The suite passes in random order (`pytest-randomly`).

## Known issues

See [FUTURE_CHANGES.md](FUTURE_CHANGES.md). The main ones: rate limits behind a proxy, request-counted ingestion limit, tokens that cannot be revoked individually, a WebSocket that is authorised only when it connects.
