# CYBER-MI6 — Frontend Mock API Documentation

This document describes every TypeScript type the frontend expects, the shape of the data the UI consumes, size limits, pagination/filtering behaviour, WebSocket message formats, auth expectations, and how the mock client works. It is intended as the single reference for anyone implementing or maintaining the mock backend that the frontend talks to.

Source of truth: `frontend/src/` (see file layout below). The types mirror `backend/models.py`; when the backend model changes, the frontend types change in the same pull request.

## 1. File layout

```
frontend/src/
├── App.svelte                  # Shell: auth gate, router, live stream
├── main.ts                     # Bootstrap (theme + mount App)
├── app.css                     # Design tokens
├── vite-env.d.ts
├── components/                 # Reusable UI components
│   ├── AlertCard.svelte
│   ├── AlertDetailPanel.svelte
│   ├── AlertHistory.svelte
│   ├── ApiBanner.svelte
│   ├── AppHeader.svelte
│   ├── BlockIpControl.svelte
│   ├── Button.svelte
│   ├── Card.svelte
│   ├── DevScenarioNotice.svelte
│   ├── EventCard.svelte
│   ├── FeedItem.svelte
│   ├── LiveActivity.svelte
│   ├── RecentEvents.svelte
│   ├── Select.svelte
│   ├── SeverityBadge.svelte
│   ├── StatTile.svelte
│   ├── StatTiles.svelte
│   ├── StateBlock.svelte
│   ├── StatusPill.svelte
│   └── ThemeToggle.svelte
├── views/                      # Page-level views (hash-routed by lib/router.ts)
│   ├── AdminDashboard.svelte
│   ├── AlertDetail.svelte
│   ├── Alerts.svelte
│   ├── Events.svelte
│   ├── Login.svelte
│   ├── NotFound.svelte
│   ├── Overview.svelte
│   └── UserProfileSettings.svelte  (empty file)
├── lib/
│   ├── api/
│   │   ├── client.ts           # DataClient interface + httpClient + mock loader
│   │   ├── http.ts             # ApiError, buildQuery, request (fetch wrapper)
│   │   ├── mock.ts             # mockClient + startMockLive (in-memory backend stand-in)
│   │   ├── fixtures.ts         # Seed alerts + events (Figma-shaped demo data)
│   │   └── scenario.ts         # ?mock= scenario switcher (loading/empty/error/offline/save-error/ws-down)
│   ├── alerts.ts               # AlertQuery, AlertPage, alertsChanged store
│   ├── auth.ts                 # auth store (token/profile in localStorage)
│   ├── blocklist.ts            # blocklist store + block/unblock helpers
│   ├── events.ts               # eventsChanged store
│   ├── explain.ts              # explain(alert) → "Why this fired" text
│   ├── format.ts               # clockTime, relativeTime, eventSummary, eventTarget, alertSummary
│   ├── health.ts               # apiHealth store + reportSuccess/reportFailure
│   ├── labels.ts               # STATUS_LABELS, SEVERITY_LABELS
│   ├── live.ts                 # feed store, MAX_FEED_ITEMS, pushLive, loadFeedHistory
│   ├── router.ts               # Route type, parseHash, href helpers
│   ├── theme.ts                # Theme store
│   ├── types.ts                # All shared API types (Event, Alert, Stats, …)
│   └── ws.ts                   # WebSocket client with reconnect + polling fallback
├── services/
│   └── api.ts                  # apiFetch (separate fetch wrapper used by Login/Admin)
└── types/
    └── auth.ts                 # UserProfile, AuthResponse
```

Note: several files named in the task (`AlertDetail.ts`, `DataClient.ts`, `httpClient.ts`, `events.ts`, `alerts.ts`, `ApiError.ts`, `buildQuery.ts`, `request.ts`, `mockClient.ts`, `startMockLive.ts`, `Scenario.ts`, `urlWithoutScenario.ts`) do not exist as standalone files. Their contents live inside `client.ts`, `http.ts`, `mock.ts`, `scenario.ts`, `alerts.ts`, `events.ts`, `live.ts`, `ws.ts`, `router.ts`, `theme.ts`, `labels.ts`, `types.ts`, `auth.ts`, `blocklist.ts`, `explain.ts`, `format.ts`, `health.ts` as noted above. `frontend/src/lib/StatusFilter.ts`, `ApiHealth.ts`, `MAX_FEED_ITEMS.ts`, `Route.ts`, `Theme.ts`, `EVENT_TYPES.ts`, `LiveHandlers.ts`, `Explanation.ts` likewise do not exist as standalone files; those symbols are defined in `alerts.ts`, `health.ts`, `live.ts`, `router.ts`, `theme.ts`, `types.ts`, `ws.ts`, `explain.ts`.

## 2. Data types the frontend needs

All datetimes are ISO 8601 UTC strings (Pydantic JSON encoding).

### 2.1 Core domain types

Defined in `frontend/src/lib/types.ts` (duplicated, unintentionally, in `frontend/src/lib/router.ts` — keep them in sync).

**Event** — a stored security event. Type-specific fields are `null` when unused (the backend model rejects cross-type fields).

| Field | Type | Notes |
|---|---|---|
| `id` | `number` | |
| `type` | `'network_connection' \| 'dns_query' \| 'auth_failure' \| 'http_request'` | `EVENT_TYPES` |
| `timestamp` | `string` (ISO 8601 UTC) | |
| `received_at` | `string` (ISO 8601 UTC) | |
| `source` | `string` | sensor name, e.g. `laptop-sensor-1`, `test-webapp` |
| `src_ip` | `string` | |
| `dst_ip` | `string \| null` | |
| `dst_port` | `number \| null` | |
| `protocol` | `'tcp' \| 'udp' \| null` | |
| `dns_name` | `string \| null` | only for `dns_query` |
| `username` | `string \| null` | only for `auth_failure` |
| `http_method` | `string \| null` | only for `http_request` |
| `http_path` | `string \| null` | only for `http_request` |
| `http_status` | `number \| null` | only for `http_request` |
| `user_agent` | `string \| null` | |
| `details` | `Record<string, string\|number\|boolean\|null> \| null` | free-form |

Valid event type / field combinations (mock `liveEvent` in `mock.ts`):
- `dns_query`: `source`, `src_ip`, `dns_name`
- `network_connection`: `source`, `src_ip`, `dst_ip`, `dst_port`, `protocol`
- `http_request`: `source`, `src_ip`, `http_method`, `http_path`, `http_status`
- `auth_failure`: `source`, `src_ip`, `username`

**Alert** — a detection-rule firing.

| Field | Type | Notes |
|---|---|---|
| `id` | `number` | |
| `rule` | `string` | `RULES`: `port_scan`, `dns_anomaly`, `auth_failures`, `web_paths` |
| `severity` | `'low' \| 'medium' \| 'high' \| 'critical'` | `SEVERITIES` |
| `title` | `string` | |
| `src_ip` | `string \| null` | |
| `evidence_event_ids` | `number[]` | ids of related events |
| `explanation` | `Record<string, unknown>` | free-form until backend defines keys; read defensively |
| `created_at` | `string` (ISO 8601 UTC) | |
| `updated_at` | `string` (ISO 8601 UTC) | moves on status change and on live deduplication |
| `status` | `'new' \| 'investigating' \| 'resolved' \| 'false_positive'` | `ALERT_STATUSES` |
| `count` | `number` | deduplicated occurrence count |

Open statuses: `OPEN_STATUSES = ['new', 'investigating']`.

**AlertDetail** (`client.ts`): `Alert & { evidence: Event[] }` — alert detail with evidence events. The comment in `client.ts` notes the exact shape is not yet confirmed with the API owner; it assumes alert fields plus an `evidence` array.

**Stats** — response of `GET /api/stats`.

| Field | Type |
|---|---|
| `events_today` | `number` |
| `events_total` | `number` |
| `alerts_total` | `number` |
| `open_alerts` | `number` |
| `alerts_by_severity` | `Record<'low'\|'medium'\|'high'\|'critical', number>` |
| `alerts_by_status` | `Record<'new'\|'investigating'\|'resolved'\|'false_positive', number>` |
| `top_source_ips` | `TopSource[]` |

**TopSource**: `{ src_ip: string; count: number }`.

### 2.2 Request / filter types

**EventFilters** (`GET /api/events` query):
- `type?`: `EventType`
- `src_ip?`: `string`
- `from?`: ISO 8601 (`e.timestamp >= from`)
- `to?`: ISO 8601 (`e.timestamp <= to`)
- `limit?`: number
- `offset?`: number

**AlertFilters** (`GET /api/alerts` query):
- `severity?`: `Severity`
- `status?`: `AlertStatus`
- `rule?`: `string`
- `limit?`: number
- `offset?`: number

**AlertQuery** (`alerts.ts`, used by `AlertHistory`): `{ severity: SeverityFilter; status: StatusFilter; rule: string }` where `SeverityFilter = Severity \| 'all'`, `StatusFilter = AlertStatus \| 'open' \| 'all'`. Default: `{ severity: 'all', status: 'open', rule: 'all' }`. Note `'open'` is a UI convenience expanded into `new` + `investigating` queries (two parallel `listAlerts` calls merged).

**AlertUpdate** (body of `PATCH /api/alerts/{id}`): `{ status: AlertStatus }`.

### 2.3 Blocklist (proposed — backend has no blocking yet)

**BlockedIp**: `{ ip: string; alert_id: number \| null; reason: string \| null; blocked_at: string }`.

**BlockRequest** (body of `POST /api/blocklist`): `{ ip: string; alert_id?: number; reason?: string }`.

Proposed endpoints (`client.ts` comments): `GET /api/blocklist → BlockedIp[]`, `POST /api/blocklist {ip, alert_id?, reason?} → BlockedIp (201)`, `DELETE /api/blocklist/{ip} → 204`. Until they exist the real API answers 404 and the panel says so. IP validation mirrors backend `models._check_ip`: valid IPv4/IPv6.

### 2.4 Auth types (`frontend/src/types/auth.ts`)

**UserProfile**: `{ id: string; username: string; role: 'admin' \| 'analyst'; permissions: string[]; status: 'active' \| 'disabled'; lastLogin?: string }`.

**AuthResponse**: `{ access_token: string; token_type: string; user: UserProfile }`.

Auth flow: `POST /token` with `{ username, password }` → `AuthResponse`; token stored in `localStorage` under `cyber_mi6_token`, profile under `cyber_mi6_user`. Requests send `Authorization: Bearer <token>`. On `401` the view logs the user out. `apiFetch` (services/api.ts) falls back to `X-API-Key: VITE_API_KEY` when no token is present.

### 2.5 Real-time / feed types

**LiveMessage** (WebSocket `/ws`): `{ kind: 'event'; data: Event } \| { kind: 'alert'; data: Alert }`.

Raw messages that aren't shaped like this are ignored by `parseMessage` (`ws.ts`): must be an object with `kind` in `{'event','alert'}` and `data` an object with a numeric `id`.

**FeedItem** (`live.ts`): `{ kind: 'event' \| 'alert'; id: string; at: string; data: Event \| Alert }`. Feed id prefix: `event-<id>` or `alert-<id>`.

**Connection**: `'live' \| 'reconnecting' \| 'offline'`.

**Route** (`router.ts`):
- `{ name: 'overview' }`
- `{ name: 'alerts' }`
- `{ name: 'alert-detail'; id: number }`
- `{ name: 'events' }`
- `{ name: 'admin' }`
- `{ name: 'profile' }`
- `{ name: 'not-found'; path: string }`

Hash-based routing: `/#/alerts/17`. Query string after `?` in the hash is preserved.

## 3. Data shapes — what the UI does with each piece

### 3.1 Stats → StatTiles (Overview)

`StatTiles` renders four tiles from `GET /api/stats`:
1. **Events today** — `stats.events_today`
2. **Alerts by severity** — `stats.alerts_total`, caption `N critical · N high · N medium · N low`
3. **Open alerts** — `stats.open_alerts`, caption `N new · N investigating` (phone: `N new`)
4. **Top source IP** — `stats.top_source_ips[0].src_ip`, caption `N events` or "No events in the last 24 h"

Design captions like "+8% vs yesterday" have no API field and are left out.

### 3.2 Alerts → AlertHistory + AlertCard

`AlertHistory` (used by Overview and Alerts view) renders:
- Desktop: table with columns Severity, Rule, Title, Source IP, Time, Status. Column widths fixed (120/144/144/104/152 px), min-width 760px, horizontal scroll.
- Phone: `AlertCard` list (max 4 cards shown when `viewAllHref` set; `nth-child(n + 5)` hidden), plus "View all N alerts" link.
- Filters: Severity, Status (incl. "Open" and "All"), Rule. A filter change resets to page 1.
- Pagination: Previous/Next. "hasNext" detected by requesting `pageSize + 1` rows. Total comes from `GET /api/stats` when filters map onto its counts, else `null`.
- `pageSize` prop default 6 (Overview passes none → 6; Alerts view passes 20).
- Empty states: "No alerts match these filters" (with Clear filters) or "No alerts yet".
- Error state with Retry now; retries every 10s (`RETRY_SECONDS`).

### 3.3 Alert detail → AlertDetailPanel

Fetches `GET /api/alerts/{id}` → `AlertDetail`. Renders:
- Severity badge + status pill
- Title, rule, source IP, first seen (`created_at`), last seen (newest evidence event timestamp, fallback `updated_at`), occurrences (`count`, "deduplicated" when > 1)
- "Why this fired" via `explain(alert)` — summary, threshold, caveat, raw key/value pairs
- Evidence list: up to 5 events previewed (`EVIDENCE_PREVIEW = 5`), "Show fewer / + N more events" toggle, note when retained events are fewer than `evidence_event_ids.length` (retention)
- Status actions (optimistic update, rolled back on failure):
  - `new` → Mark resolved / False positive / Start investigating
  - `investigating` → Mark resolved / False positive
  - `resolved`/`false_positive` → Reopen
- `BlockIpControl` under status buttons when `alert.src_ip` present

### 3.4 Events → RecentEvents + EventCard

`RecentEvents` renders:
- Desktop table: Time, Type, Source IP, Target, Sensor. min-width 720px.
- Phone: `EventCard` list (4 cards when scrolled/overview).
- Type filter (All + the 4 event types). Filter change resets to page 1.
- Pagination (optional `paged` prop): one-extra-row `hasNext` detection.
- `pageSize` default 50. Overview passes `scroll` (no paging, inner scroll, ~7 rows); Events view passes `paged`.
- Empty states: "No events of this type" / "No events yet".
- Error with retry every 10s.

### 3.5 Live feed → LiveActivity + FeedItem

Feed seeded from REST history (`listEvents` + `listAlerts`, `limit: MAX_FEED_ITEMS = 50`), then live `/ws` messages prepended via `pushLive`. An alert update replaces that alert's older feed line. Feed capped at 50 items, newest first. Phone shows only 4 lines.

`LiveActivity` shows connection badge (Live / Reconnecting… / Offline · polling every 10s) with a Reconnect button when offline. Loading state shows skeleton rows (4).

### 3.6 Blocklist → BlockIpControl

Shown under alert detail status buttons. Not optimistic: shows "Blocked" only after API confirms. Confirmation dialog; Escape cancels. IP validated client-side (`isIp`) before sending. Errors shown via `blockErrorMessage`.

### 3.7 Admin → AdminDashboard

Uses `apiFetch` (separate wrapper, `services/api.ts`) against `GET /api/users`, `PATCH /api/users/{id}`, `PATCH /api/users/{id}/status`, `POST /api/users`. Expects `UserProfile[]`. Role `admin` required to view; non-admin gets NotFound "Unauthorized Access: Admin Only".

### 3.8 Login → Login view

`POST /token` (requireAuth: false) with `{ username, password }` → `AuthResponse`. On success `auth.login(token, user)`. On 401 → logout + "Session expired" error.

## 4. Size constraints, pagination, and limits

| Limit | Value | Where |
|---|---|---|
| Default list limit | 100 | `mock.ts` `DEFAULT_LIMIT` (= storage.DEFAULT_LIST_LIMIT) |
| Max list limit | 1000 | `mock.ts` `MAX_LIMIT` (= storage.MAX_LIST_LIMIT); `page()` clamps `Math.max(1, Math.min(limit, MAX_LIMIT))` |
| Feed max items | 50 | `MAX_FEED_ITEMS` in `live.ts`; feed sliced to 50 |
| AlertHistory default pageSize | 6 | `AlertHistory.svelte` prop default |
| Alerts view pageSize | 20 | `Alerts.svelte` passes 20 |
| RecentEvents default pageSize | 50 | `RecentEvents.svelte` prop default |
| Evidence preview | 5 | `EVIDENCE_PREVIEW` in `AlertDetailPanel.svelte` |
| Phone max cards/feed lines | 4 | CSS `nth-child(n + 5)` hidden at ≤767px |
| Request timeout | 10,000 ms | `DEFAULT_TIMEOUT_MS` in `http.ts` |
| Mock latency | 300 ms | `LATENCY_MS` in `mock.ts` |
| Mock live tick | 5,000 ms | `LIVE_TICK_MS` in `mock.ts` |
| WebSocket min backoff | 1 s | `MIN_BACKOFF_MS` in `ws.ts` |
| WebSocket max backoff | 30 s | `MAX_BACKOFF_MS` in `ws.ts` |
| Offline-after | 10 s | `OFFLINE_AFTER_MS` (= RETRY_SECONDS × 1000) |
| Poll interval | 10 s | `POLL_MS` (= RETRY_SECONDS × 1000) |
| Refresh debounce | 1 s | `REFRESH_DEBOUNCE_MS` in `ws.ts` |
| Retry interval (failed REST) | 10 s | `RETRY_SECONDS` in `health.ts` |
| Evidence list max-height | 320 px | `AlertDetailPanel.svelte` CSS |
| Feed max-height | 480 px | `LiveActivity.svelte` CSS |
| Recent events scroll max-height | 296 px | `RecentEvents.svelte` CSS |

String-length constraints: none enforced in frontend types (explanation is free-form `Record<string, unknown>`; `details` is free-form). IP validation is format-based (IPv4 dotted-quad each octet ≤ 255, or IPv6-ish hex/colon), not length-based.

## 5. Data flow between components

```
App.svelte
  ├── auth.init()                          // restores token/profile from localStorage
  ├── startLive() (when authenticated)     // ws.ts: connect() → WebSocket /ws or mock startMockLive
  └── router (hash) → view:
      ├── Overview                         // GET /api/stats + loadFeedHistory (events+alerts)
      │   ├── StatTiles (stats)
      │   ├── AlertHistory (selectedId, onSelect→ #/?alert=X)
      │   ├── RecentEvents (scroll)
      │   ├── AlertDetailPanel (side, when selectedId)
      │   └── LiveActivity (feed + connection)
      ├── Alerts                           // AlertHistory pageSize=20
      ├── Events                           // RecentEvents paged
      ├── AlertDetail (id)                 // AlertDetailPanel → GET /api/alerts/{id}
      ├── AdminDashboard                   // apiFetch /api/users (admin only)
      ├── Login                            // POST /token
      └── NotFound
```

Key stores and their owners:
- `api` (`client.ts`): the single `DataClient` every view uses; switches between `httpClient` and `mockClient` at build time via `dataSource` (`VITE_DATA_SOURCE`, default mock in DEV).
- `tracked()` wrapper: reports success/failure to `apiHealth` store; only unreachable/5xx count as "API down".
- `apiHealth` (`health.ts`): `ok`, `lastSuccessAt`, `error`; drives `ApiBanner` and header Offline state.
- `blocklist` (`blocklist.ts`): `writable<Map<string, BlockedIp>>` + `blocklistAvailable`; loaded once via `loadBlocklist()`.
- `feed` / `feedLoading` / `connection` / `displayedConnection` (`live.ts`): `displayedConnection` = offline when REST health is false, else WebSocket state.
- `alertsChanged` / `eventsChanged` (`alerts.ts` / `events.ts`): version counters bumped on status change / live event to trigger reloads.
- `auth` (`auth.ts`): `isAuthenticated`, `user`, `token`.

WebSocket flow (`ws.ts`):
1. `connect()` → real `WebSocket` to `/ws` (wss:// if https), or mock `startMockLive()` when `loadMockModule()` returns a module.
2. On message: `parseMessage(raw)` → if valid `LiveMessage`, `handle()` → `pushLive(message)` + debounced `refreshAlerts()`/`refreshEvents()` + `notifyAlertsChanged()`/`notifyEventsChanged()`.
3. Reconnect with jittered exponential backoff 1s→30s; after 10s without socket go `offline` and poll `GET /api/alerts` every 10s until socket returns.

Mock live flow (`mock.ts` `startMockLive`):
- Scenario `loading`: never connects (stays "Reconnecting…").
- Scenario `offline`/`error`/`ws-down`: calls `onClose` after `LATENCY_MS`.
- Scenario `empty`: opens but sends nothing.
- Otherwise: opens after `LATENCY_MS`, then every `LIVE_TICK_MS` (5s) generates a `liveEvent(tick)` (cycles dns_query / network_connection / http_request / auth_failure), pushes it into `events`, sends `{ kind: 'event', data }`. Every 4th event (`auth_failure`) increments alert id 41 (`auth_failures`) count and sends `{ kind: 'alert', data }` — simulating deduplication.

## 6. WebSocket message formats and response times

**Inbound message** (from server, JSON):
```json
{ "kind": "event", "data": { ...Event } }
{ "kind": "alert", "data": { ...Alert } }
```
Validation in `parseMessage` (`ws.ts`): top-level object; `kind` must be `'event'` or `'alert'`; `data` must be object with numeric `id`. Anything else ignored.

**Expected response times:**
- REST calls: mocked at 300ms latency (`LATENCY_MS`). Real HTTP wrapper defaults to a 10s timeout (`AbortSignal.timeout`).
- WebSocket open: mocked 300ms after `startMockLive`; real WebSocket `open` event.
- Reconnect backoff: 1s, 2s, 4s … 30s, jittered (±50%).
- Offline polling: every 10s.
- Failed alert status PATCH: optimistic UI update, rolled back; error shown; retry not automatic for PATCH.
- Failed GET (alerts/events): retry automatically every 10s.

## 7. Authentication / authorization expectations

- Login: `POST /token` body `{ username, password }` → `{ access_token, token_type, user }`.
- Token stored in `localStorage` (`cyber_mi6_token`); profile in `cyber_mi6_user`.
- Outgoing requests (via `apiFetch` in `services/api.ts`) send `Authorization: Bearer <token>` when a token exists; otherwise fall back to `X-API-Key: VITE_API_KEY` if set.
- `401` → `auth.logout()` (clears localStorage, redirects to `#/`).
- Admin route (`/admin`) guarded client-side: only `user.role === 'admin'` sees `AdminDashboard`; others get NotFound.
- The main `api`/`DataClient` (`client.ts`/`http.ts`) does **not** attach auth headers itself — it uses same-origin `fetch` without `Authorization`. Auth header logic lives only in `services/api.ts` (used by Login and AdminDashboard). This is a gap to be aware of if the real backend requires bearer tokens on `/api/*` endpoints.

## 8. How the mock client works and supported scenarios

`mock.ts` provides `mockClient`, an in-memory `DataClient` backed by `structuredClone` copies of `alertFixtures`/`eventFixtures` (`fixtures.ts`). All reads return clones (so callers can't corrupt store). Writes (status PATCH, block/unblock) persist in memory until reload.

**Scenarios** selected via `?mock=<name>` in the page URL (`scenario.ts`; read independently of fixtures so the header can show the notice without pulling fixtures into the bundle):

| Scenario | Behaviour |
|---|---|
| `normal` | Normal mocked responses, 300ms latency, live stream active |
| `loading` | Every request never resolves; live stream never connects (stays "Reconnecting…") |
| `empty` | Every list returns `[]`; stats zeros; live stream opens but sends nothing |
| `error` | Every request fails with HTTP 500 (`http_500`); live stream fails to connect |
| `offline` | Every request fails as unreachable (status 0); live stream fails to connect |
| `save-error` | Data loads normally, but every status PATCH and block/unblock fails with 422 `validation_error` |
| `ws-down` | Data loads normally, but the live stream never connects |

**Mock latency**: every response waits `LATENCY_MS` (300ms) and respects `AbortSignal` (abort rejects). `respond()` handles loading/offline/error before producing data.

**Filtering in mock:**
- `listAlerts`: filters by `severity`, `status`, `rule`; sorts newest first (`created_at`, then `id` desc); pages via `page()` (limit clamped 1–1000).
- `listEvents`: filters by `type`, `src_ip`, `from`, `to`; sorts newest first; pages.
- `getAlert`: 404 `http_404` when not found; evidence = events whose `id` is in `evidence_event_ids`, sorted newest first; missing retention events simply absent.
- `updateAlertStatus`: persists `status` + `updated_at` in memory; 422 in `save-error` scenario; 404 when missing.
- `blockIp`/`unblockIp`: in-memory `Map<string, BlockedIp>`; IP validation via `isIp` (422 `validation_error` for invalid IP); 404 on unblock of unknown IP.

**Mock live events** (`liveEvent(tick)`, cycles every 4 ticks):
- tick%4==0: `dns_query`, `laptop-sensor-1`, `192.168.1.25`, rotating `dns_name`
- tick%4==1: `network_connection`, `laptop-sensor-1`, `192.168.1.25` → `192.168.1.1`, rotating port, tcp
- tick%4==2: `http_request`, `test-webapp`, `172.16.4.9`, rotating path, status 200
- tick%4==3: `auth_failure`, `test-webapp`, `10.0.0.14`, username `admin` → increments alert 41

**Fixtures** (`fixtures.ts`): 7 design alerts (ids 37–41, 4890-series evidence) + filler alerts so totals match Figma: 41 alerts (5 critical, 9 high, 18 medium, 9 low; 23 open: 14 new, 9 investigating). 43 events (6 recent + 37 port-scan evidence). `EVENTS_TODAY = 12,480` and `TOP_SOURCES` are hardcoded Figma stat values the fixtures can't produce.

**Dev notice**: `DevScenarioNotice.svelte` shows a banner when `DEV && dataSource === 'mock' && scenario !== 'normal'`, linking to "Show normal demo data" (`urlWithoutScenario()`).

## 9. Alignment with docs/FRONTEND_SPEC.md

The frontend implementation matches `docs/FRONTEND_SPEC.md` as follows:

| Spec item | Implementation status |
|---|---|
| Stack: Svelte 5 + TS + Vite; `frontend/src/`; `dist/` served by FastAPI | Yes (`main.ts`, `App.svelte`, build scripts) |
| Header: name + WS connection status | `AppHeader.svelte` shows Live/Reconnecting/Offline dot + label |
| Stat tiles: events today, alerts by severity, open alerts, top source IP | `StatTiles`/`StatTile` from `GET /api/stats` |
| Live activity feed via WebSocket | `ws.ts` + `live.ts` feed + `LiveActivity` |
| Alert history table + severity/status/rule filters | `AlertHistory` (table + card list + Select filters) |
| Alert detail: why fired, thresholds, evidence, status buttons | `AlertDetailPanel` (`explain`, evidence list, status actions) |
| Recent events table + type filter | `RecentEvents` |
| Auto-reconnect + backoff + 10s polling fallback | `ws.ts` (1s→30s backoff, offline→poll every 10s) |
| Severity colours always with text label | `SeverityBadge` (dot + text), `StatusPill` |
| `textContent` not `innerHTML` for attacker-controlled strings | Svelte interpolation used throughout (domains/paths/usernames never in `innerHTML`) |
| Loading/empty/error states on every table | `StateBlock` used in `AlertHistory`, `RecentEvents`, `LiveActivity`, `AlertDetailPanel` |
| Responsive laptop + phone | Media queries at 767px/640px/1023px in components |
| Optimistic `PATCH /api/alerts/{id}` with rollback | `AlertDetailPanel.setStatus` |
| File layout matches spec | Close match; spec lists `types.ts`, `router.ts`, `alerts.ts`, `events.ts`, `ws.ts`, `theme.ts` under `lib/` and `api/` for HTTP — all present. Spec's `components/`/`views/` lists omit `BlockIpControl`, `FeedItem`, `LiveActivity`, `RecentEvents`, `StatTiles`, `StateBlock`, `ThemeToggle`, `DevScenarioNotice`, `ApiBanner`, `Card`, `Select`, `Button`, `AlertDetail.svelte`, `Events.svelte`, `Login.svelte`, `AdminDashboard.svelte`, `UserProfileSettings.svelte`, `services/api.ts`, `types/auth.ts` — the spec is slightly out of date relative to the code. |

## 10. Concrete valid data payload examples

### Event (network_connection)
```json
{
  "id": 4888,
  "type": "network_connection",
  "timestamp": "2026-11-07T09:21:38Z",
  "received_at": "2026-11-07T09:21:38Z",
  "source": "laptop-sensor-1",
  "src_ip": "192.168.1.25",
  "dst_ip": "192.168.1.1",
  "dst_port": 443,
  "protocol": "tcp",
  "dns_name": null,
  "username": null,
  "http_method": null,
  "http_path": null,
  "http_status": null,
  "user_agent": null,
  "details": null
}
```

### Event (auth_failure)
```json
{
  "id": 4890,
  "type": "auth_failure",
  "timestamp": "2026-11-07T09:21:47Z",
  "received_at": "2026-11-07T09:21:47Z",
  "source": "test-webapp",
  "src_ip": "10.0.0.14",
  "dst_ip": null,
  "dst_port": null,
  "protocol": null,
  "dns_name": null,
  "username": "admin",
  "http_method": null,
  "http_path": null,
  "http_status": null,
  "user_agent": null,
  "details": null
}
```

### Alert
```json
{
  "id": 41,
  "rule": "auth_failures",
  "severity": "critical",
  "title": "5 failed logins for admin in 2 min",
  "src_ip": "10.0.0.14",
  "evidence_event_ids": [4890],
  "explanation": { "threshold": 5, "window_seconds": 300, "observed": 5, "observed_window_seconds": 120, "username": "admin" },
  "created_at": "2026-11-07T09:21:47Z",
  "updated_at": "2026-11-07T09:21:47Z",
  "status": "new",
  "count": 1
}
```

### AlertDetail (GET /api/alerts/41)
```json
{
  "id": 41,
  "rule": "auth_failures",
  "severity": "critical",
  "title": "5 failed logins for admin in 2 min",
  "src_ip": "10.0.0.14",
  "evidence_event_ids": [4890],
  "explanation": { "threshold": 5, "window_seconds": 300, "observed": 5, "observed_window_seconds": 120, "username": "admin" },
  "created_at": "2026-11-07T09:21:47Z",
  "updated_at": "2026-11-07T09:21:47Z",
  "status": "new",
  "count": 1,
  "evidence": [ { ...event 4890... } ]
}
```

### Stats (GET /api/stats)
```json
{
  "events_today": 12480,
  "events_total": 12480,
  "alerts_total": 41,
  "open_alerts": 23,
  "alerts_by_severity": { "critical": 5, "high": 9, "medium": 18, "low": 9 },
  "alerts_by_status": { "new": 14, "investigating": 9, "resolved": 12, "false_positive": 6 },
  "top_source_ips": [
    { "src_ip": "192.168.1.25", "count": 1204 },
    { "src_ip": "172.16.4.9", "count": 611 },
    { "src_ip": "192.168.1.40", "count": 388 },
    { "src_ip": "10.0.0.14", "count": 142 },
    { "src_ip": "192.168.1.77", "count": 57 }
  ]
}
```

### EventFilters query (GET /api/events)
```
/api/events?type=auth_failure&src_ip=10.0.0.14&from=2026-11-07T09:00:00Z&to=2026-11-07T10:00:00Z&limit=50&offset=0
```

### AlertFilters query (GET /api/alerts)
```
/api/alerts?severity=critical&status=new&rule=auth_failures&limit=20&offset=0
```

### AlertUpdate (PATCH /api/alerts/41)
```json
{ "status": "resolved" }
```

### BlockRequest (POST /api/blocklist) — proposed
```json
{ "ip": "10.0.0.14", "alert_id": 41, "reason": "auth_failures: 5 failed logins for admin in 2 min" }
```

### BlockedIp (GET /api/blocklist) — proposed
```json
[
  { "ip": "10.0.0.14", "alert_id": 41, "reason": "auth_failures: 5 failed logins for admin in 2 min", "blocked_at": "2026-11-07T09:30:00Z" }
]
```

### Live WebSocket message
```json
{ "kind": "event", "data": { ...Event } }
{ "kind": "alert", "data": { ...Alert } }
```

### Auth (POST /token)
Request:
```json
{ "username": "analyst", "password": "..." }
```
Response:
```json
{ "access_token": "eyJ...", "token_type": "Bearer", "user": { "id": "u1", "username": "analyst", "role": "analyst", "permissions": [], "status": "active" } }
```

### UserProfile (GET /api/users, admin)
```json
[
  { "id": "u1", "username": "analyst", "role": "analyst", "permissions": [], "status": "active", "lastLogin": "2026-11-07T08:00:00Z" }
]
```

## 11. Known gaps / things to confirm before switching to the real API

- `AlertDetail` shape (`client.ts` line 20) is assumed: alert fields + `evidence: Event[]`. Confirm with the API owner.
- Blocklist endpoints (`/api/blocklist`) are proposed only; backend has no blocking yet. Frontend treats 404/405 as "endpoint unavailable".
- The main `DataClient`/`httpClient` does not attach `Authorization` bearer tokens; auth headers live only in `services/api.ts` (Login/Admin). If the real `/api/*` endpoints require bearer auth, add it to `request()` in `http.ts` or to the `api` client.
- `explanation` keys are free-form; `explain()` reads known keys per rule and falls back to raw pairs — defensive but not type-safe.
- `types.ts` and `router.ts` both define `Event`/`Alert`/`Stats`/etc. — duplicated; keep in sync.
- `UserProfileSettings.svelte` is an empty file (profile view not implemented).
