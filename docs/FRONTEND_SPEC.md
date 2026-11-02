# CYBER-MI6 — Frontend Specification

## Stack

Svelte 5 + TypeScript + Vite. Source lives in `frontend/src/`. Build output goes to `frontend/dist/`, which FastAPI serves as static files.

---

## Dashboard sections

| Section | Contents |
|---|---|
| **Header** | CYBER-MI6 name, WebSocket connection status (connected / disconnected) |
| **Stat tiles** | Events today, alerts by severity, open alerts, top source IP |
| **Live activity feed** | New events and alerts appear instantly via WebSocket |
| **Alert history** | Table with severity, rule, title, source IP, time, status. Filters by severity, status, rule |
| **Alert detail** | Explanation of why the rule fired, thresholds, evidence events, status buttons |
| **Recent events** | Table of recent events with a type filter |

---

## Behaviour and UI rules

- `frontend/src/lib/ws.ts` reconnects automatically with backoff and falls back to polling `/api/alerts` every 10 seconds when the socket is down.
- Severity colours: low = green, medium = amber, high = orange, critical = red — always with a text label (not colour alone).
- **Insert API data with `textContent`, never `innerHTML`.** Domains, paths, usernames, and user agents are attacker-controlled strings.
- Loading, empty, and error states on every table.
- Responsive layout that works on a laptop and a phone browser.
- Status changes call `PATCH /api/alerts/{id}` and update the row immediately (optimistic update).
- Design source is Canva; exports go in `docs/` or `frontend/src/styles/`.

---

## File layout

```
frontend/src/
├── components/         # Reusable UI components
│   ├── AlertCard.svelte
│   ├── AlertDetailPanel.svelte
│   ├── AlertHistory.svelte
│   ├── AppHeader.svelte
│   ├── EventCard.svelte
│   ├── LiveActivity.svelte
│   ├── RecentEvents.svelte
│   ├── SeverityBadge.svelte
│   ├── StatTile.svelte
│   └── StatusPill.svelte
├── views/              # Page-level views (routed by lib/router.ts)
│   ├── Overview.svelte
│   ├── Alerts.svelte
│   ├── Events.svelte
│   ├── AlertDetail.svelte
│   └── NotFound.svelte
├── lib/
│   ├── api/            # HTTP client, fixtures, mock data
│   ├── ws.ts           # WebSocket client with reconnect + polling fallback
│   ├── alerts.ts       # Alert state and helpers
│   ├── events.ts       # Event state and helpers
│   ├── types.ts        # Shared TypeScript types
│   └── router.ts       # Client-side router
└── styles/
    └── tokens.css      # Design tokens (colours, spacing, severity palette)
```

---

## Building

```bash
cd frontend
npm install
npm run dev      # dev server with HMR at http://localhost:5173
npm run build    # production build → frontend/dist/
```

FastAPI automatically picks up `frontend/dist/` at startup if it exists; otherwise it falls back to `web/index.html`.
