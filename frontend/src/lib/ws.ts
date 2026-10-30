/**
 * Live updates (handbook §9): WebSocket /ws with automatic reconnect and a
 * polling fallback.
 *
 *   connected            → "Live"
 *   dropped / retrying   → "Reconnecting…"  (backoff 1 s, 2 s, 4 s … 30 s, jittered)
 *   down for 10 seconds  → "Offline · polling every 10s": GET /api/alerts every
 *                          10 s until the socket is back
 *
 * Messages are {"kind": "event" | "alert", "data": {...}} (app/routes/ws.py).
 * They come from the network, so anything not shaped like that is ignored.
 */
import { api, loadMockModule } from './api/client';
import { notifyAlertsChanged } from './alerts';
import { notifyEventsChanged } from './events';
import { RETRY_SECONDS } from './health';
import { connection, pushLive } from './live';
import type { Alert, LiveMessage } from './types';

const MIN_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 30_000;
const OFFLINE_AFTER_MS = RETRY_SECONDS * 1000;
const POLL_MS = RETRY_SECONDS * 1000;
/** Bursts of messages (a port scan is dozens of SYNs) cause one reload, not dozens. */
const REFRESH_DEBOUNCE_MS = 1_000;

export interface LiveHandlers {
  onMessage: (message: LiveMessage) => void;
  onOpen: () => void;
  onClose: () => void;
}

export function parseMessage(raw: unknown): LiveMessage | null {
  let value: unknown = raw;
  if (typeof raw === 'string') {
    try {
      value = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  if (!value || typeof value !== 'object') return null;
  const { kind, data } = value as { kind?: unknown; data?: unknown };
  if ((kind !== 'event' && kind !== 'alert') || !data || typeof data !== 'object') return null;
  if (typeof (data as { id?: unknown }).id !== 'number') return null;
  return { kind, data } as LiveMessage;
}

function debounce(fn: () => void, ms: number): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return () => {
    clearTimeout(timer);
    timer = setTimeout(fn, ms);
  };
}

const refreshAlerts = debounce(notifyAlertsChanged, REFRESH_DEBOUNCE_MS);
const refreshEvents = debounce(notifyEventsChanged, REFRESH_DEBOUNCE_MS);

function handle(message: LiveMessage): void {
  pushLive(message);
  if (message.kind === 'alert') refreshAlerts();
  else refreshEvents();
}

// --- connection state machine ---------------------------------------------

let started = false;
let socket: WebSocket | null = null;
let stopMock: (() => void) | null = null;
let attempt = 0;
let retryTimer: ReturnType<typeof setTimeout> | undefined;
let offlineTimer: ReturnType<typeof setTimeout> | undefined;
let pollTimer: ReturnType<typeof setInterval> | undefined;
let offline = false;

function onOpen(): void {
  attempt = 0;
  offline = false;
  clearTimeout(offlineTimer);
  offlineTimer = undefined;
  stopPolling();
  connection.set('live');
  // Anything that changed while we were disconnected.
  refreshAlerts();
  refreshEvents();
}

function onClose(): void {
  socket = null;
  if (!offline) connection.set('reconnecting');
  offlineTimer ??= setTimeout(goOffline, OFFLINE_AFTER_MS);
  const backoff = Math.min(MAX_BACKOFF_MS, MIN_BACKOFF_MS * 2 ** attempt);
  attempt += 1;
  clearTimeout(retryTimer);
  retryTimer = setTimeout(connect, backoff / 2 + Math.random() * (backoff / 2));
}

function goOffline(): void {
  offline = true;
  connection.set('offline');
  startPolling();
}

function connect(): void {
  const mockModule = loadMockModule();
  if (mockModule) {
    stopMock?.();
    mockModule.then((m) => {
      stopMock = m.startMockLive({ onMessage: handle, onOpen, onClose });
    });
    return;
  }
  const url = new URL('/ws', window.location.href);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  try {
    socket = new WebSocket(url);
  } catch {
    onClose();
    return;
  }
  socket.addEventListener('open', onOpen);
  socket.addEventListener('message', (e) => {
    const message = parseMessage(e.data);
    if (message) handle(message);
  });
  // An error is always followed by close; reconnect once, from close.
  socket.addEventListener('close', onClose);
}

// --- polling fallback ------------------------------------------------------

const seen = new Map<number, string>(); // alert id → updated_at
let seeded = false;

async function poll(): Promise<void> {
  try {
    const alerts: Alert[] = await api.listAlerts({ limit: 50 });
    let changed = false;
    for (const a of [...alerts].sort((x, y) => (x.updated_at < y.updated_at ? -1 : 1))) {
      if (seen.get(a.id) === a.updated_at) continue;
      seen.set(a.id, a.updated_at);
      if (seeded) {
        pushLive({ kind: 'alert', data: a });
        changed = true;
      }
    }
    seeded = true;
    if (changed) notifyAlertsChanged();
    // The API answered, so the backend is up: retry the socket now instead
    // of waiting out a backoff that may have grown to 30 s.
    if (!socket && !stopMock) {
      clearTimeout(retryTimer);
      connect();
    }
  } catch {
    // The API-health store already shows the banner; keep polling.
  }
}

function startPolling(): void {
  if (pollTimer) return;
  poll();
  pollTimer = setInterval(poll, POLL_MS);
}

function stopPolling(): void {
  clearInterval(pollTimer);
  pollTimer = undefined;
}

// --- public API --------------------------------------------------------------

/** Start once for the whole app (App.svelte). */
export function startLive(): () => void {
  if (started) return stopLive;
  started = true;
  connect();
  return stopLive;
}

/** The "Reconnect" button: try now and reset the backoff. */
export function reconnectNow(): void {
  clearTimeout(retryTimer);
  attempt = 0;
  if (socket && socket.readyState <= WebSocket.OPEN) return;
  connection.set(offline ? 'offline' : 'reconnecting');
  connect();
}

export function stopLive(): void {
  started = false;
  clearTimeout(retryTimer);
  clearTimeout(offlineTimer);
  offlineTimer = undefined;
  stopPolling();
  stopMock?.();
  stopMock = null;
  if (socket) {
    socket.removeEventListener('close', onClose);
    socket.close();
    socket = null;
  }
}
