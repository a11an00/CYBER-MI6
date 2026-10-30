/**
 * In-memory DataClient for development. Mirrors the backend's behaviour where
 * it matters to the UI: newest-first ordering, filters, limit/offset, 404s,
 * status updates that persist (until reload).
 *
 * To preview the Figma "Data states" frames, add ?mock=<scenario> to the page
 * URL (before the #):
 *   ?mock=loading   requests never resolve
 *   ?mock=empty     every list is empty
 *   ?mock=error     every request fails with HTTP 500
 *   ?mock=offline   every request fails as unreachable
 *   ?mock=save-error  data loads, but every change (status PATCH, block/unblock) fails
 *   ?mock=ws-down   data loads, but the live stream never connects
 *
 * startMockLive() stands in for WebSocket /ws: a new event every few seconds
 * and, now and then, an updated alert, written into the same in-memory data
 * the REST calls read, so tables and the feed agree.
 */
import type { Alert, AlertFilters, AlertStatus, BlockedIp, Event, EventFilters, Stats } from '../types';
import { ALERT_STATUSES, OPEN_STATUSES, SEVERITIES } from '../types';
import type { LiveHandlers } from '../ws';
import type { AlertDetail, DataClient } from './client';
import { alerts as alertFixtures, events as eventFixtures } from './fixtures';
import { ApiError } from './http';
import { scenario } from './scenario';

const LATENCY_MS = 300;
const DEFAULT_LIMIT = 100; // storage.DEFAULT_LIST_LIMIT
const MAX_LIMIT = 1000; // storage.MAX_LIST_LIMIT

/** Figma "Dashboard — Desktop" stat values the fixtures can't produce on their own. */
const EVENTS_TODAY = 12_480;
const TOP_SOURCES = [
  { src_ip: '192.168.1.25', count: 1_204 },
  { src_ip: '172.16.4.9', count: 611 },
  { src_ip: '192.168.1.40', count: 388 },
  { src_ip: '10.0.0.14', count: 142 },
  { src_ip: '192.168.1.77', count: 57 },
];

const alerts: Alert[] = structuredClone(alertFixtures);
const events: Event[] = structuredClone(eventFixtures);
const FIXTURE_EVENT_COUNT = events.length;

const byNewest = (a: string, b: string) => (a < b ? 1 : a > b ? -1 : 0);

function page<T>(rows: T[], limit = DEFAULT_LIMIT, offset = 0): T[] {
  const n = Math.max(1, Math.min(limit, MAX_LIMIT));
  return rows.slice(Math.max(0, offset), Math.max(0, offset) + n);
}

async function respond<T>(path: string, produce: () => T, signal?: AbortSignal): Promise<T> {
  if (scenario === 'loading') return new Promise<T>(() => {});
  signal?.throwIfAborted();
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, LATENCY_MS);
    signal?.addEventListener('abort', () => {
      clearTimeout(timer);
      reject(signal.reason);
    });
  });
  if (scenario === 'offline') throw new ApiError(0, path, `GET ${path} couldn't be reached`);
  if (scenario === 'error') throw new ApiError(500, path, 'Internal Server Error', 'http_500');
  return structuredClone(produce());
}

const isEmpty = () => scenario === 'empty';

const blocklist = new Map<string, BlockedIp>();

/** Same rule the backend uses for src_ip (models._check_ip): a valid IPv4/IPv6 address. */
function isIp(value: string): boolean {
  if (/^(\d{1,3})(\.\d{1,3}){3}$/.test(value)) return value.split('.').every((n) => Number(n) <= 255);
  return value.includes(':') && /^[0-9a-f:.]+$/i.test(value);
}

export const mockClient: DataClient = {
  getStats: (signal) =>
    respond<Stats>('/api/stats', () => {
      const source = isEmpty() ? [] : alerts;
      const by_severity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Stats['alerts_by_severity'];
      const by_status = Object.fromEntries(ALERT_STATUSES.map((s) => [s, 0])) as Stats['alerts_by_status'];
      for (const a of source) {
        by_severity[a.severity]++;
        by_status[a.status]++;
      }
      return {
        // Live mock events (startMockLive) add to the Figma figure.
        events_today: isEmpty() ? 0 : EVENTS_TODAY + events.length - FIXTURE_EVENT_COUNT,
        events_total: isEmpty() ? 0 : EVENTS_TODAY + events.length - FIXTURE_EVENT_COUNT,
        alerts_total: source.length,
        open_alerts: OPEN_STATUSES.reduce((sum, s) => sum + by_status[s], 0),
        alerts_by_severity: by_severity,
        alerts_by_status: by_status,
        top_source_ips: isEmpty() ? [] : TOP_SOURCES,
      };
    }, signal),

  listAlerts: (filters: AlertFilters = {}, signal) =>
    respond('/api/alerts', () => {
      if (isEmpty()) return [];
      const rows = alerts
        .filter((a) => !filters.severity || a.severity === filters.severity)
        .filter((a) => !filters.status || a.status === filters.status)
        .filter((a) => !filters.rule || a.rule === filters.rule)
        .sort((a, b) => byNewest(a.created_at, b.created_at) || b.id - a.id);
      return page(rows, filters.limit, filters.offset);
    }, signal),

  getAlert: (id, signal) =>
    respond<AlertDetail>(`/api/alerts/${id}`, () => {
      const found = isEmpty() ? undefined : alerts.find((a) => a.id === id);
      if (!found) throw new ApiError(404, `/api/alerts/${id}`, 'Alert not found', 'http_404');
      const ids = new Set(found.evidence_event_ids);
      // Like storage.get_alert_evidence: events removed by retention are just absent.
      const evidence = events
        .filter((e) => ids.has(e.id))
        .sort((a, b) => byNewest(a.timestamp, b.timestamp) || b.id - a.id);
      return { ...found, evidence };
    }, signal),

  updateAlertStatus: (id, status: AlertStatus) =>
    respond(`/api/alerts/${id}`, () => {
      if (scenario === 'save-error')
        throw new ApiError(422, `/api/alerts/${id}`, 'Status change rejected by the API', 'validation_error');
      const found = alerts.find((a) => a.id === id);
      if (!found) throw new ApiError(404, `/api/alerts/${id}`, 'Alert not found', 'http_404');
      found.status = status;
      found.updated_at = new Date().toISOString();
      return found;
    }),

  listEvents: (filters: EventFilters = {}, signal) =>
    respond('/api/events', () => {
      if (isEmpty()) return [];
      const rows = events
        .filter((e) => !filters.type || e.type === filters.type)
        .filter((e) => !filters.src_ip || e.src_ip === filters.src_ip)
        .filter((e) => !filters.from || e.timestamp >= filters.from)
        .filter((e) => !filters.to || e.timestamp <= filters.to)
        .sort((a, b) => byNewest(a.timestamp, b.timestamp) || b.id - a.id);
      return page(rows, filters.limit, filters.offset);
    }, signal),

  listBlocked: (signal) =>
    respond('/api/blocklist', () => (isEmpty() ? [] : [...blocklist.values()]), signal),

  blockIp: (body) =>
    respond('/api/blocklist', () => {
      if (scenario === 'save-error') throw new ApiError(422, '/api/blocklist', 'Block rejected by the API', 'validation_error');
      if (!isIp(body.ip)) throw new ApiError(422, '/api/blocklist', `not a valid IP address: '${body.ip}'`, 'validation_error');
      const entry: BlockedIp = {
        ip: body.ip,
        alert_id: body.alert_id ?? null,
        reason: body.reason ?? null,
        blocked_at: new Date().toISOString(),
      };
      blocklist.set(body.ip, entry);
      return entry;
    }),

  unblockIp: (ip) =>
    respond(`/api/blocklist/${ip}`, () => {
      if (scenario === 'save-error') throw new ApiError(422, `/api/blocklist/${ip}`, 'Unblock rejected by the API', 'validation_error');
      if (!blocklist.delete(ip)) throw new ApiError(404, `/api/blocklist/${ip}`, 'IP is not blocked', 'http_404');
    }),
};

// --- live stream (stands in for WebSocket /ws) --------------------------------

const LIVE_TICK_MS = 5_000;
const DOMAINS = ['api.github.com', 'fonts.gstatic.com', 'update.microsoft.com', 'time.windows.com', 'cdn.jsdelivr.net'];
const PORTS = [443, 80, 53, 22, 8080];
const PATHS = ['/', '/login', '/static/app.js', '/api/health'];

let nextEventId = Math.max(...events.map((e) => e.id)) + 1;

function liveEvent(tick: number): Event {
  const base = {
    id: nextEventId++,
    timestamp: new Date().toISOString(),
    received_at: new Date().toISOString(),
    dst_ip: null, dst_port: null, protocol: null, dns_name: null, username: null,
    http_method: null, http_path: null, http_status: null, user_agent: null, details: null,
  } satisfies Partial<Event>;
  switch (tick % 4) {
    case 0:
      return { ...base, type: 'dns_query', source: 'laptop-sensor-1', src_ip: '192.168.1.25', dns_name: DOMAINS[tick % DOMAINS.length] };
    case 1:
      return { ...base, type: 'network_connection', source: 'laptop-sensor-1', src_ip: '192.168.1.25',
        dst_ip: '192.168.1.1', dst_port: PORTS[tick % PORTS.length], protocol: 'tcp' };
    case 2:
      return { ...base, type: 'http_request', source: 'test-webapp', src_ip: '172.16.4.9',
        http_method: 'GET', http_path: PATHS[tick % PATHS.length], http_status: 200 };
    default:
      return { ...base, type: 'auth_failure', source: 'test-webapp', src_ip: '10.0.0.14', username: 'admin' };
  }
}

export function startMockLive(handlers: LiveHandlers): () => void {
  if (scenario === 'loading') return () => {}; // stays "Reconnecting…"
  if (scenario === 'offline' || scenario === 'error' || scenario === 'ws-down') {
    const t = setTimeout(handlers.onClose, LATENCY_MS); // connection refused
    return () => clearTimeout(t);
  }
  const open = setTimeout(handlers.onOpen, LATENCY_MS);
  if (scenario === 'empty') return () => clearTimeout(open);

  let tick = 0;
  const timer = setInterval(() => {
    tick += 1;
    const event = liveEvent(tick);
    events.push(event);
    handlers.onMessage({ kind: 'event', data: structuredClone(event) });
    // Every fourth event is a failed login; the auth_failures alert absorbs it
    // (deduplication: same rule + IP updates one alert, count goes up).
    if (event.type === 'auth_failure') {
      const alert = alerts.find((a) => a.id === 41);
      if (alert) {
        alert.count += 1;
        alert.updated_at = event.timestamp;
        alert.evidence_event_ids = [...alert.evidence_event_ids, event.id];
        handlers.onMessage({ kind: 'alert', data: structuredClone(alert) });
      }
    }
  }, LIVE_TICK_MS);

  return () => {
    clearTimeout(open);
    clearInterval(timer);
  };
}
