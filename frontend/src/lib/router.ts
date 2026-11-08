/**
 * Hash-based client-side router.
 *
 * Routes live after the "#" (e.g. /#/alerts/17) so FastAPI only ever serves
 * index.html and needs no per-route setup. Anything after "?" in the hash is
 * kept in `query` so views can later store filters in the URL.
 */
import { readable } from 'svelte/store';

export type Route =
  | { name: 'overview' }
  | { name: 'alerts' }
  | { name: 'alert-detail'; id: number }
  | { name: 'events' }
  | { name: 'admin' }
  | { name: 'profile' }
  | { name: 'not-found'; path: string };

export interface Location {
  route: Route;
  query: URLSearchParams;
}

const POSITIVE_INT = /^[1-9]\d*$/;

export function parseHash(hash: string): Location {
  const raw = hash.replace(/^#/, '');
  const q = raw.indexOf('?');
  const path = (q === -1 ? raw : raw.slice(0, q)) || '/';
  const query = new URLSearchParams(q === -1 ? '' : raw.slice(q + 1));
  const parts = path.split('/').filter(Boolean);

  let route: Route;
  if (parts.length === 0) route = { name: 'overview' };
  else if (parts.length === 1 && parts[0] === 'alerts') route = { name: 'alerts' };
  else if (parts.length === 2 && parts[0] === 'alerts' && POSITIVE_INT.test(parts[1]))
    route = { name: 'alert-detail', id: Number(parts[1]) };
  else if (parts.length === 1 && parts[0] === 'events') route = { name: 'events' };
  else if (parts.length === 1 && parts[0] === 'admin') route = { name: 'admin' };
  else if (parts.length === 1 && parts[0] === 'profile') route = { name: 'profile' };
  else route = { name: 'not-found', path };

  return { route, query };
}

/** The current location; updates whenever the hash changes. */
export const location = readable<Location>(parseHash(window.location.hash), (set) => {
  const update = () => set(parseHash(window.location.hash));
  window.addEventListener('hashchange', update);
  return () => window.removeEventListener('hashchange', update);
});

/** Link targets, so views never hand-build route strings. */
export const href = {
  overview: '#/',
  alerts: '#/alerts',
  alert: (id: number) => `#/alerts/${id}`,
  events: '#/events',
  admin: '#/admin',
  profile: '#/profile',
} as const;

export function navigate(to: string): void {
  window.location.hash = to;
}

/**
 * API response shapes. These mirror app/models.py exactly; when that file
 * changes, change this one in the same pull request.
 *
 * Datetimes arrive as ISO 8601 strings in UTC (Pydantic's JSON encoding).
 */

export const EVENT_TYPES = ['network_connection', 'dns_query', 'auth_failure', 'http_request'] as const;
export const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export const ALERT_STATUSES = ['new', 'investigating', 'resolved', 'false_positive'] as const;
/** Statuses counted as "open" (models.OPEN_STATUSES). */
export const OPEN_STATUSES = ['new', 'investigating'] as const;

export type EventType = (typeof EVENT_TYPES)[number];
export type Severity = (typeof SEVERITIES)[number];
export type AlertStatus = (typeof ALERT_STATUSES)[number];

/** Rule names used by the detection engine (app/detection/). */
export const RULES = ['port_scan', 'dns_anomaly', 'auth_failures', 'web_paths'] as const;
export type Rule = (typeof RULES)[number];

type IsoDateTime = string;
type DetailValue = string | number | boolean | null;

/** models.Event: a stored event. Type-specific fields are null when unused. */
export interface Event {
  id: number;
  type: EventType;
  timestamp: IsoDateTime;
  received_at: IsoDateTime;
  source: string;
  src_ip: string;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: 'tcp' | 'udp' | null;
  dns_name: string | null;
  username: string | null;
  http_method: string | null;
  http_path: string | null;
  http_status: number | null;
  user_agent: string | null;
  details: Record<string, DetailValue> | null;
}

/**
 * models.Alert. `explanation` is free-form until the detection engine defines
 * its keys (open question for the backend team), so read it defensively.
 */
export interface Alert {
  id: number;
  rule: string;
  severity: Severity;
  title: string;
  src_ip: string | null;
  evidence_event_ids: number[];
  explanation: Record<string, unknown>;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
  status: AlertStatus;
  count: number;
}

/** models.AlertUpdate: body of PATCH /api/alerts/{id}. */
export interface AlertUpdate {
  status: AlertStatus;
}

export interface TopSource {
  src_ip: string;
  count: number;
}

/** models.Stats: response of GET /api/stats. */
export interface Stats {
  events_today: number;
  events_total: number;
  alerts_total: number;
  open_alerts: number;
  alerts_by_severity: Record<Severity, number>;
  alerts_by_status: Record<AlertStatus, number>;
  top_source_ips: TopSource[];
}

/** Query filters for GET /api/events (handbook §6). */
export interface EventFilters {
  type?: EventType;
  src_ip?: string;
  from?: IsoDateTime;
  to?: IsoDateTime;
  limit?: number;
  offset?: number;
}

/** Query filters for GET /api/alerts (handbook §6). */
export interface AlertFilters {
  severity?: Severity;
  status?: AlertStatus;
  rule?: string;
  limit?: number;
  offset?: number;
}

/** WebSocket message from /ws (app/routes/ws.py). */
export type LiveMessage = { kind: 'event'; data: Event } | { kind: 'alert'; data: Alert };