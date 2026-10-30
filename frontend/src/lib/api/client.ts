/**
 * The data client every view uses. One interface, two implementations:
 *
 *   - httpClient: the real FastAPI endpoints (handbook §6)
 *   - mockClient: in-memory fixtures shaped exactly like backend/models.py
 *
 * Which one runs is decided once, at build time (see `dataSource` below), so
 * views never know or care where data comes from.
 */
import type { Alert, AlertFilters, AlertStatus, BlockedIp, BlockRequest, Event, EventFilters, Stats } from '../types';
import { reportFailure, reportSuccess } from '../health';
import { ApiError, buildQuery, request } from './http';

/**
 * GET /api/alerts/{id} returns "alert detail with evidence events" (handbook
 * §6). The exact shape is not in the repo yet; this assumes the alert fields
 * plus an `evidence` array. Confirm with the API owner before switching to the
 * real API, and adjust only this type and httpClient.getAlert.
 */
export type AlertDetail = Alert & { evidence: Event[] };

export interface DataClient {
  getStats(signal?: AbortSignal): Promise<Stats>;
  listAlerts(filters?: AlertFilters, signal?: AbortSignal): Promise<Alert[]>;
  getAlert(id: number, signal?: AbortSignal): Promise<AlertDetail>;
  updateAlertStatus(id: number, status: AlertStatus): Promise<Alert>;
  listEvents(filters?: EventFilters, signal?: AbortSignal): Promise<Event[]>;
  listBlocked(signal?: AbortSignal): Promise<BlockedIp[]>;
  blockIp(body: BlockRequest): Promise<BlockedIp>;
  unblockIp(ip: string): Promise<void>;
}

export const httpClient: DataClient = {
  getStats: (signal) => request<Stats>('GET', '/api/stats', { signal }),
  listAlerts: (filters = {}, signal) =>
    request<Alert[]>('GET', `/api/alerts${buildQuery({ ...filters })}`, { signal }),
  getAlert: (id, signal) => request<AlertDetail>('GET', `/api/alerts/${id}`, { signal }),
  updateAlertStatus: (id, status) => request<Alert>('PATCH', `/api/alerts/${id}`, { body: { status } }),
  listEvents: (filters = {}, signal) =>
    request<Event[]>('GET', `/api/events${buildQuery({ ...filters })}`, { signal }),

  /*
   * PROPOSED blocklist endpoints. The backend has no blocking yet; these are
   * the frontend's suggested contract, to be agreed with the API owner:
   *   GET    /api/blocklist        → BlockedIp[]
   *   POST   /api/blocklist        {ip, alert_id?, reason?} → BlockedIp (201)
   *   DELETE /api/blocklist/{ip}   → 204
   * Enforcement (actually refusing the traffic) is the backend's job.
   * Until they exist, the real API answers 404 and the panel says so.
   */
  listBlocked: (signal) => request<BlockedIp[]>('GET', '/api/blocklist', { signal }),
  blockIp: (body) => request<BlockedIp>('POST', '/api/blocklist', { body }),
  unblockIp: async (ip) => {
    await request<null>('DELETE', `/api/blocklist/${encodeURIComponent(ip)}`);
  },
};

/**
 * "mock" in development by default, "api" in production builds. Override with
 * VITE_DATA_SOURCE=api (or =mock) in frontend/.env.local. Mock data is never
 * used in a production build unless someone sets it explicitly.
 */
export const dataSource: 'mock' | 'api' =
  import.meta.env.VITE_DATA_SOURCE === 'api' || import.meta.env.VITE_DATA_SOURCE === 'mock'
    ? import.meta.env.VITE_DATA_SOURCE
    : import.meta.env.DEV
      ? 'mock'
      : 'api';

/**
 * The mock module, or null when using the real API. Every mock import goes
 * through here: `dataSource` is a build-time constant in this file, so a
 * production build drops the import (and the fixtures) entirely.
 */
export function loadMockModule(): Promise<typeof import('./mock')> | null {
  return dataSource === 'mock' ? import('./mock') : null;
}

let mock: Promise<DataClient> | null = null;

async function resolve(): Promise<DataClient> {
  const module = loadMockModule();
  if (!module) return httpClient;
  mock ??= module.then((m) => m.mockClient);
  return mock;
}

/**
 * Every call reports to the shared API-health store, so the banner and the
 * header's Offline state react whichever page made the request. Only
 * "the API is down" failures count: unreachable or a 5xx. A 404 or 422 means
 * the API is up and answered.
 */
async function tracked<T>(call: () => Promise<T>): Promise<T> {
  try {
    const result = await call();
    reportSuccess();
    return result;
  } catch (err) {
    if (err instanceof ApiError && (err.unreachable || err.status >= 500)) reportFailure(err);
    throw err;
  }
}

export const api: DataClient = {
  getStats: (signal) => tracked(async () => (await resolve()).getStats(signal)),
  listAlerts: (filters, signal) => tracked(async () => (await resolve()).listAlerts(filters, signal)),
  getAlert: (id, signal) => tracked(async () => (await resolve()).getAlert(id, signal)),
  updateAlertStatus: (id, status) => tracked(async () => (await resolve()).updateAlertStatus(id, status)),
  listEvents: (filters, signal) => tracked(async () => (await resolve()).listEvents(filters, signal)),
  listBlocked: (signal) => tracked(async () => (await resolve()).listBlocked(signal)),
  blockIp: (body) => tracked(async () => (await resolve()).blockIp(body)),
  unblockIp: (ip) => tracked(async () => (await resolve()).unblockIp(ip)),
};
