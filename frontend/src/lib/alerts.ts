/**
 * One page of the alert history table.
 *
 * GET /api/alerts filters by a single status and returns no total count, so:
 *   - "Open" (the Figma default) = status=new plus status=investigating,
 *     fetched in parallel and merged newest first;
 *   - whether a next page exists is found by asking for one extra row;
 *   - the total ("41 alerts", "Showing 1–6 of 41") comes from GET /api/stats
 *     when the filters map onto its counts, and is null otherwise.
 * If the API gains `status=open` or a total, only this file changes.
 */
import { writable } from 'svelte/store';
import { api } from './api/client';
import type { Alert, AlertStatus, Severity, Stats } from './types';
import { OPEN_STATUSES } from './types';

export type StatusFilter = AlertStatus | 'open' | 'all';
export type SeverityFilter = Severity | 'all';

export interface AlertQuery {
  severity: SeverityFilter;
  status: StatusFilter;
  rule: string; // 'all' or a rule name
}

export const DEFAULT_QUERY: AlertQuery = { severity: 'all', status: 'open', rule: 'all' };

/** Bump to make every alert list reload (after a status change or a live alert). */
export const alertsChanged = writable(0);
export const notifyAlertsChanged = () => alertsChanged.update((n) => n + 1);

export interface AlertPage {
  rows: Alert[];
  hasNext: boolean;
  total: number | null;
}

const newestFirst = (a: Alert, b: Alert) =>
  a.created_at < b.created_at ? 1 : a.created_at > b.created_at ? -1 : b.id - a.id;

function totalFromStats(q: AlertQuery, s: Stats): number | null {
  const sev = q.severity !== 'all';
  const rule = q.rule !== 'all';
  if (rule) return null;
  if (!sev && q.status === 'all') return s.alerts_total;
  if (!sev && q.status === 'open') return s.open_alerts;
  if (!sev && q.status !== 'all') return s.alerts_by_status[q.status as AlertStatus];
  if (sev && q.status === 'all') return s.alerts_by_severity[q.severity as Severity];
  return null; // severity + status combination: not in /api/stats
}

export async function fetchAlertPage(
  q: AlertQuery,
  page: number,
  pageSize: number,
  signal?: AbortSignal,
): Promise<AlertPage> {
  const base = {
    severity: q.severity === 'all' ? undefined : q.severity,
    rule: q.rule === 'all' ? undefined : q.rule,
  };
  const offset = page * pageSize;
  const wanted = pageSize + 1; // one extra row tells us whether there's a next page

  let rows: Alert[];
  if (q.status === 'open') {
    // Each status needs rows up to the end of this page, then merge and slice.
    const lists = await Promise.all(
      OPEN_STATUSES.map((status) => api.listAlerts({ ...base, status, limit: offset + wanted }, signal)),
    );
    rows = lists.flat().sort(newestFirst).slice(offset, offset + wanted);
  } else {
    rows = await api.listAlerts(
      { ...base, status: q.status === 'all' ? undefined : q.status, limit: wanted, offset },
      signal,
    );
  }

  const needsStats = q.rule === 'all' && !(q.severity !== 'all' && q.status !== 'all');
  const total = needsStats ? totalFromStats(q, await api.getStats(signal)) : null;

  return { rows: rows.slice(0, pageSize), hasNext: rows.length > pageSize, total };
}
