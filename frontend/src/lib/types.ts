/**
 * API response shapes. These mirror backend/models.py exactly; when that file
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

/** Rule names used by the detection engine (backend/detection/). */
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
