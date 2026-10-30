import type { Alert, Event } from './types';

/**
 * "09:21:47". Times are shown in UTC, the same clock the backend stores
 * (handbook §6), so every analyst sees the same value for the same event.
 */
export function clockTime(iso: string): string {
  return new Date(iso).toISOString().slice(11, 19);
}

/** "2s ago", "5 min ago", "3 h ago"; older than a day shows the date. */
export function relativeTime(iso: string, now = Date.now()): string {
  const seconds = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)} h ago`;
  return `on ${iso.slice(0, 10)}`;
}

/** One-line summary of an event, as in the Figma feed and Recent events rows. */
export function eventSummary(e: Event): string {
  switch (e.type) {
    case 'network_connection':
      return `${e.dst_ip}:${e.dst_port}`;
    case 'dns_query':
      return e.dns_name ?? '';
    case 'auth_failure':
      return `${e.username} from ${e.src_ip}`;
    case 'http_request':
      return `${e.http_method} ${e.http_path}${e.http_status ? ` → ${e.http_status}` : ''}`;
  }
}

/**
 * The "Target" column of Recent events (Figma Event Table Row): dst_ip:port,
 * dns_name, the HTTP request, or the username, depending on the type.
 */
export function eventTarget(e: Event): string {
  switch (e.type) {
    case 'network_connection':
      return `${e.dst_ip}:${e.dst_port}${e.protocol ? ` ${e.protocol}` : ''}`;
    case 'dns_query':
      return e.dns_name ?? '';
    case 'auth_failure':
      return `username=${e.username}`;
    case 'http_request':
      return `${e.http_method} ${e.http_path}${e.http_status ? ` → ${e.http_status}` : ''}`;
  }
}

export function alertSummary(a: Alert): string {
  return a.title;
}
