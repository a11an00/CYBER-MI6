/**
 * Live activity: the newest events and alerts, newest first.
 *
 * The feed starts from REST history (GET /api/events and /api/alerts) so it
 * isn't blank on page load; lib/ws.ts then prepends /ws messages through
 * `pushLive` and drives `connection`.
 */
import { derived, writable } from 'svelte/store';
import { api } from './api/client';
import { apiHealth } from './health';
import type { Alert, Event, LiveMessage } from './types';

export const MAX_FEED_ITEMS = 50;

export type FeedItem =
  | { kind: 'event'; id: string; at: string; data: Event }
  | { kind: 'alert'; id: string; at: string; data: Alert };

export type Connection = 'live' | 'reconnecting' | 'offline';

export const feed = writable<FeedItem[]>([]);
export const feedLoading = writable(true);

/** WebSocket state, set by lib/ws.ts. */
export const connection = writable<Connection>('reconnecting');

/** What the header and Live activity show: Offline whenever the REST API is down too. */
export const displayedConnection = derived([connection, apiHealth], ([$connection, $health]) =>
  $health.ok === false ? ('offline' as const) : $connection,
);

function toItem(message: LiveMessage): FeedItem {
  return message.kind === 'event'
    ? { kind: 'event', id: `event-${message.data.id}`, at: message.data.timestamp, data: message.data }
    : { kind: 'alert', id: `alert-${message.data.id}`, at: message.data.updated_at, data: message.data };
}

function newestFirst(items: FeedItem[]): FeedItem[] {
  return items.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : a.kind === 'alert' ? -1 : 1));
}

/** Add one live message; an alert update replaces that alert's older line. */
export function pushLive(message: LiveMessage): void {
  const item = toItem(message);
  feed.update((items) => newestFirst([item, ...items.filter((i) => i.id !== item.id)]).slice(0, MAX_FEED_ITEMS));
}

export async function loadFeedHistory(signal?: AbortSignal): Promise<void> {
  feedLoading.set(true);
  try {
    const [events, alerts] = await Promise.all([
      api.listEvents({ limit: MAX_FEED_ITEMS }, signal),
      api.listAlerts({ limit: MAX_FEED_ITEMS }, signal),
    ]);
    const items = [
      ...events.map((data) => toItem({ kind: 'event', data })),
      // History uses creation time: the moment the alert first appeared.
      ...alerts.map((data): FeedItem => ({ kind: 'alert', id: `alert-${data.id}`, at: data.created_at, data })),
    ];
    // Keep anything that arrived live while the history was loading.
    feed.update((current) => {
      const live = new Set(current.map((i) => i.id));
      return newestFirst([...current, ...items.filter((i) => !live.has(i.id))]).slice(0, MAX_FEED_ITEMS);
    });
  } finally {
    feedLoading.set(false);
  }
}
