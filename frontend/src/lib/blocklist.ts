/**
 * Blocked IPs, shared by every view so all alerts from one source agree.
 *
 * Blocking is a security action, so unlike alert status changes it is NOT
 * optimistic: the UI shows "Blocked" only after the API confirms it.
 */
import { writable } from 'svelte/store';
import { api } from './api/client';
import { ApiError } from './api/http';
import type { BlockedIp } from './types';

export const blocklist = writable<Map<string, BlockedIp>>(new Map());
/** False when the API has no blocklist endpoint yet (404/405). */
export const blocklistAvailable = writable(true);

let loaded = false;

function isMissingEndpoint(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 405);
}

export async function loadBlocklist(signal?: AbortSignal): Promise<void> {
  if (loaded) return;
  try {
    const entries = await api.listBlocked(signal);
    blocklist.set(new Map(entries.map((e) => [e.ip, e])));
    blocklistAvailable.set(true);
    loaded = true;
  } catch (err) {
    if (isMissingEndpoint(err)) blocklistAvailable.set(false);
    // Other failures: the API-health banner already says so; retry next time.
  }
}

/** A message fit to show the analyst, for a failed block or unblock. */
export function blockErrorMessage(err: unknown): string {
  if (isMissingEndpoint(err)) return "Blocking isn't available yet: the API has no /api/blocklist endpoint.";
  if (err instanceof ApiError) return err.message;
  return String(err);
}

export async function blockIp(ip: string, alertId: number, reason: string): Promise<void> {
  try {
    const entry = await api.blockIp({ ip, alert_id: alertId, reason });
    blocklist.update((m) => new Map(m).set(entry.ip, entry));
  } catch (err) {
    if (isMissingEndpoint(err)) blocklistAvailable.set(false);
    throw err;
  }
}

export async function unblockIp(ip: string): Promise<void> {
  await api.unblockIp(ip);
  blocklist.update((m) => {
    const next = new Map(m);
    next.delete(ip);
    return next;
  });
}
