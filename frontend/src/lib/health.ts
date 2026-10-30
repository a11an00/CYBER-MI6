/**
 * Whether the REST API is answering. Figma "Data states → Global · API
 * unreachable": a banner appears and the header switches to Offline, while
 * the last good data stays on screen.
 */
import { writable } from 'svelte/store';
import type { ApiError } from './api/http';

export interface ApiHealth {
  /** null until the first request finishes. */
  ok: boolean | null;
  /** ISO time of the last successful response, for "Showing data from …". */
  lastSuccessAt: string | null;
  error: ApiError | null;
}

export const apiHealth = writable<ApiHealth>({ ok: null, lastSuccessAt: null, error: null });

export function reportSuccess(): void {
  apiHealth.set({ ok: true, lastSuccessAt: new Date().toISOString(), error: null });
}

export function reportFailure(error: ApiError): void {
  apiHealth.update((h) => ({ ...h, ok: false, error }));
}

export const RETRY_SECONDS = 10;
