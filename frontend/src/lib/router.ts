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
} as const;

export function navigate(to: string): void {
  window.location.hash = to;
}
