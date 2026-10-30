/**
 * Light/dark theme.
 *
 * Which theme shows, highest priority first:
 *   1. `?theme=light|dark` in the page URL (before the #). Used to compare
 *      with the Figma frames; it isn't saved.
 *   2. The choice made with the header toggle, saved in this browser.
 *   3. The operating system's setting, followed live until the user chooses.
 *
 * The theme is applied as <html data-theme="…">, which tokens.css reads.
 * index.html applies the saved choice before the page paints, so there's no
 * flash of the wrong theme.
 */
import { writable } from 'svelte/store';

export type Theme = 'light' | 'dark';

export const THEME_STORAGE_KEY = 'cybermi6-theme';
/** How long the colour cross-fade lasts; matches the .theme-transition rule in app.css. */
const TRANSITION_MS = 300;

const isTheme = (v: unknown): v is Theme => v === 'light' || v === 'dark';

function urlTheme(): Theme | null {
  const v = new URLSearchParams(window.location.search).get('theme');
  return isTheme(v) ? v : null;
}

function savedTheme(): Theme | null {
  try {
    const v = localStorage.getItem(THEME_STORAGE_KEY);
    return isTheme(v) ? v : null;
  } catch {
    return null; // storage blocked (private mode, settings): fall back to the OS
  }
}

const systemQuery = window.matchMedia('(prefers-color-scheme: dark)');
const systemTheme = (): Theme => (systemQuery.matches ? 'dark' : 'light');

export const theme = writable<Theme>(urlTheme() ?? savedTheme() ?? systemTheme());

function apply(value: Theme): void {
  document.documentElement.dataset.theme = value;
}

/** Call once at startup (main.ts). */
export function initTheme(): void {
  theme.subscribe(apply);
  // Follow the OS until the user picks a theme themselves.
  systemQuery.addEventListener('change', () => {
    if (!urlTheme() && !savedTheme()) theme.set(systemTheme());
  });
}

/** The header toggle: switch, remember, and cross-fade the colours. */
export function toggleTheme(): void {
  const root = document.documentElement;
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (!reduceMotion) {
    root.classList.add('theme-transition');
    window.setTimeout(() => root.classList.remove('theme-transition'), TRANSITION_MS);
  }
  theme.update((current) => {
    const next: Theme = current === 'dark' ? 'light' : 'dark';
    try {
      localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // Not saved; it still applies for this visit.
    }
    return next;
  });
}
