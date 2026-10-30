/**
 * Development-only switch for previewing the Figma Data states:
 * ?mock=loading | empty | error | offline | save-error | ws-down in the page
 * URL (before the #). save-error loads normally but every status change
 * fails; ws-down loads normally but the WebSocket never connects.
 * Kept apart from mock.ts so the header can read it without pulling the
 * fixtures into the main bundle.
 */
export type Scenario = 'normal' | 'loading' | 'empty' | 'error' | 'offline' | 'save-error' | 'ws-down';

const SCENARIOS: readonly Scenario[] = ['loading', 'empty', 'error', 'offline', 'save-error', 'ws-down'];

export const scenario: Scenario = (() => {
  const s = new URLSearchParams(window.location.search).get('mock');
  return SCENARIOS.includes(s as Scenario) ? (s as Scenario) : 'normal';
})();

/** The current page URL with the ?mock= switch removed. */
export function urlWithoutScenario(): string {
  const url = new URL(window.location.href);
  url.searchParams.delete('mock');
  return url.toString();
}
