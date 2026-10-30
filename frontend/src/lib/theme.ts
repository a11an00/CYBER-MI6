/**
 * Light/dark theme. The Figma design has both modes but no theme switch, so
 * the app follows the operating system by default. `?theme=light` or
 * `?theme=dark` in the page URL (before the #) forces one, which is how the
 * two modes are compared against the Figma frames during development.
 */
export type Theme = 'light' | 'dark';

export function applyThemeOverride(): void {
  const requested = new URLSearchParams(window.location.search).get('theme');
  if (requested === 'light' || requested === 'dark') {
    document.documentElement.dataset.theme = requested;
  }
}
