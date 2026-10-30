<script lang="ts">
  import { theme, toggleTheme } from '../lib/theme';

  // Header switch between light and dark. Not in the Figma frames (the design
  // has both themes but no switch); styled from the same tokens.
  // A sun knob slides right and turns into a small crescent moon, with a few
  // stars appearing on the track. All motion is off under reduced motion.
  const dark = $derived($theme === 'dark');
</script>

<button
  type="button"
  class="theme-toggle"
  class:dark
  role="switch"
  aria-checked={dark}
  aria-label="Dark theme"
  title={dark ? 'Switch to light theme' : 'Switch to dark theme'}
  onclick={toggleTheme}
>
  <span class="stars" aria-hidden="true">
    <span class="star s1"></span><span class="star s2"></span><span class="star s3"></span>
  </span>
  <span class="knob" aria-hidden="true">
    <svg class="icon sun" viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2m-7.07-17.07 1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
    </svg>
    <svg class="icon moon" viewBox="0 0 24 24">
      <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
    </svg>
  </span>
</button>

<style>
  .theme-toggle {
    --track-w: 52px;
    --track-h: 28px;
    --knob: 22px;
    --pad: 2px;
    --spring: cubic-bezier(0.34, 1.56, 0.64, 1);

    position: relative;
    flex: none;
    width: var(--track-w);
    height: var(--track-h);
    padding: 0;
    border: 1px solid var(--color-border-default);
    border-radius: 999px;
    background: var(--color-bg-surface-raised);
    cursor: pointer;
    overflow: hidden;
    transition:
      background-color 300ms ease,
      border-color 300ms ease;
  }
  .theme-toggle:hover {
    border-color: var(--color-border-strong);
  }
  .theme-toggle:focus-visible {
    outline: 2px solid var(--color-focus-ring);
    outline-offset: 2px;
  }

  /* Knob: slides with a little overshoot, squashes on press. */
  .knob {
    position: absolute;
    top: var(--pad);
    left: var(--pad);
    width: var(--knob);
    height: var(--knob);
    border-radius: 50%;
    background: var(--color-bg-surface);
    box-shadow:
      0 1px 2px rgb(15 23 42 / 0.25),
      0 0 0 1px var(--color-border-default);
    transition:
      transform 400ms var(--spring),
      background-color 300ms ease,
      width 150ms ease;
  }
  .dark .knob {
    transform: translateX(calc(var(--track-w) - var(--knob) - 2 * var(--pad) - 2px));
  }
  .theme-toggle:hover .knob {
    box-shadow:
      0 2px 6px rgb(15 23 42 / 0.3),
      0 0 0 1px var(--color-border-strong);
  }

  /* Sun and moon share the knob: one spins out as the other spins in. */
  .icon {
    position: absolute;
    inset: 4px;
    width: 14px;
    height: 14px;
    transition:
      transform 400ms var(--spring),
      opacity 250ms ease;
  }
  .sun {
    fill: var(--color-severity-medium-dot);
    stroke: var(--color-severity-medium-dot);
    stroke-width: 2;
    stroke-linecap: round;
  }
  .moon {
    fill: var(--color-accent-default);
    stroke: none;
    opacity: 0;
    transform: rotate(-90deg) scale(0.4);
  }
  .dark .sun {
    opacity: 0;
    transform: rotate(90deg) scale(0.4);
  }
  .dark .moon {
    opacity: 1;
    transform: rotate(-20deg) scale(1);
  }

  /* Tiny stars twinkle onto the track in dark mode. */
  .stars {
    position: absolute;
    inset: 0;
    pointer-events: none;
  }
  .star {
    position: absolute;
    width: 3px;
    height: 3px;
    border-radius: 50%;
    background: var(--color-text-secondary);
    opacity: 0;
    transform: scale(0);
    transition:
      opacity 300ms ease,
      transform 300ms var(--spring);
  }
  .s1 {
    top: 7px;
    left: 9px;
  }
  .s2 {
    top: 16px;
    left: 15px;
    width: 2px;
    height: 2px;
  }
  .s3 {
    top: 9px;
    left: 21px;
    width: 2px;
    height: 2px;
  }
  .dark .star {
    opacity: 0.9;
    transform: scale(1);
  }
  .dark .s2 {
    transition-delay: 80ms;
  }
  .dark .s3 {
    transition-delay: 160ms;
  }

  @media (prefers-reduced-motion: reduce) {
    .theme-toggle,
    .knob,
    .icon,
    .star {
      transition: none;
    }
  }
</style>
