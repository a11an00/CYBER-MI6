<script lang="ts">
  import type { Severity } from '../lib/types';

  // Figma "Severity Badge": coloured dot plus Label/Caps text, no background.
  // Colour is always paired with the label (handbook §9).
  let { severity }: { severity: Severity } = $props();
</script>

<span class="badge" data-severity={severity}>
  <span class="dot" aria-hidden="true"></span>{severity}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font: var(--text-label-caps);
    letter-spacing: var(--tracking-label-caps);
    text-transform: uppercase;
    white-space: nowrap;
  }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
  }
  [data-severity='low'] {
    color: var(--color-severity-low-text);
  }
  [data-severity='low'] .dot {
    background: var(--color-severity-low-dot);
  }
  [data-severity='medium'] {
    color: var(--color-severity-medium-text);
  }
  [data-severity='medium'] .dot {
    background: var(--color-severity-medium-dot);
  }
  [data-severity='high'] {
    color: var(--color-severity-high-text);
  }
  [data-severity='high'] .dot {
    background: var(--color-severity-high-dot);
  }
  [data-severity='critical'] {
    color: var(--color-severity-critical-text);
  }
  [data-severity='critical'] .dot {
    background: var(--color-severity-critical-dot);
  }
</style>
