<script lang="ts">
  import { STATUS_LABELS } from '../lib/labels';
  import type { AlertStatus } from '../lib/types';

  // Figma "Status Pill": radius/sm, 1px border, padding spacing/2xs ×
  // spacing/sm, Inter 500 12/16; colours status/<status>/bg|fg|border.
  let { status }: { status: AlertStatus } = $props();
</script>

<span class="pill" data-status={status}>{STATUS_LABELS[status]}</span>

<style>
  .pill {
    display: inline-block;
    padding: var(--spacing-2xs) var(--spacing-sm);
    border: 1px solid;
    border-radius: var(--radius-sm);
    font: var(--text-body-small-strong);
    white-space: nowrap;
  }
  [data-status='new'] {
    background: var(--color-status-new-bg);
    border-color: var(--color-status-new-border);
    color: var(--color-status-new-fg);
  }
  [data-status='investigating'] {
    background: var(--color-status-investigating-bg);
    border-color: var(--color-status-investigating-border);
    color: var(--color-status-investigating-fg);
  }
  [data-status='resolved'] {
    background: var(--color-status-resolved-bg);
    border-color: var(--color-status-resolved-border);
    color: var(--color-status-resolved-fg);
  }
  [data-status='false_positive'] {
    background: var(--color-status-false-positive-bg);
    border-color: var(--color-status-false-positive-border);
    color: var(--color-status-false-positive-fg);
  }
</style>
