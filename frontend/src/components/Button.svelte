<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLButtonAttributes } from 'svelte/elements';

  // Figma component "Button": Primary / Secondary / Ghost, each with Default,
  // Hover, Focus and Disabled states. radius/md, padding spacing/sm ×
  // spacing/lg, gap spacing/xs, label Body/Strong.
  // "danger" is not a Figma variant: it reuses the Figma severity/critical
  // colours for destructive actions such as blocking an IP.
  let {
    variant = 'primary',
    children,
    ...rest
  }: { variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; children: Snippet } & HTMLButtonAttributes = $props();
</script>

<button type="button" class="btn {variant}" {...rest}>{@render children()}</button>

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--spacing-xs);
    padding: var(--spacing-sm) var(--spacing-lg);
    border: 1px solid transparent;
    border-radius: var(--radius-md);
    font: var(--text-body-strong);
    cursor: pointer;
  }
  /* Figma Focus state: 2px color/focus/ring outside the button. */
  .btn:focus-visible {
    outline: 2px solid var(--color-focus-ring);
    outline-offset: 0;
  }
  .btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .primary {
    background: var(--color-accent-default);
    color: var(--color-on-accent);
  }
  .primary:hover:not(:disabled) {
    background: var(--color-accent-hover);
  }

  .secondary {
    background: var(--color-bg-surface);
    border-color: var(--color-border-strong);
    color: var(--color-text-primary);
  }
  .secondary:hover:not(:disabled) {
    background: var(--color-bg-surface-raised);
  }

  .ghost {
    background: transparent;
    color: var(--color-accent-default);
  }
  .ghost:hover:not(:disabled) {
    background: var(--color-bg-surface-raised);
  }

  .danger {
    background: var(--color-severity-critical-bg);
    border-color: var(--color-severity-critical-border);
    color: var(--color-severity-critical-text);
  }
  .danger:hover:not(:disabled) {
    border-color: var(--color-severity-critical-dot);
  }
</style>
