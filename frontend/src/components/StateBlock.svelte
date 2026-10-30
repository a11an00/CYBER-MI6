<script lang="ts">
  import type { Snippet } from 'svelte';

  // Figma component "State Block": replaces a table or feed body while data
  // is loading, when there's nothing to show, or when a call fails
  // (handbook §9). Padding spacing/xl × spacing/lg, gap spacing/xs, 24px icon.
  let {
    state,
    title = '',
    message = '',
    rows = 3,
    action,
  }: {
    state: 'loading' | 'empty' | 'error';
    title?: string;
    message?: string;
    /** Skeleton rows for the loading state. */
    rows?: number;
    action?: Snippet;
  } = $props();
</script>

{#if state === 'loading'}
  <div class="skeleton" role="status" aria-label={title || 'Loading'}>
    {#each Array(rows) as _, i (i)}
      <div class="bar-row" aria-hidden="true">
        <span class="bar short"></span><span class="bar long"></span><span class="bar short"></span>
      </div>
    {/each}
    {#if title}<p class="loading-label">{title}</p>{/if}
  </div>
{:else}
  <div class="block" role={state === 'error' ? 'alert' : 'status'}>
    {#if state === 'empty'}
      <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
        <path d="m9 12 2 2 4-4" />
      </svg>
    {:else}
      <svg class="icon error" viewBox="0 0 24 24" aria-hidden="true">
        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3" />
        <path d="M12 9v4" />
        <path d="M12 17h.01" />
      </svg>
    {/if}
    <span class="spacer" aria-hidden="true"></span>
    <p class="title">{title}</p>
    <p class="message">{message}</p>
    {#if action}
      <span class="spacer" aria-hidden="true"></span>
      {@render action()}
    {/if}
  </div>
{/if}

<style>
  .block {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--spacing-xs);
    padding: var(--spacing-xl) var(--spacing-lg);
    text-align: center;
  }
  .icon {
    width: 24px;
    height: 24px;
    fill: none;
    stroke: var(--color-text-muted);
    stroke-width: 2;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .icon.error {
    stroke: var(--color-severity-critical-dot);
  }
  .spacer {
    height: var(--spacing-xs);
  }
  p {
    margin: 0;
  }
  .title {
    font: var(--text-body-strong);
    color: var(--color-text-primary);
  }
  .message {
    max-width: 320px;
    font: var(--text-body-small);
    color: var(--color-text-secondary);
  }

  .skeleton {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-sm);
    padding: var(--spacing-lg);
  }
  .bar-row {
    display: flex;
    gap: var(--spacing-lg);
  }
  .bar {
    height: 10px;
    border-radius: var(--radius-sm);
    background: var(--color-bg-surface-raised);
  }
  .bar.short {
    flex: 1;
  }
  .bar.long {
    flex: 3;
  }
  .loading-label {
    margin: var(--spacing-xs) 0 0;
    font: var(--text-body-small);
    color: var(--color-text-muted);
  }
</style>
