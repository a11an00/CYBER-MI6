<script lang="ts">
  import type { Snippet } from 'svelte';

  // Surface used by "Alert history", "Recent events" and "Live activity" in
  // the Figma dashboard frames: radius/lg, 1px color/border/default.
  let {
    title,
    phoneTitle,
    count,
    countOnPhone = true,
    actions,
    children,
  }: {
    title: string;
    /** Figma's phone Recent events title has no count. */
    countOnPhone?: boolean;
    /** Shorter title shown below 768px, when the phone frame names it differently. */
    phoneTitle?: string;
    count?: string;
    actions?: Snippet;
    children: Snippet;
  } = $props();

  const headingId = `card-${Math.random().toString(36).slice(2, 8)}`;
</script>

<section class="card" aria-labelledby={headingId}>
  <header>
    <h2 id={headingId}>
      {#if phoneTitle}<span class="wide">{title}</span><span class="narrow">{phoneTitle}</span>{:else}{title}{/if}
      {#if count}<span class="count" class:wide-only={!countOnPhone}>{count}</span>{/if}
    </h2>
    {#if actions}<div class="actions">{@render actions()}</div>{/if}
  </header>
  {@render children()}
</section>

<style>
  .card {
    min-width: 0;
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-lg);
    background: var(--color-bg-surface);
    overflow: hidden;
  }
  header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--spacing-sm);
    padding: var(--spacing-lg);
  }
  h2 {
    margin: 0;
    font: var(--text-heading-card);
    color: var(--color-text-primary);
  }
  .count {
    margin-left: var(--spacing-sm);
    font: var(--text-body-small);
    color: var(--color-text-muted);
  }
  .narrow {
    display: none;
  }
  @media (max-width: 767px) {
    .wide,
    .wide-only {
      display: none;
    }
    .narrow {
      display: inline;
    }
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--spacing-sm);
  }
</style>
