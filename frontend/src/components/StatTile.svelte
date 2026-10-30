<script lang="ts">
  // Figma component "Stat Tile": 1px color/border/default, radius/lg,
  // padding spacing/lg, gap spacing/xs; Label/Caps, Display/Stat, Body/Small.
  let {
    label,
    value,
    caption,
    phoneCaption,
    loading = false,
  }: { label: string; value: string; caption?: string; phoneCaption?: string; loading?: boolean } = $props();
</script>

<div class="tile" aria-busy={loading}>
  <span class="label">{label}</span>
  {#if loading}
    <span class="value" aria-hidden="true">—</span>
    <span class="caption">Loading…</span>
  {:else}
    <span class="value">{value}</span>
    {#if caption}
      {#if phoneCaption}
        <span class="caption wide">{caption}</span><span class="caption narrow">{phoneCaption}</span>
      {:else}
        <span class="caption">{caption}</span>
      {/if}
    {/if}
  {/if}
</div>

<style>
  .tile {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-xs);
    min-width: 0;
    padding: var(--spacing-lg);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-lg);
    background: var(--color-bg-surface);
  }
  .label {
    font: var(--text-label-caps);
    letter-spacing: var(--tracking-label-caps);
    text-transform: uppercase;
    color: var(--color-text-secondary);
  }
  .value {
    font: var(--text-display-stat);
    color: var(--color-text-primary);
    overflow-wrap: anywhere;
  }
  .caption {
    font: var(--text-body-small);
    color: var(--color-text-muted);
  }
  .narrow {
    display: none;
  }
  @media (max-width: 640px) {
    .wide {
      display: none;
    }
    .narrow {
      display: inline;
    }
  }
</style>
