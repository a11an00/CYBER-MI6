<script lang="ts">
  import { displayedConnection as connection, feed, feedLoading } from '../lib/live';
  import { reconnectNow } from '../lib/ws';
  import Button from './Button.svelte';
  import Card from './Card.svelte';
  import FeedItem from './FeedItem.svelte';
  import StateBlock from './StateBlock.svelte';

  // Figma: "Live activity" card plus its Data states (offline/polling
  // fallback, empty, loading).
  let { onReconnect = reconnectNow, limit }: { onReconnect?: () => void; limit?: number } = $props();

  const items = $derived(limit ? $feed.slice(0, limit) : $feed);
  const live = $derived($connection === 'live');
</script>

<Card title="Live activity">
  {#snippet actions()}
    <span class="badge" data-state={$connection}>
      <span class="dot" aria-hidden="true"></span>{live ? 'Live' : $connection === 'offline' ? 'Offline · polling every 10s' : 'Reconnecting…'}
    </span>
  {/snippet}

  {#if $connection === 'offline'}
    <StateBlock
      state="error"
      title="Live updates paused"
      message="WebSocket disconnected. Checking /api/alerts every 10 seconds instead."
    >
      {#snippet action()}
        <Button variant="secondary" onclick={onReconnect}>Reconnect</Button>
      {/snippet}
    </StateBlock>
  {:else if $feedLoading && $feed.length === 0}
    <StateBlock state="loading" rows={4} />
  {:else if $feed.length === 0}
    <StateBlock state="empty" title="Waiting for activity" message="New events and alerts appear here instantly." />
  {:else}
    <ol class="feed" aria-live="polite" aria-label="Newest first">
      {#each items as item (item.id)}
        <FeedItem {item} />
      {/each}
    </ol>
  {/if}
</Card>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font: var(--text-body-small);
    color: var(--color-text-secondary);
    white-space: nowrap;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--color-connection-reconnecting);
  }
  [data-state='live'] .dot {
    background: var(--color-connection-live);
  }
  [data-state='offline'] .dot {
    background: var(--color-connection-offline);
  }
  .feed {
    margin: 0;
    padding: 0;
    list-style: none;
    border-top: 1px solid var(--color-border-default);
    max-height: 480px;
    overflow-y: auto;
  }
  /* Figma Phone / Overview: the four newest lines, no inner scroll. */
  @media (max-width: 767px) {
    .feed {
      max-height: none;
    }
    .feed > :global(li:nth-child(n + 5)) {
      display: none;
    }
  }
</style>
