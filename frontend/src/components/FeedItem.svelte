<script lang="ts">
  import { alertSummary, clockTime, eventSummary } from '../lib/format';
  import type { FeedItem } from '../lib/live';
  import { href } from '../lib/router';

  // Figma component "Feed Item" (Kind = Event | Alert): padding spacing/sm ×
  // spacing/lg, gap spacing/sm, bottom border; time Mono/Small muted, kind
  // Label/Caps (muted for events, accent for alerts), message Body/Small.
  let { item }: { item: FeedItem } = $props();

  const label = $derived(item.kind === 'alert' ? item.data.rule : item.data.type);
  const summary = $derived(item.kind === 'alert' ? alertSummary(item.data) : eventSummary(item.data));
</script>

<li class="item" data-kind={item.kind}>
  <time class="time" datetime={item.at}>{clockTime(item.at)}</time>
  <span class="kind">{item.kind}</span>
  {#if item.kind === 'alert'}
    <a class="message" href={href.alert(item.data.id)}>{label} · {summary}</a>
  {:else}
    <span class="message">{label} · {summary}</span>
  {/if}
</li>

<style>
  .item {
    display: flex;
    align-items: flex-start;
    gap: var(--spacing-sm);
    padding: var(--spacing-sm) var(--spacing-lg);
    border-bottom: 1px solid var(--color-border-default);
  }
  .item:last-child {
    border-bottom: none;
  }
  .time {
    flex: none;
    font: var(--text-mono-small);
    color: var(--color-text-muted);
  }
  .kind {
    flex: none;
    width: 40px;
    font: var(--text-label-caps);
    letter-spacing: var(--tracking-label-caps);
    text-transform: uppercase;
    color: var(--color-text-muted);
  }
  [data-kind='alert'] .kind {
    color: var(--color-accent-default);
  }
  .message {
    min-width: 0;
    font: var(--text-body-small);
    color: var(--color-text-primary);
    overflow-wrap: anywhere;
    text-decoration: none;
  }
  a.message:hover {
    text-decoration: underline;
  }
</style>
