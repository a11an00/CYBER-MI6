<script lang="ts">
  import { clockTime, eventTarget } from '../lib/format';
  import type { Event } from '../lib/types';

  // Figma "Event Card" (phone layout of a Recent events row): padding
  // spacing/sm × spacing/lg, gap spacing/2xs, bottom border. Top = type
  // (Mono/Small) and time; Target (Mono/Default); Origin "from src_ip · source".
  let { event }: { event: Event } = $props();
</script>

<li class="card">
  <span class="top">
    <span class="type">{event.type}</span>
    <time datetime={event.timestamp}>{clockTime(event.timestamp)}</time>
  </span>
  <span class="target">{eventTarget(event)}</span>
  <span class="origin">from {event.src_ip} · {event.source}</span>
</li>

<style>
  .card {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-2xs);
    padding: var(--spacing-sm) var(--spacing-lg);
    border-bottom: 1px solid var(--color-border-default);
  }
  .card:last-child {
    border-bottom: none;
  }
  .top {
    display: flex;
    justify-content: space-between;
    gap: var(--spacing-sm);
  }
  .type {
    font: var(--text-mono-small);
    color: var(--color-text-secondary);
  }
  time {
    font: var(--text-body-small);
    color: var(--color-text-muted);
  }
  .target {
    font: var(--text-mono-default);
    color: var(--color-text-primary);
    overflow-wrap: anywhere;
  }
  .origin {
    font: var(--text-body-small);
    color: var(--color-text-muted);
    overflow-wrap: anywhere;
  }
</style>
