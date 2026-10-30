<script lang="ts">
  import { clockTime } from '../lib/format';
  import type { Alert } from '../lib/types';
  import SeverityBadge from './SeverityBadge.svelte';
  import StatusPill from './StatusPill.svelte';

  // Figma "Alert Card" (Phone / Alerts list): badges, title (Body/Strong),
  // then rule · source IP and time. The whole card links to the detail.
  let { alert, href }: { alert: Alert; href: string } = $props();
</script>

<li>
  <a class="card" {href}>
    <span class="badges"><SeverityBadge severity={alert.severity} /><StatusPill status={alert.status} /></span>
    <span class="title">{alert.title}</span>
    <span class="meta">
      <span class="origin">{alert.rule}{alert.src_ip ? ` · ${alert.src_ip}` : ''}</span>
      <time datetime={alert.updated_at}>{clockTime(alert.updated_at)}</time>
    </span>
  </a>
</li>

<style>
  li {
    border-bottom: 1px solid var(--color-border-default);
  }
  li:last-child {
    border-bottom: none;
  }
  .card {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-xs);
    padding: var(--spacing-md) var(--spacing-lg);
    color: inherit;
    text-decoration: none;
  }
  .card:hover {
    background: var(--color-bg-surface-raised);
  }
  .badges {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--spacing-sm);
  }
  .title {
    font: var(--text-body-strong);
    color: var(--color-text-primary);
    overflow-wrap: anywhere;
  }
  .meta {
    display: flex;
    justify-content: space-between;
    gap: var(--spacing-sm);
    font: var(--text-mono-small);
    color: var(--color-text-secondary);
  }
  .origin {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  time {
    flex: none;
    color: var(--color-text-muted);
  }
</style>
