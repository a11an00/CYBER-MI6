<script lang="ts">
  import type { Stats } from '../lib/types';
  import StatTile from './StatTile.svelte';

  // The four tiles from handbook §9 and the Figma dashboard frames. Captions
  // show only what GET /api/stats returns: the design's "+8% vs yesterday"
  // and the top IP's alert count have no API field, so they're left out.
  let { stats, loading = false }: { stats: Stats | null; loading?: boolean } = $props();

  const n = (value: number) => value.toLocaleString('en-US');
  const NONE = '—';

  const tiles = $derived.by(() => {
    const s = stats;
    const top = s?.top_source_ips[0];
    return [
      { key: 'events', label: 'Events today', value: s ? n(s.events_today) : NONE, caption: undefined },
      {
        key: 'severity',
        label: 'Alerts by severity',
        value: s ? n(s.alerts_total) : NONE,
        caption: s
          ? `${s.alerts_by_severity.critical} critical · ${s.alerts_by_severity.high} high · ` +
            `${s.alerts_by_severity.medium} medium · ${s.alerts_by_severity.low} low`
          : undefined,
      },
      {
        key: 'open',
        label: 'Open alerts',
        value: s ? n(s.open_alerts) : NONE,
        caption: s ? `${s.alerts_by_status.new} new · ${s.alerts_by_status.investigating} investigating` : undefined,
        phoneCaption: s ? `${s.alerts_by_status.new} new` : undefined,
      },
      {
        key: 'top',
        label: 'Top source IP',
        value: top ? top.src_ip : NONE,
        caption: top ? `${n(top.count)} events` : s ? 'No events in the last 24 h' : undefined,
      },
    ];
  });
</script>

<section class="tiles" aria-label="Summary">
  {#each tiles as tile (tile.key)}
    <StatTile
      label={tile.label}
      value={tile.value}
      caption={tile.caption}
      phoneCaption={'phoneCaption' in tile ? tile.phoneCaption : undefined}
      loading={loading && !stats}
    />
  {/each}
</section>

<style>
  .tiles {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: var(--spacing-lg);
  }
  /* Tablet (no Figma frame): two per row so values like an IP don't wrap. */
  @media (max-width: 1023px) {
    .tiles {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }
  /* Phone: "Events today" and "Open alerts" share a row, the others span it
     (Figma "Phone / Overview"). */
  @media (max-width: 640px) {
    .tiles {
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: var(--spacing-sm);
    }
    .tiles > :global(:nth-child(1)) {
      order: 1;
    }
    .tiles > :global(:nth-child(3)) {
      order: 2;
    }
    .tiles > :global(:nth-child(2)) {
      order: 3;
      grid-column: 1 / -1;
    }
    .tiles > :global(:nth-child(4)) {
      order: 4;
      grid-column: 1 / -1;
    }
  }
</style>
