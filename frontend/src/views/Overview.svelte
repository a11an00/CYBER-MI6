<script lang="ts">
  import { onMount } from 'svelte';
  import AlertDetailPanel from '../components/AlertDetailPanel.svelte';
  import AlertHistory from '../components/AlertHistory.svelte';
  import ApiBanner from '../components/ApiBanner.svelte';
  import StateBlock from '../components/StateBlock.svelte';
  import LiveActivity from '../components/LiveActivity.svelte';
  import RecentEvents from '../components/RecentEvents.svelte';
  import StatTiles from '../components/StatTiles.svelte';
  import { api } from '../lib/api/client';
  import { alertsChanged } from '../lib/alerts';
  import { eventsChanged } from '../lib/events';
  import { RETRY_SECONDS } from '../lib/health';
  import { loadFeedHistory } from '../lib/live';
  import { location, navigate } from '../lib/router';
  import type { Stats } from '../lib/types';

  // Figma "Dashboard — Desktop" and "Phone / Overview".
  let stats = $state<Stats | null>(null);
  let loading = $state(true);

  // The selected alert lives in the URL (#/?alert=17) so it survives a reload
  // and can be shared; the side panel shows it.
  const selectedId = $derived.by(() => {
    const raw = $location.query.get('alert');
    return raw && /^[1-9]\d*$/.test(raw) ? Number(raw) : null;
  });
  const selectAlert = (id: number) => navigate(`#/?alert=${id}`);

  async function load(signal: AbortSignal): Promise<boolean> {
    try {
      // The api client reports success/failure to the API-health store itself.
      const [s] = await Promise.all([api.getStats(signal), loadFeedHistory(signal)]);
      stats = s;
      return true;
    } catch {
      return signal.aborted;
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    // On failure keep the last data on screen and retry (Figma: "retrying every 10 seconds").
    const run = async () => {
      if (!(await load(controller.signal)) && !controller.signal.aborted) {
        timer = setTimeout(run, RETRY_SECONDS * 1000);
      }
    };
    run();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  });

  // Status changes and new live events change the tile counts too.
  let firstChange = true;
  $effect(() => {
    $alertsChanged;
    $eventsChanged;
    if (firstChange) {
      firstChange = false;
      return;
    }
    api.getStats().then((s) => (stats = s)).catch(() => {});
  });

</script>

<svelte:head><title>Overview · CYBER-MI6</title></svelte:head>

<h1 class="visually-hidden">Overview</h1>
<ApiBanner />

<div class="overview">
  <div class="tiles"><StatTiles {stats} {loading} /></div>

  <div class="main">
    <AlertHistory {selectedId} onSelect={selectAlert} viewAllHref="#/alerts" />
    <RecentEvents scroll />
  </div>

  <aside class="side">
    <div class="detail-slot">
      {#if selectedId}
        {#key selectedId}<AlertDetailPanel id={selectedId} />{/key}
      {:else}
        <div class="no-selection">
          <StateBlock state="empty" title="No alert selected" message="Select an alert to see why it fired." />
        </div>
      {/if}
    </div>
    <LiveActivity />
  </aside>
</div>

<style>
  .overview {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 368px;
    grid-template-areas:
      'tiles tiles'
      'main side';
    gap: var(--spacing-xl);
  }
  .tiles {
    grid-area: tiles;
  }
  .main {
    grid-area: main;
  }
  .side {
    grid-area: side;
  }
  .main,
  .side {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-xl);
    min-width: 0;
  }
  .no-selection {
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-lg);
    background: var(--color-bg-surface);
  }

  /* Tablet and phone: one column. Phone order follows "Phone / Overview":
     tiles, alerts, live activity, recent events. */
  @media (max-width: 1023px) {
    .overview {
      grid-template-columns: minmax(0, 1fr);
      grid-template-areas: none;
      gap: var(--spacing-lg);
    }
    .tiles,
    .main,
    .side {
      grid-area: auto;
    }
    .main,
    .side {
      display: contents;
    }
    .main > :global(:first-child) {
      order: 1;
    }
    .side > :global(:last-child) {
      order: 2;
    }
    .main > :global(:last-child) {
      order: 3;
    }
    .side > :first-child {
      display: none; /* phone opens alert detail as its own screen (#/alerts/:id) */
    }
    .tiles {
      order: 0;
    }
  }
</style>
