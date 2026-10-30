<script lang="ts">
  import { onMount } from 'svelte';
  import AppHeader from './components/AppHeader.svelte';
  import DevScenarioNotice from './components/DevScenarioNotice.svelte';
  import { displayedConnection, feed } from './lib/live';
  import { location } from './lib/router';
  import { startLive } from './lib/ws';
  import AlertDetail from './views/AlertDetail.svelte';
  import Alerts from './views/Alerts.svelte';
  import Events from './views/Events.svelte';
  import NotFound from './views/NotFound.svelte';
  import Overview from './views/Overview.svelte';

  const route = $derived($location.route);
  // Figma header: "Last event 2s ago" = the newest event in the live feed.
  const lastEventAt = $derived($feed.find((i) => i.kind === 'event')?.at ?? null);

  onMount(startLive);
</script>

<DevScenarioNotice />
<!-- Figma Data states: the header switches to Offline when the API is unreachable. -->
<AppHeader
  connection={$displayedConnection}
  {lastEventAt}
  back={route.name === 'alert-detail' ? { href: '#/alerts', label: 'Alerts' } : undefined}
/>

<main class="content">
  {#if route.name === 'overview'}
    <Overview />
  {:else if route.name === 'alerts'}
    <Alerts />
  {:else if route.name === 'alert-detail'}
    <AlertDetail id={route.id} />
  {:else if route.name === 'events'}
    <Events />
  {:else}
    <NotFound path={route.path} />
  {/if}
</main>

<style>
  .content {
    max-width: 1440px;
    margin: 0 auto;
    padding: var(--spacing-xl);
  }
  @media (max-width: 640px) {
    .content {
      padding: var(--spacing-lg);
    }
  }
</style>
