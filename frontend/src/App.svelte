<script lang="ts">
  import { onMount } from 'svelte';
  import { get } from 'svelte/store';
  import AppHeader from './components/AppHeader.svelte';
  import DevScenarioNotice from './components/DevScenarioNotice.svelte';
  import { displayedConnection, feed } from './lib/live';
  import { location } from './lib/router';
  import { startLive, stopLive } from './lib/ws';
  import { auth } from './lib/auth';
  
  import AlertDetail from './views/AlertDetail.svelte';
  import Alerts from './views/Alerts.svelte';
  import Events from './views/Events.svelte';
  import NotFound from './views/NotFound.svelte';
  import Overview from './views/Overview.svelte';
  
  import Login from './views/Login.svelte';
  import AdminDashboard from './views/AdminDashboard.svelte';
  import UserProfileSettings from './views/UserProfileSettings.svelte';

  const route = $derived($location.route);
  const lastEventAt = $derived($feed.find((i) => i.kind === 'event')?.at ?? null);

  onMount(() => {
    auth.init();
    if (get(auth).isAuthenticated) {
      startLive();
    }
  });

  $effect(() => {
    if ($auth.isAuthenticated) {
      startLive();
    } else {
      stopLive(); // logged out: close the live socket instead of leaving it streaming
    }
  });
</script>

{#if !$auth.initialized}
  <!-- auth.init() hasn't run yet — don't mount any views so they can't fire
       unauthenticated requests before the token is loaded from localStorage. -->
{:else if !$auth.isAuthenticated}
  <main class="auth-layout">
    <Login />
  </main>
{:else}
  <DevScenarioNotice />
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
    {:else if route.name === 'admin'}
      {#if $auth.user?.role === 'admin'}
        <AdminDashboard />
      {:else}
        <NotFound path="Unauthorized Access: Admin Only" />
      {/if}
    {:else if route.name === 'profile'}
      <UserProfileSettings />
    {:else if route.name === 'not-found'}
      <NotFound path={route.path} />
    {/if}
  </main>
{/if}

<style>
  .content {
    max-width: 1440px;
    margin: 0 auto;
    padding: var(--spacing-xl);
  }
  .auth-layout {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  @media (max-width: 640px) {
    .content {
      padding: var(--spacing-lg);
    }
  }
</style>
