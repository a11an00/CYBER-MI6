<script lang="ts">
  import { auth } from '../lib/auth';
  import { relativeTime } from '../lib/format';
  import { href } from '../lib/router';
  import Button from './Button.svelte';
  import ThemeToggle from './ThemeToggle.svelte';

  // Matches the Figma "Connection Indicator" component. Wired to the
  // WebSocket store in a later step; the text label is always shown next to
  // the dot (handbook §9: never colour alone).
  type Connection = 'live' | 'reconnecting' | 'offline';

  let {
    connection = 'reconnecting',
    lastEventAt = null,
    back,
  }: {
    connection?: Connection;
    /** ISO time of the newest event, for "Last event 2s ago". */
    lastEventAt?: string | null;
    /** Phone screens below the overview show "‹ Alerts" in place of the wordmark. */
    back?: { href: string; label: string };
  } = $props();

  const labels: Record<Connection, string> = {
    live: 'Live',
    reconnecting: 'Reconnecting…',
    offline: 'Offline · polling every 10s',
  };

  // Re-render the relative time every second.
  let now = $state(Date.now());
  $effect(() => {
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });
</script>

<header class="app-header">
  {#if back}<a class="back" href={back.href}>‹ {back.label}</a>{/if}
  <a class="brand" class:has-back={!!back} href={href.overview} aria-label="CYBER-MI6 overview">
    <!-- TODO: swap in the logo from the Figma "Logo" page once exported. -->
    <span class="wordmark">CYBER-<span class="accent">MI6</span></span>
    <span class="tagline">Detect. Analyze. Respond. Secure.</span>
  </a>

  <div class="status">
    {#if lastEventAt}
      <time class="last-event" datetime={lastEventAt}>Last event {relativeTime(lastEventAt, now)}</time>
    {/if}
    <p class="connection" data-state={connection} role="status">
      <span class="dot" aria-hidden="true"></span>{labels[connection]}
    </p>
    <ThemeToggle />
    {#if $auth.user}
      <div class="account">
        <span class="who">{$auth.user.username}</span>
        {#if $auth.user.role === 'admin'}<a class="admin-link" href={href.admin}>Users</a>{/if}
        <Button variant="ghost" onclick={() => auth.logout()}>Log out</Button>
      </div>
    {/if}
  </div>
</header>

<style>
  .app-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--spacing-lg);
    min-height: 60px;
    padding: var(--spacing-sm) var(--spacing-xl);
    border-bottom: 1px solid var(--color-border-default);
    background: var(--color-bg-surface);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
    color: inherit;
    text-decoration: none;
  }
  .back {
    display: none;
    font: var(--text-body-strong);
    color: var(--color-accent-text);
    text-decoration: none;
  }
  .wordmark {
    font: 700 18px / 24px var(--font-sans);
    color: var(--color-text-primary);
  }
  .accent {
    color: var(--color-accent-default);
  }
  .tagline {
    font: var(--text-body-small);
    color: var(--color-text-muted);
  }
  .status {
    display: flex;
    align-items: center;
    gap: var(--spacing-lg);
  }
  .last-event {
    font: var(--text-body-small);
    color: var(--color-text-muted);
  }
  .connection {
    margin: 0;
    display: flex;
    align-items: center;
    gap: 6px;
    font: var(--text-body-small);
    color: var(--color-text-secondary);
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }
  [data-state='live'] .dot {
    background: var(--color-connection-live);
  }
  [data-state='reconnecting'] .dot {
    background: var(--color-connection-reconnecting);
  }
  [data-state='offline'] .dot {
    background: var(--color-connection-offline);
  }
  .account {
    display: flex;
    align-items: center;
    gap: var(--spacing-md);
  }
  .who {
    font: var(--text-body-small);
    color: var(--color-text-secondary);
  }
  .admin-link {
    font: var(--text-body-small);
    color: var(--color-accent-text);
    text-decoration: none;
  }
  .admin-link:hover {
    text-decoration: underline;
  }
  @media (max-width: 640px) {
    .who {
      display: none;
    }
    .app-header {
      min-height: 52px;
      padding: var(--spacing-sm) var(--spacing-lg);
    }
    .tagline,
    .last-event {
      display: none;
    }
    .status {
      gap: var(--spacing-md);
    }
    .back {
      display: inline;
    }
    .brand.has-back {
      display: none;
    }
  }
</style>
