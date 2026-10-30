<script lang="ts">
  import { untrack } from 'svelte';
  import { api } from '../lib/api/client';
  import { ApiError } from '../lib/api/http';
  import { eventsChanged } from '../lib/events';
  import { clockTime, eventTarget } from '../lib/format';
  import { RETRY_SECONDS } from '../lib/health';
  import { displayedConnection } from '../lib/live';
  import { EVENT_TYPES, type Event, type EventType } from '../lib/types';
  import Button from './Button.svelte';
  import Card from './Card.svelte';
  import EventCard from './EventCard.svelte';
  import Select from './Select.svelte';
  import StateBlock from './StateBlock.svelte';

  // Figma "Recent events" card: Event Table Header + Event Table Row on
  // desktop, Event Card list on phone, a Type filter, and the Data states.
  let {
    pageSize = 50,
    paged = false,
    scroll = false,
  }: {
    /** Events per request; the card title says "last {pageSize}". */
    pageSize?: number;
    /** Events page: Previous/Next. Overview: newest page only. */
    paged?: boolean;
    /** Overview: keep the card short and scroll inside it. */
    scroll?: boolean;
  } = $props();

  let type = $state<EventType | 'all'>('all');
  let page = $state(0);
  let rows = $state<Event[]>([]);
  let hasNext = $state(false);
  let loaded = $state(false);
  let loading = $state(true);
  let error = $state<ApiError | null>(null);
  let retries = $state(0);

  const typeOptions = [{ value: 'all', label: 'All' }, ...EVENT_TYPES.map((t) => ({ value: t, label: t }))] as const;

  $effect(() => {
    const t = type;
    const p = page;
    retries;
    $eventsChanged;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;

    const run = async () => {
      loading = true;
      try {
        // One extra row tells us whether there's a next page.
        const result = await api.listEvents(
          { type: t === 'all' ? undefined : t, limit: pageSize + 1, offset: p * pageSize },
          controller.signal,
        );
        rows = result.slice(0, pageSize);
        hasNext = result.length > pageSize;
        loaded = true;
        error = null;
      } catch (err) {
        if (controller.signal.aborted) return;
        error = err instanceof ApiError ? err : new ApiError(0, '/api/events', String(err));
        timer = setTimeout(run, RETRY_SECONDS * 1000);
      } finally {
        if (!controller.signal.aborted) loading = false;
      }
    };
    untrack(run);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  });

  const setType = (v: EventType | 'all') => {
    type = v;
    page = 0;
  };
  const retryNow = () => (retries += 1);

  const countLabel = $derived(`${$displayedConnection === 'live' ? 'Live · ' : ''}last ${pageSize}`);
  const errorMessage = $derived(
    `GET /api/events ${error?.unreachable ? "didn't respond" : `returned an error (${error?.status})`}. Retrying in ${RETRY_SECONDS} seconds.`,
  );
</script>

<Card title="Recent events" count={countLabel} countOnPhone={!scroll}>
  {#snippet actions()}
    <Select label="Type" options={typeOptions} bind:value={() => type, setType} />
  {/snippet}

  <div class="body" class:scroll>
    <div class="table-wrap">
      <table>
        <colgroup>
          <col class="c-time" /><col class="c-type" /><col class="c-ip" /><col /><col class="c-sensor" />
        </colgroup>
        <thead>
          <tr><th>Time</th><th>Type</th><th>Source IP</th><th>Target</th><th>Sensor</th></tr>
        </thead>
        {#if !error && rows.length > 0}
          <tbody aria-busy={loading}>
            {#each rows as event (event.id)}
              <tr>
                <td class="time"><time datetime={event.timestamp}>{clockTime(event.timestamp)}</time></td>
                <td class="mono-small">{event.type}</td>
                <td class="mono">{event.src_ip}</td>
                <td class="mono target" title={eventTarget(event)}>{eventTarget(event)}</td>
                <td class="sensor">{event.source}</td>
              </tr>
            {/each}
          </tbody>
        {/if}
      </table>
    </div>

    {#if !error && rows.length > 0}
      <ul class="cards" aria-busy={loading}>
        {#each rows as event (event.id)}<EventCard {event} />{/each}
      </ul>
    {/if}
  </div>

  {#if error}
    <StateBlock state="error" title="Couldn't load events" message={errorMessage}>
      {#snippet action()}
        <Button variant="secondary" onclick={retryNow}>Retry now</Button>
      {/snippet}
    </StateBlock>
  {:else if loading && !loaded}
    <StateBlock state="loading" title="Loading events…" />
  {:else if rows.length === 0}
    {#if type !== 'all'}
      <StateBlock state="empty" title="No events of this type" message="Try another event type.">
        {#snippet action()}
          <Button variant="ghost" onclick={() => setType('all')}>Show all types</Button>
        {/snippet}
      </StateBlock>
    {:else}
      <StateBlock
        state="empty"
        title="No events yet"
        message="Start the Scapy sensor or run tools/send_demo_events.py to generate safe test events."
      />
    {/if}
  {/if}

  {#if paged && !error && (page > 0 || hasNext)}
    <footer>
      <span class="range">Showing {page * pageSize + 1}–{page * pageSize + rows.length}</span>
      <span class="pager">
        <Button variant="secondary" disabled={page === 0 || loading} onclick={() => (page -= 1)}>Previous</Button>
        <Button variant="secondary" disabled={!hasNext || loading} onclick={() => (page += 1)}>Next</Button>
      </span>
    </footer>
  {/if}
</Card>

<style>
  .body.scroll {
    max-height: 296px; /* header + about seven rows, as in the dashboard frame */
    overflow-y: auto;
  }
  .table-wrap {
    overflow-x: auto;
  }
  table {
    width: 100%;
    min-width: 720px;
    border-collapse: collapse;
    table-layout: fixed;
  }
  /* Column widths from Figma "Event Table Header"; Target takes the rest. */
  .c-time {
    width: 104px; /* 88 + spacing/lg left padding */
  }
  .c-type {
    width: 152px;
  }
  .c-ip {
    width: 144px;
  }
  .c-sensor {
    width: 168px; /* 136 + gap + spacing/lg right padding */
  }
  th,
  td {
    padding: 0 0 0 var(--spacing-lg);
    text-align: left;
    vertical-align: middle;
  }
  th:last-child,
  td:last-child {
    padding-right: var(--spacing-lg);
  }
  thead tr {
    background: var(--color-bg-surface-raised);
    border-top: 1px solid var(--color-border-default);
    border-bottom: 1px solid var(--color-border-default);
  }
  .scroll thead th {
    position: sticky;
    top: 0;
    background: var(--color-bg-surface-raised);
  }
  th {
    padding-block: var(--spacing-sm);
    font: var(--text-label-caps);
    letter-spacing: var(--tracking-label-caps);
    text-transform: uppercase;
    color: var(--color-text-secondary);
  }
  tbody tr {
    border-bottom: 1px solid var(--color-border-default);
  }
  tbody tr:last-child {
    border-bottom: none;
  }
  td {
    padding-block: var(--spacing-sm);
  }
  .time,
  .sensor {
    font: var(--text-body-small);
    color: var(--color-text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .mono-small {
    font: var(--text-mono-small);
    color: var(--color-text-secondary);
  }
  .mono {
    font: var(--text-mono-default);
    color: var(--color-text-primary);
  }
  .target {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .cards {
    display: none;
    margin: 0;
    padding: 0;
    list-style: none;
    border-top: 1px solid var(--color-border-default);
  }
  footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--spacing-sm);
    padding: var(--spacing-md) var(--spacing-lg);
    border-top: 1px solid var(--color-border-default);
  }
  .range {
    font: var(--text-body-small);
    color: var(--color-text-secondary);
  }
  .pager {
    display: flex;
    gap: var(--spacing-sm);
  }

  /* Phone: Event Card list (Figma "Phone / Overview"). */
  @media (max-width: 767px) {
    .table-wrap {
      display: none;
    }
    .cards {
      display: block;
    }
    /* Figma Phone / Overview: four cards, no inner scroll. */
    .body.scroll {
      max-height: none;
    }
    .scroll .cards > :global(li:nth-child(n + 5)) {
      display: none;
    }
  }
</style>
