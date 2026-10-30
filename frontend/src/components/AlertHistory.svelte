<script lang="ts">
  import { untrack } from 'svelte';
  import { ApiError } from '../lib/api/http';
  import { alertsChanged, DEFAULT_QUERY, fetchAlertPage, type AlertPage, type AlertQuery } from '../lib/alerts';
  import { clockTime } from '../lib/format';
  import { RETRY_SECONDS } from '../lib/health';
  import { SEVERITY_LABELS, STATUS_LABELS } from '../lib/labels';
  import { href, navigate } from '../lib/router';
  import { ALERT_STATUSES, RULES, SEVERITIES } from '../lib/types';
  import AlertCard from './AlertCard.svelte';
  import Button from './Button.svelte';
  import Card from './Card.svelte';
  import Select from './Select.svelte';
  import SeverityBadge from './SeverityBadge.svelte';
  import StateBlock from './StateBlock.svelte';
  import StatusPill from './StatusPill.svelte';

  // Figma "Alert history" card: Alert Table Header + Alert Table Row (desktop)
  // or Alert Card list (phone), Select filters, pagination, and the Data
  // states (loading, empty with filters, error).
  let {
    pageSize = 6,
    selectedId = null,
    onSelect,
    viewAllHref,
  }: {
    pageSize?: number;
    /** Row whose detail panel is open (Figma "Selected" row state). */
    selectedId?: number | null;
    /** Desktop overview: open the side panel instead of navigating. */
    onSelect?: (id: number) => void;
    /** Phone overview (Figma): first 4 alerts and "View all N alerts" instead of paging. */
    viewAllHref?: string;
  } = $props();

  let query = $state<AlertQuery>({ ...DEFAULT_QUERY });
  let page = $state(0);
  let result = $state<AlertPage | null>(null);
  let loading = $state(true);
  let error = $state<ApiError | null>(null);

  const severityOptions = [
    { value: 'all', label: 'All' },
    ...[...SEVERITIES].reverse().map((s) => ({ value: s, label: SEVERITY_LABELS[s] })),
  ] as const;
  const statusOptions = [
    { value: 'all', label: 'All' },
    { value: 'open', label: 'Open' },
    ...ALERT_STATUSES.map((s) => ({ value: s, label: STATUS_LABELS[s] })),
  ] as const;
  const ruleOptions = [{ value: 'all', label: 'All' }, ...RULES.map((r) => ({ value: r, label: r }))] as const;

  // The default "Status: Open" is itself a filter, so an empty default view
  // offers "Clear filters" (→ all statuses), as in the Figma empty state.
  const filtered = $derived(query.severity !== 'all' || query.status !== 'all' || query.rule !== 'all');

  // Reload whenever filters, page or alertsChanged change. Older responses are
  // dropped by aborting their request.
  $effect(() => {
    const q = { ...query };
    const p = page;
    $alertsChanged;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;

    const run = async () => {
      loading = true;
      try {
        result = await fetchAlertPage(q, p, pageSize, controller.signal);
        error = null;
      } catch (err) {
        if (controller.signal.aborted) return;
        error = err instanceof ApiError ? err : new ApiError(0, '/api/alerts', String(err));
        timer = setTimeout(run, RETRY_SECONDS * 1000); // Figma: "Retrying in 10 seconds."
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

  // A filter change starts again at page 1.
  function setFilter<K extends keyof AlertQuery>(key: K, value: AlertQuery[K]) {
    query = { ...query, [key]: value };
    page = 0;
  }
  const clearFilters = () => {
    query = { ...DEFAULT_QUERY, status: 'all' };
    page = 0;
  };
  const retryNow = () => (query = { ...query });

  function open(id: number) {
    if (onSelect) onSelect(id);
    else navigate(href.alert(id));
  }

  const rows = $derived(result?.rows ?? []);
  const first = $derived(page * pageSize + 1);
  const last = $derived(page * pageSize + rows.length);
  const countLabel = $derived(result?.total != null ? `${result.total.toLocaleString('en-US')} alerts` : undefined);
  const errorMessage = $derived(
    error?.unreachable
      ? `GET /api/alerts didn't respond. Retrying in ${RETRY_SECONDS} seconds.`
      : `GET /api/alerts returned an error (${error?.status}). Retrying in ${RETRY_SECONDS} seconds.`,
  );
</script>

<Card title="Alert history" phoneTitle="Alerts" count={countLabel}>
  {#snippet actions()}
    <Select label="Severity" options={severityOptions} bind:value={() => query.severity, (v) => setFilter('severity', v)} />
    <Select label="Status" options={statusOptions} bind:value={() => query.status, (v) => setFilter('status', v)} />
    <Select label="Rule" options={ruleOptions} bind:value={() => query.rule, (v) => setFilter('rule', v)} />
  {/snippet}

  <div class="table-wrap">
    <table>
      <colgroup>
        <col class="c-severity" /><col class="c-rule" /><col /><col class="c-ip" /><col class="c-time" /><col class="c-status" />
      </colgroup>
      <thead>
        <tr><th>Severity</th><th>Rule</th><th>Title</th><th>Source IP</th><th>Time</th><th>Status</th></tr>
      </thead>
      {#if !error && rows.length > 0}
        <tbody aria-busy={loading}>
          {#each rows as alert (alert.id)}
            <tr
              class:selected={alert.id === selectedId}
              aria-current={alert.id === selectedId ? 'true' : undefined}
              onclick={() => open(alert.id)}
            >
              <td><SeverityBadge severity={alert.severity} /></td>
              <td class="mono-small">{alert.rule}</td>
              <td class="title">
                <a
                  href={href.alert(alert.id)}
                  title={alert.title}
                  onclick={(e) => {
                    e.stopPropagation();
                    if (onSelect) {
                      e.preventDefault();
                      onSelect(alert.id);
                    }
                  }}>{alert.title}</a
                >
              </td>
              <td class="mono">{alert.src_ip ?? '—'}</td>
              <td class="time"><time datetime={alert.updated_at}>{clockTime(alert.updated_at)}</time></td>
              <td><StatusPill status={alert.status} /></td>
            </tr>
          {/each}
        </tbody>
      {/if}
    </table>
  </div>

  {#if !error && rows.length > 0}
    <ul class="cards" class:preview={!!viewAllHref} aria-busy={loading}>
      {#each rows as alert (alert.id)}
        <AlertCard {alert} href={href.alert(alert.id)} />
      {/each}
    </ul>
  {/if}

  {#if error}
    <StateBlock state="error" title="Couldn't load alerts" message={errorMessage}>
      {#snippet action()}
        <Button variant="secondary" onclick={retryNow}>Retry now</Button>
      {/snippet}
    </StateBlock>
  {:else if loading && !result}
    <StateBlock state="loading" title="Loading alerts…" />
  {:else if rows.length === 0}
    {#if filtered}
      <StateBlock state="empty" title="No alerts match these filters" message="Try a different severity, status or rule.">
        {#snippet action()}
          <Button variant="ghost" onclick={clearFilters}>Clear filters</Button>
        {/snippet}
      </StateBlock>
    {:else}
      <StateBlock state="empty" title="No alerts yet" message="Alerts appear here when a detection rule fires." />
    {/if}
  {/if}

  {#if viewAllHref && !error && rows.length > 0}
    <a class="view-all" href={viewAllHref}>
      View all{#if result?.total != null}&nbsp;{result.total.toLocaleString('en-US')}{/if} alerts
    </a>
  {/if}

  {#if !error && rows.length > 0}
    <footer class:has-view-all={!!viewAllHref}>
      <span class="range">
        Showing {first}–{last}{#if result?.total != null}&nbsp;of {result.total.toLocaleString('en-US')}{/if}
      </span>
      <span class="pager">
        <Button variant="secondary" disabled={page === 0 || loading} onclick={() => (page -= 1)}>Previous</Button>
        <Button variant="secondary" disabled={!result?.hasNext || loading} onclick={() => (page += 1)}>Next</Button>
      </span>
    </footer>
  {/if}
</Card>

<style>
  .table-wrap {
    overflow-x: auto;
  }
  table {
    width: 100%;
    min-width: 760px;
    border-collapse: collapse;
    table-layout: fixed;
  }
  /* Column widths from Figma "Alert Table Header"; Title takes the rest. */
  .c-severity {
    width: 120px; /* 104 + spacing/lg left padding */
  }
  .c-rule {
    width: 144px;
  }
  .c-ip {
    width: 144px;
  }
  .c-time {
    width: 104px;
  }
  .c-status {
    width: 152px; /* 120 + gap + spacing/lg right padding */
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
  th {
    padding-block: var(--spacing-sm);
    font: var(--text-label-caps);
    letter-spacing: var(--tracking-label-caps);
    text-transform: uppercase;
    color: var(--color-text-secondary);
  }
  tbody tr {
    border-bottom: 1px solid var(--color-border-default);
    background: var(--color-bg-surface);
    cursor: pointer;
  }
  td {
    padding-block: var(--spacing-md);
  }
  tbody tr:hover,
  tbody tr.selected {
    background: var(--color-bg-surface-raised);
  }
  /* Figma "Selection bar": 3px color/accent/default on the left edge. */
  tbody tr.selected td:first-child {
    box-shadow: inset 3px 0 0 var(--color-accent-default);
  }
  .mono-small {
    font: var(--text-mono-small);
    color: var(--color-text-secondary);
  }
  .mono {
    font: var(--text-mono-default);
    color: var(--color-text-primary);
  }
  .title a {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font: var(--text-body-default);
    color: var(--color-text-primary);
    text-decoration: none;
  }
  .title a:hover {
    text-decoration: underline;
  }
  .time {
    font: var(--text-body-small);
    color: var(--color-text-secondary);
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
  }
  .range {
    font: var(--text-body-small);
    color: var(--color-text-secondary);
  }
  .pager {
    display: flex;
    gap: var(--spacing-sm);
  }
  .view-all {
    display: none;
    padding: var(--spacing-md) var(--spacing-lg);
    border-top: 1px solid var(--color-border-default);
    font: var(--text-body-strong);
    color: var(--color-accent-text);
    text-align: center;
    text-decoration: none;
  }

  /* Phone: Alert Card list instead of the table (Figma "Phone / Alerts list"). */
  @media (max-width: 767px) {
    .table-wrap {
      display: none;
    }
    .cards {
      display: block;
    }
    .cards.preview > :global(li:nth-child(n + 5)) {
      display: none;
    }
    .view-all {
      display: block;
    }
    footer.has-view-all {
      display: none;
    }
  }
</style>
