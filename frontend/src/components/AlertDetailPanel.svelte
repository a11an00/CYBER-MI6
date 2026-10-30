<script lang="ts">
  import { api, type AlertDetail } from '../lib/api/client';
  import { ApiError } from '../lib/api/http';
  import { notifyAlertsChanged } from '../lib/alerts';
  import { explain } from '../lib/explain';
  import { clockTime, eventSummary } from '../lib/format';
  import { RETRY_SECONDS } from '../lib/health';
  import type { AlertStatus, Event } from '../lib/types';
  import Button from './Button.svelte';
  import SeverityBadge from './SeverityBadge.svelte';
  import StateBlock from './StateBlock.svelte';
  import StatusPill from './StatusPill.svelte';

  // Figma "Alert detail" (desktop side panel and Phone / Alert detail):
  // radius/lg card, padding and gap spacing/lg. Sections: badges, Heading/H2
  // title, Meta list, "Why this fired", Evidence, Set status.
  let { id }: { id: number } = $props();

  const EVIDENCE_PREVIEW = 5;

  let alert = $state<AlertDetail | null>(null);
  let error = $state<ApiError | null>(null);
  let showAllEvidence = $state(false);
  let saving = $state<AlertStatus | null>(null);
  let saveError = $state<string | null>(null);

  $effect(() => {
    const alertId = id;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    alert = null;
    error = null;
    showAllEvidence = false;
    saveError = null;

    const run = async () => {
      try {
        alert = await api.getAlert(alertId, controller.signal);
        error = null;
      } catch (err) {
        if (controller.signal.aborted) return;
        error = err instanceof ApiError ? err : new ApiError(0, `/api/alerts/${alertId}`, String(err));
        if (error.status !== 404) timer = setTimeout(run, RETRY_SECONDS * 1000);
      }
    };
    run();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  });

  const why = $derived(alert ? explain(alert) : null);
  const evidence = $derived(alert?.evidence ?? []);
  const shownEvidence = $derived(showAllEvidence ? evidence : evidence.slice(0, EVIDENCE_PREVIEW));
  const expectedEvidence = $derived(alert?.evidence_event_ids.length ?? 0);

  // "Last seen" = newest evidence event. The alert's updated_at also moves when
  // someone changes its status, so it is only the fallback.
  const lastSeen = $derived(evidence.length ? evidence[0].timestamp : (alert?.updated_at ?? ''));

  function evidenceDetail(e: Event): string {
    return e.type === 'network_connection' ? `#${e.id} → ${eventSummary(e)}` : `#${e.id} ${eventSummary(e)}`;
  }

  // Figma shows "Mark resolved" + "False positive" for an open alert. A new
  // alert can also be moved to investigating; a closed one can be reopened.
  type Action = { status: AlertStatus; label: string; variant: 'primary' | 'secondary' | 'ghost' };
  const actions = $derived.by((): Action[] => {
    switch (alert?.status) {
      case 'new':
        return [
          { status: 'resolved', label: 'Mark resolved', variant: 'primary' },
          { status: 'false_positive', label: 'False positive', variant: 'secondary' },
          { status: 'investigating', label: 'Start investigating', variant: 'ghost' },
        ];
      case 'investigating':
        return [
          { status: 'resolved', label: 'Mark resolved', variant: 'primary' },
          { status: 'false_positive', label: 'False positive', variant: 'secondary' },
        ];
      case 'resolved':
      case 'false_positive':
        return [{ status: 'investigating', label: 'Reopen', variant: 'secondary' }];
      default:
        return [];
    }
  });

  /** Handbook §9: the change shows immediately; it's rolled back if PATCH fails. */
  async function setStatus(status: AlertStatus) {
    if (!alert || saving) return;
    const previous = alert.status;
    saving = status;
    saveError = null;
    alert = { ...alert, status };
    try {
      const updated = await api.updateAlertStatus(alert.id, status);
      alert = { ...alert, ...updated, evidence: alert.evidence };
      notifyAlertsChanged();
    } catch (err) {
      alert = { ...alert, status: previous };
      saveError = err instanceof ApiError ? err.message : String(err);
    } finally {
      saving = null;
    }
  }
</script>

<section class="detail" aria-label="Alert detail" aria-busy={!alert && !error}>
  {#if error}
    {#if error.status === 404}
      <StateBlock state="empty" title="Alert not found" message={`Alert #${id} doesn't exist or was removed.`} />
    {:else}
      <StateBlock
        state="error"
        title="Couldn't load this alert"
        message={`GET /api/alerts/${id} ${error.unreachable ? "didn't respond" : `returned an error (${error.status})`}. Retrying in ${RETRY_SECONDS} seconds.`}
      />
    {/if}
  {:else if !alert}
    <StateBlock state="loading" title={`Loading alert #${id}…`} />
  {:else}
    <div class="badges">
      <SeverityBadge severity={alert.severity} />
      <StatusPill status={alert.status} />
    </div>

    <h2 class="title">{alert.title}</h2>

    <dl class="meta">
      <div><dt>Rule</dt><dd>{alert.rule}</dd></div>
      <div><dt>Source IP</dt><dd>{alert.src_ip ?? '—'}</dd></div>
      <div><dt>First seen</dt><dd><time datetime={alert.created_at}>{clockTime(alert.created_at)}</time></dd></div>
      <div><dt>Last seen</dt><dd><time datetime={lastSeen}>{clockTime(lastSeen)}</time></dd></div>
      <div><dt>Occurrences</dt><dd>{alert.count > 1 ? `${alert.count} (deduplicated)` : alert.count}</dd></div>
    </dl>

    {#if why}
      <div class="why">
        <p class="caps">Why this fired</p>
        {#if why.summary}<p class="summary">{why.summary}</p>{/if}
        {#if why.threshold}<p class="threshold">{why.threshold}</p>{/if}
        {#if why.raw.length}
          <dl class="raw">
            {#each why.raw as [key, value] (key)}<div><dt>{key}</dt><dd>{value}</dd></div>{/each}
          </dl>
        {/if}
        {#if !why.summary && !why.threshold && !why.raw.length}
          <p class="summary">No explanation was recorded for this alert.</p>
        {/if}
        {#if why.caveat}<p class="caveat">{why.caveat}</p>{/if}
      </div>
    {/if}

    <div class="evidence">
      <p class="caps">Evidence · {expectedEvidence} {expectedEvidence === 1 ? 'event' : 'events'}</p>
      {#if evidence.length}
        <ol class="evidence-list">
          {#each shownEvidence as e (e.id)}
            <li>
              <time datetime={e.timestamp}>{clockTime(e.timestamp)}</time>
              <span class="evidence-detail">{evidenceDetail(e)}</span>
            </li>
          {/each}
        </ol>
      {/if}
      {#if evidence.length > EVIDENCE_PREVIEW}
        <button type="button" class="more" onclick={() => (showAllEvidence = !showAllEvidence)}>
          {showAllEvidence ? 'Show fewer events' : `+ ${evidence.length - EVIDENCE_PREVIEW} more events`}
        </button>
      {/if}
      {#if evidence.length < expectedEvidence}
        <p class="note">
          {expectedEvidence - evidence.length} evidence {expectedEvidence - evidence.length === 1 ? 'event is' : 'events are'}
          no longer stored (retention).
        </p>
      {/if}
    </div>

    {#if actions.length}
      <div class="actions">
        <p class="caps">Set status</p>
        <div class="buttons">
          {#each actions as action (action.status)}
            <Button variant={action.variant} disabled={saving !== null} onclick={() => setStatus(action.status)}>
              {saving === action.status ? 'Saving…' : action.label}
            </Button>
          {/each}
        </div>
        {#if saveError}<p class="save-error" role="alert">Status not changed: {saveError}</p>{/if}
      </div>
    {/if}
  {/if}
</section>

<style>
  .detail {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-lg);
    min-width: 0;
    padding: var(--spacing-lg);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-lg);
    background: var(--color-bg-surface);
  }
  p {
    margin: 0;
  }
  .badges {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--spacing-sm);
  }
  .title {
    margin: 0;
    font: var(--text-heading-card);
    color: var(--color-text-primary);
    overflow-wrap: anywhere;
  }
  .caps {
    font: var(--text-label-caps);
    letter-spacing: var(--tracking-label-caps);
    text-transform: uppercase;
    color: var(--color-text-secondary);
  }

  /* Meta: 16px rows, gap spacing/xs; Body/Small label, Mono/Small value. */
  dl {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-xs);
    margin: 0;
  }
  dl div {
    display: flex;
    justify-content: space-between;
    gap: var(--spacing-sm);
  }
  dt {
    font: var(--text-body-small);
    color: var(--color-text-secondary);
  }
  dd {
    margin: 0;
    min-width: 0;
    font: var(--text-mono-small);
    color: var(--color-text-primary);
    text-align: right;
    overflow-wrap: anywhere;
  }

  /* Why this fired: radius/md, padding spacing/md, gap spacing/xs, surface-raised. */
  .why {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-xs);
    padding: var(--spacing-md);
    border-radius: var(--radius-md);
    background: var(--color-bg-surface-raised);
  }
  .summary {
    font: var(--text-body-default);
    color: var(--color-text-primary);
  }
  .threshold {
    font: var(--text-mono-small);
    color: var(--color-text-secondary);
  }
  .caveat {
    font: var(--text-body-small);
    color: var(--color-text-muted);
  }

  /* Evidence: gap spacing/xs; list radius/md with 1px border; Evidence Row. */
  .evidence {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-xs);
  }
  .evidence-list {
    margin: 0;
    padding: 0;
    list-style: none;
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    max-height: 320px;
    overflow-y: auto;
  }
  .evidence-list li {
    display: flex;
    gap: var(--spacing-md);
    padding: var(--spacing-xs) var(--spacing-md);
    font: var(--text-mono-small);
  }
  .evidence-list time {
    flex: none;
    color: var(--color-text-muted);
  }
  .evidence-detail {
    min-width: 0;
    color: var(--color-text-secondary);
    overflow-wrap: anywhere;
  }
  .more {
    align-self: flex-start;
    padding: 0;
    border: none;
    background: none;
    font: var(--text-body-small);
    color: var(--color-accent-text);
    cursor: pointer;
  }
  .more:hover {
    text-decoration: underline;
  }
  .note {
    font: var(--text-body-small);
    color: var(--color-text-muted);
  }

  /* Actions: gap spacing/sm; buttons share the row. */
  .actions {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-sm);
  }
  .buttons {
    display: flex;
    flex-wrap: wrap;
    gap: var(--spacing-sm);
  }
  .buttons > :global(.btn) {
    flex: 1 1 0;
    min-width: max-content;
  }
  .save-error {
    font: var(--text-body-small);
    color: var(--color-severity-critical-text);
  }
</style>
