<script lang="ts">
  import { clockTime } from '../lib/format';
  import { apiHealth, RETRY_SECONDS } from '../lib/health';

  // Figma "Data states → Global · API unreachable (header switches to offline)".
  const h = $derived($apiHealth);
  const message = $derived.by(() => {
    if (!h.error) return '';
    const lead = h.error.unreachable
      ? "Can't reach the CYBER-MI6 API."
      : `The CYBER-MI6 API returned an error (${h.error.status}).`;
    const retry = `retrying every ${RETRY_SECONDS} seconds.`;
    return h.lastSuccessAt
      ? `${lead} Showing data from ${clockTime(h.lastSuccessAt)} — ${retry}`
      : `${lead} Retrying every ${RETRY_SECONDS} seconds.`;
  });
</script>

{#if h.ok === false}
  <div class="banner" role="alert">
    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3" />
      <path d="M12 9v4" />
      <path d="M12 17h.01" />
    </svg>
    <p>{message}</p>
    <span class="status"><span class="dot" aria-hidden="true"></span>Offline · polling every {RETRY_SECONDS}s</span>
  </div>
{/if}

<style>
  .banner {
    display: flex;
    align-items: center;
    gap: var(--spacing-md);
    margin-bottom: var(--spacing-lg);
    padding: var(--spacing-md) var(--spacing-lg);
    border: 1px solid var(--color-severity-critical-border);
    border-radius: var(--radius-md);
    background: var(--color-severity-critical-bg);
    color: var(--color-severity-critical-text);
  }
  .icon {
    flex: none;
    width: 16px;
    height: 16px;
    fill: none;
    stroke: var(--color-severity-critical-dot);
    stroke-width: 2;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  p {
    flex: 1;
    margin: 0;
    font: var(--text-body-default);
  }
  .status {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font: var(--text-body-small);
    color: var(--color-text-secondary);
    white-space: nowrap;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--color-connection-offline);
  }
  @media (max-width: 640px) {
    .banner {
      flex-wrap: wrap;
    }
  }
</style>
