<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { blockErrorMessage, blockIp, blocklist, loadBlocklist, unblockIp } from '../lib/blocklist';
  import { clockTime } from '../lib/format';
  import Button from './Button.svelte';

  // Sits under the status buttons in the alert detail. Blocking needs a
  // confirmation step and only shows "Blocked" once the API confirms it.
  let { ip, alertId, reason }: { ip: string; alertId: number; reason: string } = $props();

  let confirming = $state(false);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let container = $state<HTMLDivElement | null>(null);

  const entry = $derived($blocklist.get(ip) ?? null);

  onMount(() => {
    loadBlocklist();
  });

  /** Keep keyboard focus on the control as it changes shape. */
  async function focusButton(selector: string) {
    await tick();
    container?.querySelector<HTMLButtonElement>(selector)?.focus();
  }

  async function askToConfirm() {
    error = null;
    confirming = true;
    await focusButton('.confirm .btn.danger'); // land on the decision
  }

  async function cancel() {
    confirming = false;
    await focusButton('.btn.danger'); // back to "Block <ip>"
  }

  async function confirmBlock() {
    busy = true;
    error = null;
    try {
      await blockIp(ip, alertId, reason);
      confirming = false;
      focusButton('.btn.ghost'); // "Unblock"
    } catch (err) {
      error = blockErrorMessage(err);
    } finally {
      busy = false;
    }
  }

  async function unblock() {
    busy = true;
    error = null;
    try {
      await unblockIp(ip);
      focusButton('.btn.danger');
    } catch (err) {
      error = blockErrorMessage(err);
    } finally {
      busy = false;
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && confirming && !busy) cancel();
  }
</script>

<!-- Escape cancels the confirmation. -->
<svelte:window onkeydown={onKeydown} />

<div class="block-ip" bind:this={container} role="group" aria-label="Block source IP">
  {#if entry}
    <p class="blocked" role="status">
      <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10" /><path d="m4.9 4.9 14.2 14.2" /></svg>
      <span><span class="ip">{ip}</span> is blocked · since {clockTime(entry.blocked_at)}</span>
    </p>
    <Button variant="ghost" disabled={busy} onclick={unblock}>{busy ? 'Unblocking…' : 'Unblock'}</Button>
  {:else if confirming}
    <div class="confirm" role="alertdialog" aria-labelledby="block-ip-question" aria-describedby="block-ip-detail">
      <p id="block-ip-question" class="question">Block <span class="ip">{ip}</span>?</p>
      <p id="block-ip-detail" class="detail">
        New traffic from this address will be refused. The alert and its evidence are kept, and you can unblock it later.
      </p>
      <div class="buttons">
        <Button variant="danger" disabled={busy} onclick={confirmBlock}>
          {busy ? 'Blocking…' : 'Block IP'}
        </Button>
        <Button variant="secondary" disabled={busy} onclick={cancel}>Cancel</Button>
      </div>
    </div>
  {:else}
    <Button variant="danger" onclick={askToConfirm}>
      <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10" /><path d="m4.9 4.9 14.2 14.2" /></svg>
      Block <span class="ip">{ip}</span>
    </Button>
  {/if}

  {#if error}<p class="error" role="alert">Not blocked: {error}</p>{/if}
</div>

<style>
  .block-ip {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-sm);
  }
  .block-ip > :global(.btn) {
    width: 100%;
  }
  p {
    margin: 0;
  }
  .ip {
    font-family: var(--font-mono);
  }
  .icon {
    flex: none;
    width: 16px;
    height: 16px;
    fill: none;
    stroke: currentColor;
    stroke-width: 2;
    stroke-linecap: round;
  }
  .confirm {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-xs);
    padding: var(--spacing-md);
    border: 1px solid var(--color-severity-critical-border);
    border-radius: var(--radius-md);
    background: var(--color-severity-critical-bg);
  }
  .question {
    font: var(--text-body-strong);
    color: var(--color-text-primary);
  }
  .detail {
    font: var(--text-body-small);
    color: var(--color-text-secondary);
  }
  .buttons {
    display: flex;
    flex-wrap: wrap;
    gap: var(--spacing-sm);
    margin-top: var(--spacing-xs);
  }
  .buttons > :global(.btn) {
    flex: 1 1 0;
    min-width: max-content;
  }
  .blocked {
    display: flex;
    align-items: center;
    gap: var(--spacing-sm);
    padding: var(--spacing-sm) var(--spacing-md);
    border: 1px solid var(--color-severity-critical-border);
    border-radius: var(--radius-md);
    background: var(--color-severity-critical-bg);
    font: var(--text-body-small);
    color: var(--color-severity-critical-text);
  }
  .error {
    font: var(--text-body-small);
    color: var(--color-severity-critical-text);
  }
</style>
