<script lang="ts">
  import { dataSource } from '../lib/api/client';
  import { scenario, urlWithoutScenario } from '../lib/api/scenario';

  // Development aid, not part of the Figma design: makes it obvious when a
  // ?mock= preview switch is holding the page in a loading/empty/error state.
  const active = import.meta.env.DEV && dataSource === 'mock' && scenario !== 'normal';
</script>

{#if active}
  <p class="notice" role="note">
    Previewing the <strong>{scenario}</strong> state with mock data (<code>?mock={scenario}</code>).
    <a href={urlWithoutScenario()}>Show normal demo data</a>
  </p>
{/if}

<style>
  .notice {
    margin: 0;
    padding: var(--spacing-xs) var(--spacing-xl);
    font: var(--text-body-small);
    text-align: center;
    color: var(--color-on-accent);
    background: var(--color-accent-default);
  }
  .notice a {
    margin-left: var(--spacing-sm);
    color: inherit;
    font-weight: 600;
  }
  code {
    font: var(--text-mono-small);
  }
</style>
