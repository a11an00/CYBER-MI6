<script lang="ts">
  import AlertDetailPanel from '../components/AlertDetailPanel.svelte';
  import ApiBanner from '../components/ApiBanner.svelte';

  // Figma "Phone / Alert detail": the header shows "‹ Alerts" (AppHeader),
  // then the detail card. On desktop the same card, at a readable width.
  let { id }: { id: number } = $props();
</script>

<svelte:head><title>Alert #{id} · CYBER-MI6</title></svelte:head>

<h1 class="visually-hidden">Alert #{id}</h1>
<ApiBanner />
<a class="back" href="#/alerts">‹ Alerts</a>
<div class="page">
  {#key id}<AlertDetailPanel {id} />{/key}
</div>

<style>
  /* Desktop only: on phone the header carries the back link. */
  .back {
    display: inline-block;
    margin-bottom: var(--spacing-lg);
    font: var(--text-body-strong);
    color: var(--color-accent-text);
    text-decoration: none;
  }
  @media (max-width: 640px) {
    .back {
      display: none;
    }
  }
  .page {
    max-width: 640px;
  }
</style>
