<script lang="ts">
  import AlertHistory from '../components/AlertHistory.svelte';
  import ApiBanner from '../components/ApiBanner.svelte';
</script>

<svelte:head><title>Alerts · CYBER-MI6</title></svelte:head>

<!-- Figma "Phone / Alerts list"; on desktop the same card with more rows. -->
<h1 class="visually-hidden">Alerts</h1>
<ApiBanner />
<AlertHistory pageSize={20} />
