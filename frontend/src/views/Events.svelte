<script lang="ts">
  import ApiBanner from '../components/ApiBanner.svelte';
  import RecentEvents from '../components/RecentEvents.svelte';
</script>

<svelte:head><title>Events · CYBER-MI6</title></svelte:head>

<!-- The Recent events card at full height, with paging through older events. -->
<h1 class="visually-hidden">Recent events</h1>
<ApiBanner />
<RecentEvents paged />
