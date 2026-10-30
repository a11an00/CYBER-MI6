<script lang="ts">
  import { href } from '../lib/router';

  let { path }: { path: string } = $props();
</script>

<svelte:head><title>Not found · CYBER-MI6</title></svelte:head>

<h1>Page not found</h1>
<!-- Svelte text interpolation sets textContent, so the path is never parsed as HTML. -->
<p>No page exists at <code>{path}</code>.</p>
<p><a href={href.overview}>Back to overview</a></p>
