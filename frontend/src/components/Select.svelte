<script lang="ts" generics="T extends string">
  // Figma "Select": a native <select> (keyboard and screen-reader friendly)
  // styled as the component: radius/md, 1px color/border/default, padding
  // spacing/xs × spacing/md; label Body/Small secondary, value 500 12/16.
  let {
    label,
    value = $bindable(),
    options,
  }: { label: string; value: T; options: readonly { value: T; label: string }[] } = $props();
</script>

<label class="select">
  <span class="label">{label}:</span>
  <select bind:value>
    {#each options as option (option.value)}
      <option value={option.value}>{option.label}</option>
    {/each}
  </select>
  <svg class="chevron" viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6" /></svg>
</label>

<style>
  .select {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: var(--spacing-xs);
    padding: var(--spacing-xs) var(--spacing-md);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    background: var(--color-bg-surface);
    white-space: nowrap;
  }
  .select:focus-within {
    outline: 2px solid var(--color-focus-ring);
    outline-offset: 0;
  }
  .label {
    font: var(--text-body-small);
    color: var(--color-text-secondary);
  }
  select {
    appearance: none;
    field-sizing: content; /* hug the chosen value, like the Figma component */
    margin: 0;
    padding: 0 14px 0 0;
    border: none;
    background: transparent;
    font: var(--text-body-small-strong);
    color: var(--color-text-primary);
    cursor: pointer;
  }
  select:focus {
    outline: none;
  }
  option {
    background: var(--color-bg-surface);
    color: var(--color-text-primary);
  }
  .chevron {
    position: absolute;
    right: var(--spacing-md);
    width: 12px;
    height: 12px;
    fill: none;
    stroke: var(--color-text-secondary);
    stroke-width: 2;
    stroke-linecap: round;
    stroke-linejoin: round;
    pointer-events: none;
  }
</style>
