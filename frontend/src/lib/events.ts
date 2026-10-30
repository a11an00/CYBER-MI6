import { writable } from 'svelte/store';

/** Bump to make Recent events reload (the WebSocket step calls this for new events). */
export const eventsChanged = writable(0);
export const notifyEventsChanged = () => eventsChanged.update((n) => n + 1);
