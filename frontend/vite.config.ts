import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// The FastAPI backend runs on port 8000 (handbook §14). In development, Vite
// forwards API and WebSocket calls to it, so the browser sees one origin and
// no CORS setup is needed. In production FastAPI serves frontend/dist itself.
const BACKEND = 'http://127.0.0.1:8000';

export default defineConfig({
  plugins: [svelte()],
  server: {
    port: 5173,
    proxy: {
      '/api': BACKEND,
      '/ws': { target: BACKEND, ws: true },
    },
  },
});
