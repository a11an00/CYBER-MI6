import { auth } from '../lib/auth';
import { get } from 'svelte/store';

// Same origin by default: in development Vite proxies /api to FastAPI (vite.config.ts), in
// production FastAPI serves the built frontend itself. So no CORS setup is needed.
const API_BASE = import.meta.env.VITE_API_URL || '/api';

interface FetchOptions extends RequestInit {
  requireAuth?: boolean;
}

export async function apiFetch<T>(endpoint: string, options: FetchOptions = {}): Promise<T> {
  const { requireAuth = true, headers, ...customConfig } = options;
  const currentAuth = get(auth);
  
  const config: RequestInit = {
    ...customConfig,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  };

  // The ingestion API key (X-API-Key) is for sensors only. It must never be put in frontend code:
  // every VITE_* variable is copied into the public JavaScript bundle.
  if (requireAuth && currentAuth.token) {
    (config.headers as Record<string, string>)['Authorization'] = `Bearer ${currentAuth.token}`;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, config);

  if (response.status === 401 && requireAuth) {
    const { isAuthenticated } = get(auth);
    if (isAuthenticated) {
      // Only logout if we actually had a session — genuine expiry, not a
      // request that fired before auth.init() had a chance to run.
      auth.logout();
    }
    throw new Error('Session expired. Please log in again.');
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `API request failed with status ${response.status}`);
  }

  return response.json();
}
