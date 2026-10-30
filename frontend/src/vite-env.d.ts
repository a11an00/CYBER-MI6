/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "mock" or "api"; see src/lib/api/client.ts. */
  readonly VITE_DATA_SOURCE?: 'mock' | 'api';
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
