/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL: string;
  readonly VITE_USE_MOCK_DATA: string;
  readonly VITE_POLLING_INTERVAL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}