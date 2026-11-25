/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Optional absolute API base URL; defaults to same-origin (Vite proxy). */
  readonly VITE_API_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
