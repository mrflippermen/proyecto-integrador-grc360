/// <reference path="../.astro/types.d.ts" />
/// <reference types="astro/client" />

interface ImportMetaEnv {
  /** URL base de la API Flask (por defecto http://127.0.0.1:5000/api). */
  readonly PUBLIC_API_URL: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
