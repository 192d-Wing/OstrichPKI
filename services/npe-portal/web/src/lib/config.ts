// Runtime config injected by the Rust server into index.html as
// `window.__OSTRICH_NPE_CONFIG__` (server/template.rs serve_index).
export interface ClientConfig {
  apiBaseUrl: string;
  appName: string;
  classificationBanner: string;
  /** Optional explicit banner background (CSS color); overrides the derived one. */
  classificationColor?: string | null;
  version: string;
  basename: string;
}

declare global {
  interface Window {
    __OSTRICH_NPE_CONFIG__?: Partial<ClientConfig>;
  }
}

const defaults: ClientConfig = {
  apiBaseUrl: "/api",
  appName: "OstrichPKI NPE Portal",
  classificationBanner: "UNCLASSIFIED//FOR OFFICIAL USE ONLY",
  version: "dev",
  basename: "/",
};

export const config: ClientConfig = {
  ...defaults,
  ...(window.__OSTRICH_NPE_CONFIG__ ?? {}),
};
