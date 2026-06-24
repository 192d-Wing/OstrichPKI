// Runtime config injected by the Rust server into index.html as
// `window.__CONFIG__` (mirrors the existing ClientConfig the Yew app reads).
// See docs/WEBUI_SHADCN_MIGRATION.md §4.2.
export interface ClientConfig {
  apiBaseUrl: string;
  oidcClientId: string;
  oidcAuthUrl: string;
  appName: string;
  version: string;
}

declare global {
  interface Window {
    __CONFIG__?: Partial<ClientConfig>;
  }
}

const defaults: ClientConfig = {
  apiBaseUrl: "/api",
  oidcClientId: "",
  oidcAuthUrl: "",
  appName: "OstrichPKI",
  version: "dev",
};

export const config: ClientConfig = {
  ...defaults,
  ...(typeof window !== "undefined" ? window.__CONFIG__ : undefined),
};
