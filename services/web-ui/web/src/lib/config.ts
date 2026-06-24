// Runtime config injected by the Rust server into index.html as
// `window.__OSTRICH_CONFIG__` — the SAME global the existing server template
// (server/template.rs) already emits for the Yew app, so no server change is
// needed to feed this app. See docs/WEBUI_SHADCN_MIGRATION.md §4.2.
export interface ClientConfig {
  apiBaseUrl: string;
  oidcClientId: string;
  oidcAuthUrl: string;
  appName: string;
  version: string;
}

declare global {
  interface Window {
    __OSTRICH_CONFIG__?: Partial<ClientConfig>;
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
  ...(window.__OSTRICH_CONFIG__ ?? {}),
};
