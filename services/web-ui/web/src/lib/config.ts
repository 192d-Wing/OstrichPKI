// Runtime config injected by the Rust server into index.html as
// `window.__OSTRICH_CONFIG__` (server/template.rs serve_index). See
// docs/WEBUI_SHADCN_MIGRATION.md §4.2.
export interface ClientConfig {
  apiBaseUrl: string;
  oidcClientId: string;
  oidcAuthUrl: string;
  appName: string;
  version: string;
  // Router basename. The server injects "/" — the React console is served at the
  // root (the Yew SPA was retired). Legacy /next links 301-redirect to /.
  basename: string;
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
  basename: "/",
};

export const config: ClientConfig = {
  ...defaults,
  ...(window.__OSTRICH_CONFIG__ ?? {}),
};
