// Runtime config injected by the Rust server into index.html as
// `window.__OSTRICH_NPE_CONFIG__` (server/template.rs serve_index).

/** A certificate profile offered on the submit form (deployment-configured). */
export interface CertProfile {
  label: string;
  value: string;
  /** Server-side key generation flow (EFS): no CSR; returns a PKCS#12. */
  efs?: boolean;
  /** Carries id-kp-serverAuth EKU → drives the 397-day validity advisory. */
  serverAuth?: boolean;
}

/** A CC/S/A option group (DoD mode). */
export interface CcsaGroup {
  label: string;
  options: { label: string; value: string }[];
}

export interface ClientConfig {
  apiBaseUrl: string;
  appName: string;
  classificationBanner: string;
  /** Optional explicit banner background (CSS color); overrides the derived one. */
  classificationColor?: string | null;
  /** DoD deployment mode — gates DoD-specific UI (e.g. the CC/S/A selector). */
  dodMode: boolean;
  /** Certificate profiles offered on the submit form. */
  certProfiles: CertProfile[];
  /** CC/S/A option groups (shown only in DoD mode). */
  ccsaOptions: CcsaGroup[];
  /** Public EST base URL (e.g. https://est.example.mil) for the catalog page's
   * enrollment commands. When unset, the page guesses from the browser host. */
  estBaseUrl?: string | null;
  /** Server inactivity timeout (seconds); drives the pre-logout warning modal. */
  sessionIdleSeconds: number;
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
  dodMode: false,
  certProfiles: [
    { label: "TLS Client", value: "tls_client" },
    { label: "TLS Server", value: "tls_server", serverAuth: true },
    { label: "TLS Server + Client", value: "tls_server_client", serverAuth: true },
    { label: "EFS (File Encryption)", value: "efs", efs: true },
  ],
  ccsaOptions: [],
  sessionIdleSeconds: 1800,
  version: "dev",
  basename: "/",
};

export const config: ClientConfig = {
  ...defaults,
  ...(window.__OSTRICH_NPE_CONFIG__ ?? {}),
};
