import { lazy, Suspense, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Navigate, Route, Routes } from "react-router-dom";
import Spinner from "@cloudscape-design/components/spinner";

import { CloudscapeLayout } from "@/components/layout/cloudscape-layout";
import { RequireAuth, RequirePermission } from "@/components/protected";
import { AuthProvider } from "@/lib/auth-context";
import { Placeholder } from "@/pages/placeholder";

// Route-level code-splitting: each page is its own async chunk so the initial
// load only pulls the shell + the landing route. Named page exports are adapted
// to the default export React.lazy expects.
const AuditPage = lazy(() => import("@/pages/audit").then((m) => ({ default: m.AuditPage })));
const CertificateDetailPage = lazy(() =>
  import("@/pages/certificate-detail").then((m) => ({ default: m.CertificateDetailPage })),
);
const CertificateIssuePage = lazy(() =>
  import("@/pages/certificate-issue").then((m) => ({ default: m.CertificateIssuePage })),
);
const CertificatesPage = lazy(() =>
  import("@/pages/certificates").then((m) => ({ default: m.CertificatesPage })),
);
const CrlPage = lazy(() => import("@/pages/crl").then((m) => ({ default: m.CrlPage })));
const DashboardPage = lazy(() =>
  import("@/pages/dashboard").then((m) => ({ default: m.DashboardPage })),
);
const ProfilesPage = lazy(() =>
  import("@/pages/profiles").then((m) => ({ default: m.ProfilesPage })),
);
const SettingsPage = lazy(() =>
  import("@/pages/settings").then((m) => ({ default: m.SettingsPage })),
);
const EstPage = lazy(() => import("@/pages/est").then((m) => ({ default: m.EstPage })));
const FqdnsPage = lazy(() => import("@/pages/fqdns").then((m) => ({ default: m.FqdnsPage })));
const FqdnDetailPage = lazy(() =>
  import("@/pages/fqdn-detail").then((m) => ({ default: m.FqdnDetailPage })),
);
const LoginPage = lazy(() => import("@/pages/login").then((m) => ({ default: m.LoginPage })));

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, staleTime: 10_000 } },
});

/** Centered spinner shown while a lazy route chunk loads. */
function RouteFallback() {
  return (
    <div style={{ display: "flex", justifyContent: "center", padding: "2rem" }}>
      <Spinner size="large" />
    </div>
  );
}

/** Wrap a page in its RBAC permission gate. */
function gated(permission: string, node: ReactNode) {
  return <RequirePermission permission={permission}>{node}</RequirePermission>;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Suspense fallback={<RouteFallback />}>
          <Routes>
          <Route path="/login" element={<LoginPage />} />

          {/* Authenticated app shell. Approvals, Tokens (SCMS), and Users are
              placeholders (no CA endpoint yet) but route + gate like real pages. */}
          <Route element={<RequireAuth />}>
            <Route element={<CloudscapeLayout />}>
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<DashboardPage />} />
              <Route path="est" element={gated("generate_est_token", <EstPage />)} />
              <Route
                path="certificates"
                element={gated("view_certificates", <CertificatesPage />)}
              />
              {/* static `issue` outranks the dynamic `:id` in react-router. */}
              <Route
                path="certificates/issue"
                element={gated("issue_certificates", <CertificateIssuePage />)}
              />
              <Route
                path="certificates/:id"
                element={gated("view_certificates", <CertificateDetailPage />)}
              />
              <Route path="fqdns" element={gated("view_certificates", <FqdnsPage />)} />
              <Route
                path="fqdns/:fqdn"
                element={gated("view_certificates", <FqdnDetailPage />)}
              />
              <Route path="crl" element={gated("view_crl", <CrlPage />)} />
              <Route path="profiles" element={gated("view_config", <ProfilesPage />)} />
              <Route path="approvals" element={gated("view_approvals", <Placeholder title="Approvals" />)} />
              <Route path="audit" element={gated("read_audit_log", <AuditPage />)} />
              <Route path="scms" element={gated("view_tokens", <Placeholder title="Tokens" />)} />
              <Route path="users" element={gated("manage_users", <Placeholder title="Users" />)} />
              <Route path="settings" element={gated("admin", <SettingsPage />)} />
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Route>
          </Route>
          </Routes>
        </Suspense>
      </AuthProvider>
    </QueryClientProvider>
  );
}
