import { type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Navigate, Route, Routes } from "react-router-dom";

import { AppLayout } from "@/components/layout/app-layout";
import { RequireAuth, RequirePermission } from "@/components/protected";
import { AuthProvider } from "@/lib/auth-context";
import { AuditPage } from "@/pages/audit";
import { CertificatesPage } from "@/pages/certificates";
import { DashboardPage } from "@/pages/dashboard";
import { EstPage } from "@/pages/est";
import { LoginPage } from "@/pages/login";
import { Placeholder } from "@/pages/placeholder";

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, staleTime: 10_000 } },
});

/** Wrap a page in its RBAC permission gate. */
function gated(permission: string, node: ReactNode) {
  return <RequirePermission permission={permission}>{node}</RequirePermission>;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />

          {/* Authenticated app shell. Only EST is ported so far; the rest are
              placeholders (P3) but route + gate exactly like the real pages. */}
          <Route element={<RequireAuth />}>
            <Route element={<AppLayout />}>
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<DashboardPage />} />
              <Route path="est" element={gated("generate_est_token", <EstPage />)} />
              <Route
                path="certificates"
                element={gated("view_certificates", <CertificatesPage />)}
              />
              <Route path="crl" element={gated("view_crl", <Placeholder title="Revocation Lists" />)} />
              <Route path="profiles" element={gated("view_config", <Placeholder title="Profiles" />)} />
              <Route path="approvals" element={gated("view_approvals", <Placeholder title="Approvals" />)} />
              <Route path="audit" element={gated("read_audit_log", <AuditPage />)} />
              <Route path="scms" element={gated("view_tokens", <Placeholder title="Tokens" />)} />
              <Route path="users" element={gated("manage_users", <Placeholder title="Users" />)} />
              <Route path="settings" element={gated("view_config", <Placeholder title="Settings" />)} />
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Route>
          </Route>
        </Routes>
      </AuthProvider>
    </QueryClientProvider>
  );
}
