import { type ReactNode } from "react";
import { Navigate, Outlet } from "react-router-dom";
import { Box, Spinner } from "@cloudscape-design/components";

import { useAuth } from "@/lib/auth-context";

/**
 * Layout route guard: shows a spinner while the initial session probe runs,
 * redirects to /login when there's no (unlocked) session, else renders the
 * nested routes. NIST 800-53: AC-3 (access enforcement at the UI boundary).
 */
export function RequireAuth() {
  const { isAuthenticated, isChecking } = useAuth();
  if (isChecking) {
    return (
      <div
        style={{
          display: "flex",
          minHeight: "100vh",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Box color="text-status-inactive">
          <Spinner /> Checking session…
        </Box>
      </div>
    );
  }
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <Outlet />;
}

/** Gate a page/section behind a permission (mirrors the CA's RBAC). */
export function RequirePermission({
  permission,
  children,
}: Readonly<{
  permission: string;
  children: ReactNode;
}>) {
  const { can } = useAuth();
  if (!can(permission)) {
    return (
      <Box padding="l">
        <Box color="text-status-warning">
          You don't have permission to view this page.
        </Box>
      </Box>
    );
  }
  return <>{children}</>;
}
