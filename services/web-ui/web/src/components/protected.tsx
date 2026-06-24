import { type ReactNode } from "react";
import { Loader2 } from "lucide-react";
import { Navigate, Outlet } from "react-router-dom";

import { useAuth } from "@/lib/auth-context";

function FullScreen({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center text-muted-foreground">
      {children}
    </div>
  );
}

/**
 * Layout route guard: shows a spinner while the initial session probe runs,
 * redirects to /login when there's no (unlocked) session, else renders the
 * nested routes. NIST 800-53: AC-3 (access enforcement at the UI boundary).
 */
export function RequireAuth() {
  const { isAuthenticated, isChecking } = useAuth();
  if (isChecking) {
    return (
      <FullScreen>
        <Loader2 className="mr-2 size-5 animate-spin" /> Checking session…
      </FullScreen>
    );
  }
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <Outlet />;
}

/** Gate a page/section behind a permission (mirrors the CA's RBAC). */
export function RequirePermission({
  permission,
  children,
}: {
  permission: string;
  children: ReactNode;
}) {
  const { can } = useAuth();
  if (!can(permission)) {
    return (
      <div className="p-6">
        <div className="rounded-md border border-yellow-500/30 bg-yellow-500/10 px-4 py-3 text-sm text-yellow-700 dark:text-yellow-300">
          You don't have permission to view this page.
        </div>
      </div>
    );
  }
  return <>{children}</>;
}
