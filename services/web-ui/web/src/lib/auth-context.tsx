import { createContext, useContext, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";

import { fetchUserInfo, hasPermission, type UserInfo } from "@/lib/auth";

interface AuthValue {
  user: UserInfo | null;
  /** Authenticated AND not locked. */
  isAuthenticated: boolean;
  /** Initial session probe in flight — guards show a spinner, not a bounce. */
  isChecking: boolean;
  sessionLocked: boolean;
  can: (permission: string) => boolean;
  /** Re-run the /auth/userinfo probe (e.g. after login). */
  refresh: () => void;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["userinfo"],
    queryFn: fetchUserInfo,
    retry: false,
    staleTime: 30_000,
  });
  const user = data ?? null;

  const value: AuthValue = {
    user,
    isAuthenticated: !!user && !user.session_locked,
    isChecking: isLoading,
    sessionLocked: !!user?.session_locked,
    can: (permission) => hasPermission(user, permission),
    refresh: () => void refetch(),
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
