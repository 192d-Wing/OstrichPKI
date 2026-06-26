import { createContext, useContext, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";

import { fetchSession, hasPermission, type UserInfo } from "@/lib/auth";

interface AuthValue {
  user: UserInfo | null;
  isAuthenticated: boolean;
  isChecking: boolean;
  /** True once authenticated but the USG consent banner is unacknowledged. */
  consentRequired: boolean;
  can: (permission: string) => boolean;
  refresh: () => void;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["npe-session"],
    queryFn: fetchSession,
    retry: false,
    staleTime: 30_000,
  });
  const user = data ?? null;

  const value: AuthValue = {
    user,
    isAuthenticated: !!user,
    isChecking: isLoading,
    consentRequired: !!user && !user.consentAccepted,
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
