import { config } from "@/lib/config";

// Mirrors the server's /auth/userinfo (UserInfoResponse, snake_case).
export interface UserInfo {
  subject: string;
  username: string | null;
  email: string | null;
  roles: string[];
  session_locked: boolean;
}

// Role → permission map, mirroring the CA's RBAC (services/web-ui/src/client/
// services/auth.rs) so the UI gates match what the CA will actually authorize.
// Separation of duties: Administrator manages the system but does NOT issue or
// revoke certificates — that is OperationsStaff.
const ROLE_PERMISSIONS: Record<string, string[]> = {
  Administrator: [
    "view_certificates",
    "view_approvals",
    "view_tokens",
    "view_crl",
    "view_config",
    "manage_users",
    "generate_est_token",
    "admin",
  ],
  admin: [
    "view_certificates",
    "view_approvals",
    "view_tokens",
    "view_crl",
    "view_config",
    "manage_users",
    "generate_est_token",
    "admin",
  ],
  OperationsStaff: [
    "view_certificates",
    "issue_certificates",
    "revoke_certificates",
    "view_tokens",
    "manage_tokens",
    "view_crl",
    "generate_crl",
    "generate_est_token",
  ],
  RaStaff: ["view_certificates", "view_approvals"],
  Aor: ["view_approvals", "approve_requests"],
  Auditor: ["view_certificates", "read_audit_log"],
  auditor: ["view_certificates", "read_audit_log"],
  user: ["view_certificates"],
};

/** True if any of the user's roles grants `permission`. */
export function hasPermission(user: UserInfo | null, permission: string): boolean {
  if (!user) return false;
  return user.roles.some((role) =>
    (ROLE_PERMISSIONS[role] ?? []).includes(permission),
  );
}

/** Display name for the current user. */
export function displayName(user: UserInfo | null): string {
  return user?.username ?? user?.subject ?? "user";
}

/**
 * Fetch the current session identity. Returns null on 401 (no/expired session)
 * so callers can route to login; throws on unexpected transport errors.
 * The session is an httpOnly cookie the JS can't read — this is the probe.
 */
export async function fetchUserInfo(): Promise<UserInfo | null> {
  const res = await fetch("/auth/userinfo", { credentials: "same-origin" });
  if (res.status === 401) return null;
  if (!res.ok) throw new Error(`userinfo failed (${res.status})`);
  return (await res.json()) as UserInfo;
}

/** Internal-auth login. Resolves on success (the server sets the session cookie). */
export async function internalLogin(
  username: string,
  password: string,
): Promise<void> {
  const res = await fetch("/auth/internal-login", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (res.status === 401) throw new Error("Invalid username or password");
  if (!res.ok) throw new Error(`Login failed (HTTP ${res.status})`);
}

/** Begin OIDC SSO (server handles the PKCE redirect). */
export function oidcLoginUrl(): string {
  return "/auth/login";
}

/** Log out (server clears the session, then redirects to /auth/login). */
export function logoutUrl(): string {
  return "/auth/logout";
}

/** Root path the app mounts under (basename), for post-login navigation. */
export function appBase(): string {
  return config.basename === "/" ? "" : config.basename;
}
