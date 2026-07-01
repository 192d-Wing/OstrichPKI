// NPE portal identity + RBAC. The role is derived server-side from the mTLS
// client certificate's OIDs; the SPA only mirrors the role->permission map so it
// can render the right menus. The CA service is the real enforcement point.

export interface UserInfo {
  commonName: string;
  subjectDn: string;
  roles: string[];
  consentAccepted: boolean;
}

// Mirrors crates/ostrich-common/src/auth/permissions.rs (NPE roles).
const ROLE_PERMISSIONS: Record<string, string[]> = {
  pki_sponsor: [
    "submit_request",
    "renew_certificate",
    "view_requests",
    "view_certificate",
    "generate_est_token",
  ],
  pki_sponsor_admin: [
    "submit_request",
    "renew_certificate",
    "view_requests",
    "view_certificate",
    "generate_est_token",
    "bulk_enroll",
  ],
  registration_authority: [
    "approve_request",
    "reject_request",
    "view_requests",
    "revoke_certificate",
    "override_validation",
    "view_certificate",
    "read_audit_log",
  ],
  caa_admin: [
    "modify_config",
    "view_config",
    "create_user",
    "modify_user",
    "delete_user",
    "assign_roles",
    "view_users",
    "manage_namespaces",
    "read_audit_log",
  ],
  npe_auditor: ["read_audit_log", "view_certificate", "view_requests"],
};

export function hasPermission(user: UserInfo | null, permission: string): boolean {
  if (!user) return false;
  return user.roles.some((r) => ROLE_PERMISSIONS[r]?.includes(permission));
}

/** The portal certificate maps to exactly one NPE role; return the first. */
export function primaryRole(user: UserInfo | null): string | null {
  return user?.roles[0] ?? null;
}

export function roleLabel(role: string | null): string {
  switch (role) {
    case "pki_sponsor":
      return "PKI Sponsor";
    case "pki_sponsor_admin":
      return "Administrator";
    case "registration_authority":
      return "Registration Authority";
    case "caa_admin":
      return "Certificate Authority Admin";
    case "npe_auditor":
      return "Auditor";
    default:
      return "Unknown";
  }
}

async function authFetch(method: string, path: string): Promise<UserInfo | null> {
  const res = await fetch(path, { method, credentials: "same-origin" });
  if (!res.ok) return null;
  try {
    return (await res.json()) as UserInfo;
  } catch {
    return null;
  }
}

/**
 * Establish (or resume) a session. GET /auth/login is idempotent: it returns the
 * existing session if the cookie is live, otherwise performs the mTLS OID->role
 * bootstrap. Returns null when no authorized client certificate was presented.
 */
export function fetchSession(): Promise<UserInfo | null> {
  return authFetch("GET", "/auth/login");
}

/** Acknowledge the USG consent banner; returns the updated session. */
export function acceptConsent(): Promise<UserInfo | null> {
  return authFetch("POST", "/auth/consent");
}

export async function logout(): Promise<void> {
  await fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
}
