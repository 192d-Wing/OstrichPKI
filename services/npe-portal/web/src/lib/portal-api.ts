// Typed wrappers over the allowlisted BFF proxy (/api/ca/*, /api/est/*). The
// proxy attaches the authenticated NPE identity; these calls carry no credential.
import { api } from "@/lib/api";

export interface ApplicationInfo {
  id: string;
  request_type: string;
  requestor_username: string;
  status: string;
  created_at: string;
  expires_at: string;
}

export interface ApplicationDetail {
  request: ApplicationInfo;
  decisions: {
    id: string;
    approver_username: string;
    decision: string;
    reason?: string | null;
    justification?: string | null;
    decided_at: string;
  }[];
}

export interface CaInfo {
  ca_id: string;
  ca_dn: string;
  issuer_dn?: string;
  serial?: string;
  not_before?: string;
  not_after?: string;
  signature_algorithm?: string;
  key_type?: string;
  chain_pem?: string;
}

export interface ApprovalDecisionResult {
  decision: {
    id: string;
    approver_username: string;
    decision: string;
    reason?: string | null;
    justification?: string | null;
    decided_at: string;
  };
  updated_status: string;
}

// NOTE: the CA's certificate detail DTO is serialized camelCase
// (`#[serde(rename_all = "camelCase")]`), unlike the snake_case approval DTOs.
export interface CertificateSummary {
  serialNumber: string;
  status: string;
  subjectDn: string;
  validTo: string;
  daysRemaining?: number | null;
}

// RFC 5280 §5.3.1 revocation reason codes, serialized as the RevocationReason
// enum variant names the CA expects.
export const REVOCATION_REASONS = [
  { label: "Unspecified", value: "Unspecified" },
  { label: "Key compromise", value: "KeyCompromise" },
  { label: "CA compromise", value: "CaCompromise" },
  { label: "Affiliation changed", value: "AffiliationChanged" },
  { label: "Superseded", value: "Superseded" },
  { label: "Cessation of operation", value: "CessationOfOperation" },
  { label: "Certificate hold", value: "CertificateHold" },
  { label: "Privilege withdrawn", value: "PrivilegeWithdrawn" },
] as const;

export interface RevokeResult {
  success: boolean;
  revocation_time: string;
}

// Bulk enrollment DTOs (camelCase — the CA bulk endpoints serialize camelCase).
export interface BulkJobSummary {
  id: string;
  bulkIdentifier: string;
  profileName: string;
  status: string;
  totalCount: number;
  succeededCount: number;
  failedCount: number;
  createdAt: string;
  completedAt?: string | null;
}

export interface BulkItem {
  itemIndex: number;
  sourceName: string;
  subjectCn?: string | null;
  status: string;
  requestId?: string | null;
  error?: string | null;
}

export interface BulkJobDetail {
  job: BulkJobSummary;
  items: BulkItem[];
}

// CAA DTOs (camelCase — the CA serializes these camelCase).
export interface PortalUser {
  id: string;
  username: string;
  displayName?: string | null;
  email?: string | null;
  certificateSubject?: string | null;
  roles: string[];
  status: string;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string | null;
}

// Roles the CAA may assign (must match ASSIGNABLE_NPE_ROLES on the backend).
export const ASSIGNABLE_ROLES = [
  { label: "PKI Sponsor", value: "pki_sponsor" },
  { label: "PKI Sponsor (Admin)", value: "pki_sponsor_admin" },
  { label: "Registration Authority", value: "registration_authority" },
  { label: "CA Admin (CAA)", value: "caa_admin" },
] as const;

export const ACCOUNT_STATUSES = ["active", "disabled", "suspended", "locked"] as const;

export interface Namespace {
  id: string;
  pattern: string;
  allow: boolean;
  description?: string | null;
  createdBy: string;
  createdAt: string;
}

export interface ConfigSetting {
  key: string;
  value: string;
  description?: string | null;
  updatedBy: string;
  updatedAt: string;
}

export interface SubmitApplicationResponse {
  id: string;
  request_type: string;
  status: string;
  created_at: string;
  expires_at: string;
}

export interface MintTokenResponse {
  token: string;
  identity: string;
  expiresAt: string;
  expiresInSeconds: number;
  maxUses: number;
}

export interface EfsKeygenResponse {
  format: string;
  certificateId: string;
  /** Base64-encoded encrypted PKCS#12 (RFC 7292) holding the key + certificate. */
  pkcs12: string;
  /** One-time PKCS#12 decryption password — shown once, never recoverable. */
  password: string;
}

// EST label that resolves to the EFS profile (server-side keygen, RSA-2048
// delivered as an encrypted PKCS#12). See `ParsedLabel::profile_name`.
export const EFS_EST_LABEL = "PTEFS";

// EST password TTL is fixed at 8 hours per the portal requirements.
export const EST_TOKEN_TTL_SECONDS = 8 * 60 * 60;

export const portalApi = {
  /** Submit a certificate application (issuance) or rekey (renewal). */
  submitApplication: (
    requestType: "issuance" | "renewal",
    details: Record<string, unknown>,
  ) =>
    api.post<SubmitApplicationResponse>("/ca/api/v1/approvals", {
      request_type: requestType,
      request_details: details,
    }),

  listMyApplications: () =>
    api.get<{ requests: ApplicationInfo[] }>("/ca/api/v1/approvals"),

  /**
   * The approval queue. Hits the same endpoint as listMyApplications; the CA
   * returns every pending request (not just the caller's own) when the caller
   * holds the ApproveRequest permission, i.e. for an RA.
   */
  listApprovalQueue: () =>
    api.get<{ requests: ApplicationInfo[] }>("/ca/api/v1/approvals"),

  /** Approve a pending application. `override` requires OverrideValidation. */
  approveApplication: (id: string, justification: string, override = false) =>
    api.post<ApprovalDecisionResult>(
      `/ca/api/v1/approvals/${encodeURIComponent(id)}/approve${
        override ? "?override=true" : ""
      }`,
      { justification },
    ),

  /** Reject a pending application with a reason + justification. */
  rejectApplication: (id: string, reason: string, justification: string) =>
    api.post<ApprovalDecisionResult>(
      `/ca/api/v1/approvals/${encodeURIComponent(id)}/reject`,
      { reason, justification },
    ),

  /** Look up an issued certificate by id (for review before revoking). */
  getCertificate: (id: string) =>
    api.get<CertificateSummary>(`/ca/api/v1/certificates/${encodeURIComponent(id)}`),

  /** Revoke an issued certificate. `reason` is an RFC 5280 reason-code name. */
  revokeCertificate: (id: string, reason: string, justification: string) =>
    api.post<RevokeResult>(
      `/ca/api/v1/certificates/${encodeURIComponent(id)}/revoke`,
      { reason, justification },
    ),

  /**
   * Bulk-enroll a ZIP of CSRs under one profile (Administrator). Each valid CSR
   * is queued as an approval request; returns the job + per-CSR outcomes.
   */
  bulkEnroll: (profile: string, archive: File) => {
    const form = new FormData();
    form.append("profile", profile);
    form.append("archive", archive);
    return api.postForm<BulkJobDetail>("/ca/api/v1/bulk-enroll", form);
  },

  getApplication: (id: string) =>
    api.get<ApplicationDetail>(`/ca/api/v1/approvals/${encodeURIComponent(id)}`),

  bulkStatus: (ids: string[]) =>
    api.get<{ requests: ApplicationInfo[] }>(
      `/ca/api/v1/approvals/status?ids=${encodeURIComponent(ids.join(","))}`,
    ),

  caInfo: () => api.get<CaInfo>("/ca/api/v1/ca/info"),

  /** Mint an EST enrollment password (single- or multi-use). */
  mintToken: (identity: string, maxUses: number) =>
    api.post<MintTokenResponse>("/est/api/v1/est/enrollment-tokens", {
      identity,
      ttlSeconds: EST_TOKEN_TTL_SECONDS,
      maxUses,
    }),

  /**
   * EFS server-side key generation. The server generates the RSA key (the
   * subject is the authenticated identity — no CSR or client key is sent) and
   * returns it + the issued certificate as an encrypted PKCS#12 with a one-time
   * password. Auto-issued: this does NOT go through the approval queue.
   */
  efsServerKeygen: (keyStrength: number) =>
    api.post<EfsKeygenResponse>(
      `/est/.well-known/est/${EFS_EST_LABEL}/serverkeygen`,
      { keyStrength },
    ),

  // --- CAA: user management ---
  listUsers: () => api.get<PortalUser[]>("/ca/api/v1/users"),
  createUser: (body: {
    username: string;
    certificateSubject: string;
    displayName?: string;
    email?: string;
    roles: string[];
  }) => api.post<PortalUser>("/ca/api/v1/users", body),
  setUserRoles: (id: string, roles: string[]) =>
    api.put<PortalUser>(`/ca/api/v1/users/${encodeURIComponent(id)}/roles`, { roles }),
  setUserStatus: (id: string, status: string) =>
    api.put<PortalUser>(`/ca/api/v1/users/${encodeURIComponent(id)}/status`, { status }),
  deleteUser: (id: string) => api.del(`/ca/api/v1/users/${encodeURIComponent(id)}`),

  // --- CAA: namespace / wildcard policy ---
  listNamespaces: () => api.get<Namespace[]>("/ca/api/v1/namespaces"),
  createNamespace: (body: { pattern: string; allow: boolean; description?: string }) =>
    api.post<Namespace>("/ca/api/v1/namespaces", body),
  deleteNamespace: (id: string) => api.del(`/ca/api/v1/namespaces/${encodeURIComponent(id)}`),

  // --- CAA: system configuration ---
  listConfig: () => api.get<ConfigSetting[]>("/ca/api/v1/config"),
  setConfig: (key: string, value: string) =>
    api.put<ConfigSetting>(`/ca/api/v1/config/${encodeURIComponent(key)}`, { value }),
};
