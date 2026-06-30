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

// One row of the certificate inventory listing (GET /ca/api/v1/certificates).
export interface CertificateRow {
  id: string;
  serialNumber: string;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  status: string;
  keyAlgorithm?: string | null;
  /** Whole days until expiry (server-computed), clamped at 0. */
  daysRemaining?: number | null;
}

export interface CertificateListResponse {
  certificates: CertificateRow[];
  total: number;
  page: number;
  pageSize: number;
}

export interface CertificateSan {
  nameType: string;
  value: string;
}

export interface CertificateExtension {
  oid: string;
  name: string;
  critical: boolean;
  value: string;
}

// The CA's full certificate detail DTO (camelCase). Backs the detail view and
// the renew pre-fill.
export interface CertificateDetail {
  id: string;
  serialNumber: string;
  version: number;
  status: string;
  subjectDn: string;
  issuerDn: string;
  validFrom: string;
  validTo: string;
  daysRemaining?: number | null;
  keyAlgorithm: string;
  keySize: number;
  signatureAlgorithm: string;
  fingerprintSha256: string;
  fingerprintSha1: string;
  extensions: CertificateExtension[];
  subjectAltNames: CertificateSan[];
  keyUsage: string[];
  extendedKeyUsage: string[];
  authorityKeyId?: string | null;
  subjectKeyId?: string | null;
  crlDistributionPoints: string[];
  ocspResponderUrls: string[];
  revocationTime?: string | null;
  revocationReason?: string | null;
  pem: string;
}

// Certs-only PKCS#7 (.p7b) download payload: base64-encoded DER (leaf + CA).
export interface CertificatePkcs7 {
  pkcs7: string;
}

// Filters for the certificate inventory listing.
export interface ListCertificatesParams {
  status?: string;
  search?: string;
  /** Active certs expiring within this many days (drill-down from the dashboard). */
  expiringInDays?: number;
  sort?: "serial" | "subject" | "issuer" | "expires";
  order?: "asc" | "desc";
  page?: number;
  pageSize?: number;
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

/** Subject CN + SANs parsed from a pasted CSR (submit-form preview). */
export interface ParsedCsrInfo {
  commonName: string | null;
  subjectDn: string;
  sans: string[];
}

// --- EST enrollment catalog (GET /est/.well-known/est/catalog) ---
export interface EstCatalogProfile {
  token: string;
  profileName?: string | null;
  display: string;
  description: string;
  issuable: boolean;
  serverKeygen: boolean;
}

export interface EstCatalogKeyAlgo {
  token: string;
  display: string;
  description: string;
}

export interface EstCatalog {
  labelFormat: string;
  /** Whether label-routed enrollment (/{label}/simpleenroll) is configured. */
  labeledEnrollment: boolean;
  /** Profile issued by the unlabeled /.well-known/est/simpleenroll path. */
  defaultProfile: string;
  profiles: EstCatalogProfile[];
  keyAlgorithms: EstCatalogKeyAlgo[];
  maxValidityDays: number;
  maxCcsaLen: number;
  examples: string[];
}

// --- Audit log (GET /ca/api/v1/audit, /audit/verify) — ReadAuditLog (RA/CAA) ---
export interface AuditEvent {
  id: string;
  timestamp: string;
  eventType: string;
  actor: string;
  target: string;
  action: string;
  outcome: string;
  /** True if the record carries an AU-10 digital signature (vs. hash-chain only). */
  signed: boolean;
  ipAddress?: string | null;
}

export interface AuditListResponse {
  events: AuditEvent[];
  total: number;
  page: number;
  pageSize: number;
}

export interface AuditVerifyResult {
  /** True iff the hash chain recomputes AND every signed record verifies. */
  intact: boolean;
  totalRecords: number;
  signedRecords: number;
  verifiedAt: string;
}

export interface ListAuditParams {
  page?: number;
  pageSize?: number;
  actor?: string;
  eventType?: string;
  outcome?: string;
  start?: string;
  end?: string;
  sort?: string;
  order?: "asc" | "desc";
}

/** Inventory certificate counts (dashboard). Own-scoped for Sponsors. */
export interface CertificateStats {
  total: number;
  active: number;
  revoked: number;
  expired: number;
  pending: number;
  expiringSoon: number;
}

export const portalApi = {
  /**
   * Parse a pasted PKCS#10 CSR to preview its Common Name + Subject Alternative
   * Names. Portal-local and session-gated; the CA re-validates on submit.
   */
  parseCsr: (csrPem: string) =>
    api.post<ParsedCsrInfo>("/v1/parse-csr", { csr_pem: csrPem }),

  /** Inventory certificate counts for the dashboard (own-scoped for Sponsors). */
  certificateStats: () =>
    api.get<CertificateStats>("/ca/api/v1/certificates/stats"),

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

  /**
   * List issued certificates (own-scoped for Sponsors). With `expiringInDays`
   * this is the drill-down behind the dashboard's "Expiring in N Days" card and
   * matches that count exactly.
   */
  listCertificates: (params: ListCertificatesParams = {}) => {
    const qs = new URLSearchParams();
    if (params.status) qs.set("status", params.status);
    if (params.search) qs.set("search", params.search);
    if (params.expiringInDays != null)
      qs.set("expiringInDays", String(params.expiringInDays));
    if (params.sort) qs.set("sort", params.sort);
    if (params.order) qs.set("order", params.order);
    if (params.page != null) qs.set("page", String(params.page));
    if (params.pageSize != null) qs.set("pageSize", String(params.pageSize));
    const query = qs.toString();
    const suffix = query ? `?${query}` : "";
    return api.get<CertificateListResponse>(`/ca/api/v1/certificates${suffix}`);
  },

  /** Look up an issued certificate by id (for review before revoking). */
  getCertificate: (id: string) =>
    api.get<CertificateSummary>(`/ca/api/v1/certificates/${encodeURIComponent(id)}`),

  /** Full certificate detail (SANs, key usage) — used to pre-fill a renewal. */
  certificateDetail: (id: string) =>
    api.get<CertificateDetail>(`/ca/api/v1/certificates/${encodeURIComponent(id)}`),

  /** Certs-only PKCS#7 (.p7b) for a certificate: base64 DER of leaf + issuing CA. */
  certificatePkcs7: (id: string) =>
    api.get<CertificatePkcs7>(`/ca/api/v1/certificates/${encodeURIComponent(id)}/pkcs7`),

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

  /** Paginated, filtered audit-log review (ReadAuditLog — RA/CAA). FAU_SAR.1. */
  listAuditEvents: (params: ListAuditParams = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v != null && v !== "") qs.set(k, String(v));
    }
    const suffix = qs.toString() ? `?${qs}` : "";
    return api.get<AuditListResponse>(`/ca/api/v1/audit${suffix}`);
  },

  /** Recompute the audit hash chain + verify signatures (AU-9/AU-10). */
  verifyAuditChain: () => api.get<AuditVerifyResult>("/ca/api/v1/audit/verify"),

  /** EST enrollment catalog (label scheme + profile/key-algorithm tokens). */
  estCatalog: () => api.get<EstCatalog>("/est/.well-known/est/catalog"),

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
