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
};
