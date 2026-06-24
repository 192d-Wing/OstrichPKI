import { api } from "@/lib/api";

// Mirrors the CA's audit types (services/web-ui/src/client/types/api.rs).
export interface AuditEvent {
  id: string;
  timestamp: string;
  eventType: string;
  actor: string;
  target: string;
  action: string;
  outcome: string;
  signed: boolean;
  ipAddress?: string | null;
}

export interface AuditListResponse {
  events: AuditEvent[];
  total: number;
  page: number;
  pageSize: number;
}

export interface AuditVerifyResponse {
  intact: boolean;
  totalRecords: number;
  signedRecords: number;
  verifiedAt: string;
}

/** Event-type filter options (label, backend value) — mirrors the Yew page. */
export const AUDIT_EVENT_TYPES: { value: string; label: string }[] = [
  { value: "authentication", label: "Authentication" },
  { value: "authorization", label: "Authorization" },
  { value: "certificate_issuance", label: "Certificate Issuance" },
  { value: "certificate_revocation", label: "Certificate Revocation" },
  { value: "crl_generation", label: "CRL Generation" },
  { value: "key_generation", label: "Key Generation" },
  { value: "configuration_change", label: "Configuration Change" },
  { value: "access_violation", label: "Access Violation" },
  { value: "token_lifecycle", label: "Token Lifecycle" },
  { value: "est_protocol", label: "EST Protocol" },
  { value: "acme_protocol", label: "ACME Protocol" },
];

/** GET the audit log page (CA paginates + filters). */
export function fetchAuditLogs(query: string): Promise<AuditListResponse> {
  return api.get<AuditListResponse>(`/ca/api/v1/audit?${query}`);
}

/** Recompute the audit hash chain / signature integrity (AU-9 / AU-10). */
export function verifyAudit(): Promise<AuditVerifyResponse> {
  return api.get<AuditVerifyResponse>("/ca/api/v1/audit/verify");
}
