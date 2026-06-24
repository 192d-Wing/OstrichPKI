import { api } from "@/lib/api";

// Mirrors the CA's certificate types (services/web-ui/src/client/types/api.rs).
export type CertificateStatus = "active" | "revoked" | "expired" | "pending";

export interface CertificateSummary {
  id: string;
  serialNumber: string;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  status: CertificateStatus;
  keyAlgorithm?: string | null;
}

export interface CertificateListResponse {
  certificates: CertificateSummary[];
  total?: number;
  page?: number;
  pageSize?: number;
  totalPages?: number;
}

/** GET the certificate inventory, proxied to the CA's GET /api/v1/certificates. */
export function fetchCertificates(
  query: string,
): Promise<CertificateListResponse> {
  return api.get<CertificateListResponse>(`/ca/api/v1/certificates?${query}`);
}

// RFC 5280 §5.3.1 reason codes. Wire form is PascalCase to match the CA's
// `RevocationReason` — the revoke endpoint rejects any other casing.
export type RevocationReason =
  | "Unspecified"
  | "KeyCompromise"
  | "CaCompromise"
  | "AffiliationChanged"
  | "Superseded"
  | "CessationOfOperation"
  | "CertificateHold"
  | "RemoveFromCrl"
  | "PrivilegeWithdrawn"
  | "AaCompromise";

export const REVOCATION_REASONS: { value: RevocationReason; label: string }[] = [
  { value: "Unspecified", label: "Unspecified" },
  { value: "KeyCompromise", label: "Key Compromise" },
  { value: "CaCompromise", label: "CA Compromise" },
  { value: "AffiliationChanged", label: "Affiliation Changed" },
  { value: "Superseded", label: "Superseded" },
  { value: "CessationOfOperation", label: "Cessation of Operation" },
  { value: "CertificateHold", label: "Certificate Hold" },
  { value: "PrivilegeWithdrawn", label: "Privilege Withdrawn" },
  { value: "AaCompromise", label: "AA Compromise" },
];

/** Revoke a certificate (CA's POST /api/v1/certificates/{id}/revoke). */
export function revokeCertificate(
  id: string,
  reason: RevocationReason,
  notes?: string,
): Promise<unknown> {
  return api.post(`/ca/api/v1/certificates/${id}/revoke`, {
    reason,
    notes: notes && notes.trim() ? notes.trim() : null,
  });
}
