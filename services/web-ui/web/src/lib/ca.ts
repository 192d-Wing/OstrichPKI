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

// NOTE: the /profiles, /crl, and /ca/info endpoints return snake_case JSON
// (unlike /certificates and /audit), so these types mirror that exactly.

/** A code-defined certificate profile (read-only catalog). */
export interface CertProfile {
  name: string;
  profile_type: string;
  description?: string;
  validity_days: number;
  key_type: string;
  algorithm: string;
  basic_constraints_ca: boolean;
  basic_constraints_path_len?: number | null;
  subject_alt_name_required: boolean;
  key_usages?: string[];
  extended_key_usages?: string[];
}

export function fetchProfiles(): Promise<{ profiles: CertProfile[] }> {
  return api.get<{ profiles: CertProfile[] }>("/ca/api/v1/profiles");
}

export interface CaInfo {
  ca_id: string;
  ca_dn: string;
}

export function fetchCaInfo(): Promise<CaInfo> {
  return api.get<CaInfo>("/ca/api/v1/ca/info");
}

/** Result of generating a CRL (POST /ca/api/v1/crl[/delta]). */
export interface CrlResult {
  crl_number: number;
  this_update: string;
  next_update: string;
  revoked_count: number;
  pem_encoded: string;
}

export function generateCrl(endpoint: string): Promise<CrlResult> {
  return api.post<CrlResult>(endpoint);
}

/** Liveness probe for a backend service via the proxy (GET /{svc}/health). */
export async function serviceUp(svc: string): Promise<boolean> {
  try {
    await api.get(`/${svc}/health`);
    return true;
  } catch {
    return false;
  }
}

// ---- Certificate detail (camelCase, like the list) -------------------------
export interface CertificateExtension {
  oid: string;
  name: string;
  critical: boolean;
  value: string;
}
export interface SubjectAltName {
  nameType: string;
  value: string;
}
export interface CertificateDetails {
  id: string;
  serialNumber: string;
  version: number;
  status: CertificateStatus;
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
  subjectAltNames: SubjectAltName[];
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

export function fetchCertificateDetail(id: string): Promise<CertificateDetails> {
  return api.get<CertificateDetails>(`/ca/api/v1/certificates/${id}`);
}

// ---- Issuance (snake_case request/response) --------------------------------
export interface IssueResponse {
  certificate_id: string;
  serial_number: string;
  pem_encoded: string;
  not_before: string;
  not_after: string;
}

/** Strip PEM armor from a CSR, leaving the base64 DER body the CA expects. */
export function pemToCsrB64(pem: string): string {
  return pem
    .split("\n")
    .filter((l) => !l.includes("-----"))
    .flatMap((l) => l.split(/\s+/))
    .filter(Boolean)
    .join("");
}

/** Issue an end-entity certificate from a CSR (POST /ca/api/v1/certificates). */
export function issueCertificate(
  profileName: string,
  csrDer: string,
): Promise<IssueResponse> {
  return api.post<IssueResponse>("/ca/api/v1/certificates", {
    profile_name: profileName,
    csr_der: csrDer,
  });
}
