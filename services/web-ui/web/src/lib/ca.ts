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
