import { api } from "@/lib/api";
import type { CertificateSummary } from "@/lib/ca";

// Mirrors the CA's FQDN history DTOs (crates/ostrich-ca/src/rest.rs), proxied via
// the web-ui BFF at /ca/api/v1/fqdns.

/** One row in the distinct-FQDN listing. */
export interface FqdnSummary {
  fqdn: string;
  certificateCount: number;
  firstSeen: string;
  lastIssued: string;
}

export interface FqdnListResponse {
  fqdns: FqdnSummary[];
  total: number;
  page: number;
  pageSize: number;
}

/** Aggregated history for a single FQDN. */
export interface FqdnRecord {
  fqdn: string;
  firstSeen: string | null;
  lastIssued: string | null;
  firstRequestedBy: string | null;
  lastRequestedBy: string | null;
  certificateCount: number;
  notificationEmail: string | null;
  /** True if any cert for this FQDN was EST-issued — drives the EST Tokens tab. */
  usesEst: boolean;
  certificates: CertificateSummary[];
}

/** One EST enrollment token bound to an FQDN (metadata only; never the token). */
export interface EstToken {
  id: string;
  identity: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  status: string;
  usedByCert: string | null;
}

export interface FqdnNotification {
  fqdn: string;
  email: string | null;
  updatedBy: string | null;
  updatedAt: string | null;
}

/** List distinct FQDNs (CA's GET /api/v1/fqdns). */
export function fetchFqdns(query: string): Promise<FqdnListResponse> {
  return api.get<FqdnListResponse>(`/ca/api/v1/fqdns?${query}`);
}

/** Fetch the aggregated history record for one FQDN. */
export function fetchFqdnRecord(fqdn: string): Promise<FqdnRecord> {
  return api.get<FqdnRecord>(`/ca/api/v1/fqdns/${encodeURIComponent(fqdn)}`);
}

/** EST enrollment tokens bound to an FQDN (gated by generate_est_token). */
export function fetchFqdnEstTokens(fqdn: string): Promise<{ tokens: EstToken[] }> {
  return api.get<{ tokens: EstToken[] }>(
    `/ca/api/v1/fqdns/${encodeURIComponent(fqdn)}/est-tokens`,
  );
}

/** Set the renewal-notification contact for an FQDN (PUT). */
export function setFqdnNotification(
  fqdn: string,
  email: string,
): Promise<FqdnNotification> {
  return api.put<FqdnNotification>(
    `/ca/api/v1/fqdns/${encodeURIComponent(fqdn)}/notification`,
    { email },
  );
}
