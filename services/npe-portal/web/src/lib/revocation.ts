// Canonical RFC 5280 §5.3.1 revocation reasons — the single source of truth for
// the revoke dropdown (by enum name) and the OCSP result (by numeric CRL code),
// so the two can never disagree on wording.

export interface RevocationReason {
  /** CRL reason code (the numeric value used in the CRLReason extension / OCSP). */
  code: number;
  /** The RevocationReason enum variant the CA expects. */
  name: string;
  label: string;
}

export const REVOCATION_REASONS: readonly RevocationReason[] = [
  { code: 0, name: "Unspecified", label: "Unspecified" },
  { code: 1, name: "KeyCompromise", label: "Key compromise" },
  { code: 2, name: "CaCompromise", label: "CA compromise" },
  { code: 3, name: "AffiliationChanged", label: "Affiliation changed" },
  { code: 4, name: "Superseded", label: "Superseded" },
  { code: 5, name: "CessationOfOperation", label: "Cessation of operation" },
  { code: 6, name: "CertificateHold", label: "Certificate hold" },
  { code: 8, name: "RemoveFromCrl", label: "Remove from CRL" },
  { code: 9, name: "PrivilegeWithdrawn", label: "Privilege withdrawn" },
  { code: 10, name: "AaCompromise", label: "AA compromise" },
];

/** Human label for a numeric CRL reason code (e.g. from an OCSP RevokedInfo). */
export function revocationReasonLabel(code: number): string {
  return REVOCATION_REASONS.find((r) => r.code === code)?.label ?? `Reason ${code}`;
}
