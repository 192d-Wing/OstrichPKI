import { useQuery } from "@tanstack/react-query";
import {
  Box,
  ExpandableSection,
  KeyValuePairs,
  SpaceBetween,
} from "@cloudscape-design/components";

import { portalApi, type SubmittedApplicationDetails } from "@/lib/portal-api";

/** Comma-separate a list of values, or an em dash when empty/absent. */
function listOrDash(values?: string[] | null): string {
  return values && values.length > 0 ? values.join(", ") : "—";
}

/**
 * Renders what a requester submitted for a certificate application — the fields
 * from `request_details` plus the Common Name / Subject DN parsed from the CSR.
 *
 * Shared by the RA review view (manage-application-detail) and the requester's
 * own status view (application-status); both read the same owner-or-approver
 * gated `getApplication` detail response, so neither exposes anything the viewer
 * is not already authorized to see.
 *
 * `cacheKey` should be the request id, so the per-application CSR parse is cached
 * independently.
 */
export function SubmittedDetails({
  details,
  cacheKey,
}: Readonly<{ details?: SubmittedApplicationDetails | null; cacheKey: string }>) {
  // The CSR carries the Common Name / full subject; parse it (portal-local,
  // session-gated) so the identity being requested is shown, not just the SANs.
  const csrPem = details?.csr_pem ?? "";
  const csrInfo = useQuery({
    queryKey: ["submitted-csr", cacheKey],
    queryFn: () => portalApi.parseCsr(csrPem),
    enabled: csrPem.length > 0,
  });

  if (!details) {
    return <Box color="text-body-secondary">No submitted details available.</Box>;
  }

  const commonName = csrInfo.data?.commonName ?? (csrInfo.isLoading ? "Loading…" : "—");

  return (
    <SpaceBetween size="l">
      <KeyValuePairs
        columns={3}
        items={[
          { label: "Common name", value: commonName },
          { label: "Subject DN", value: <Box variant="code">{csrInfo.data?.subjectDn ?? "—"}</Box> },
          { label: "Profile", value: details.profile ?? "—" },
          { label: "Subject alternative names", value: listOrDash(details.subject_alt_names) },
          { label: "Key usage", value: listOrDash(details.key_usage) },
          { label: "Extended key usage", value: listOrDash(details.extended_key_usage) },
          { label: "CC/S/A", value: details.ccsa ?? "—" },
          { label: "Notification email", value: details.notification_email ?? "—" },
          { label: "ISSM email", value: details.issm_email ?? "—" },
          { label: "PM email", value: details.pm_email ?? "—" },
        ]}
      />
      {details.csr_pem && (
        <ExpandableSection headerText="Submitted CSR (PEM)">
          <Box variant="code" fontSize="body-s">
            <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {details.csr_pem}
            </pre>
          </Box>
        </ExpandableSection>
      )}
    </SpaceBetween>
  );
}
