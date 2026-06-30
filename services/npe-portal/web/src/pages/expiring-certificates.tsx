import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Badge,
  Box,
  Button,
  ContentLayout,
  Header,
  SpaceBetween,
  Table,
} from "@cloudscape-design/components";

import { portalApi, type CertificateRow } from "@/lib/portal-api";

// The dashboard "Expiring in 90 Days" card drills down to this list; keep the
// window in lockstep with that card's definition.
const EXPIRY_WINDOW_DAYS = 90;

/** Whole days from now until `iso` (negative if already past). */
function daysUntil(iso: string): number {
  const ms = new Date(iso).getTime() - Date.now();
  return Math.ceil(ms / 86_400_000);
}

/** Common Name pulled from an RFC 4514 subject DN, falling back to the full DN. */
function commonName(subjectDn: string): string {
  const match = /CN=([^,]+)/i.exec(subjectDn);
  return match ? match[1].trim() : subjectDn;
}

function ExpiryBadge({ days }: Readonly<{ days: number }>) {
  // <=30 days is the urgent band; <=60 is a heads-up; otherwise neutral.
  const color = days <= 30 ? "red" : days <= 60 ? "blue" : "grey";
  const label = days <= 0 ? "Expires today" : `${days} day${days === 1 ? "" : "s"}`;
  return <Badge color={color}>{label}</Badge>;
}

export function ExpiringCertificatesPage() {
  const navigate = useNavigate();
  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["certificates", "expiring", EXPIRY_WINDOW_DAYS],
    queryFn: () =>
      portalApi.listCertificates({
        status: "active",
        expiringInDays: EXPIRY_WINDOW_DAYS,
        sort: "expires",
        order: "asc",
        pageSize: 500,
      }),
    staleTime: 60_000,
  });

  const items = useMemo(() => data?.certificates ?? [], [data]);

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={`Active certificates expiring within ${EXPIRY_WINDOW_DAYS} days. Renew before expiry to avoid an outage.`}
          counter={data ? `(${data.total})` : undefined}
          actions={
            <Button iconName="refresh" loading={isFetching} onClick={() => refetch()}>
              Refresh
            </Button>
          }
        >
          Expiring Certificates
        </Header>
      }
    >
      <Table<CertificateRow>
        loading={isLoading}
        items={items}
        variant="container"
        wrapLines
        columnDefinitions={[
          {
            id: "subject",
            header: "Common Name",
            cell: (c) => commonName(c.subject),
          },
          {
            id: "serial",
            header: "Serial",
            cell: (c) => <Box variant="code">{c.serialNumber}</Box>,
          },
          {
            id: "expires",
            header: "Expires",
            cell: (c) => c.validTo.slice(0, 10),
          },
          {
            id: "remaining",
            header: "Time remaining",
            cell: (c) => <ExpiryBadge days={daysUntil(c.validTo)} />,
          },
          {
            id: "actions",
            header: "Action",
            cell: (c) => (
              <Button
                variant="inline-link"
                iconName="refresh"
                onClick={() => navigate(`/certificates/rekey?renewFrom=${encodeURIComponent(c.id)}`)}
              >
                Renew / Rekey
              </Button>
            ),
          },
        ]}
        empty={
          <Box textAlign="center" color="inherit">
            <SpaceBetween size="xs">
              <b>Nothing expiring soon</b>
              <span>No active certificate expires within {EXPIRY_WINDOW_DAYS} days.</span>
            </SpaceBetween>
          </Box>
        }
      />
    </ContentLayout>
  );
}
