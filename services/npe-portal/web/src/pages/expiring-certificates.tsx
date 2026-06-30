import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Badge,
  Box,
  Button,
  ContentLayout,
  Header,
  Link,
  SpaceBetween,
  Table,
} from "@cloudscape-design/components";

import { commonName } from "@/lib/dn";
import { portalApi, type CertificateRow } from "@/lib/portal-api";

// The dashboard "Expiring in 90 Days" card drills down to this list; keep the
// window in lockstep with that card's definition.
const EXPIRY_WINDOW_DAYS = 90;

/** Whole days from now until `iso` (negative if already past). Fallback only —
 * the CA supplies `daysRemaining` so the list and detail view agree. */
function daysUntil(iso: string): number {
  const ms = new Date(iso).getTime() - Date.now();
  return Math.ceil(ms / 86_400_000);
}

// <=30 days is the urgent band; <=60 is a heads-up; otherwise neutral.
function expiryColor(days: number): "red" | "blue" | "grey" {
  if (days <= 30) return "red";
  if (days <= 60) return "blue";
  return "grey";
}

function expiryLabel(days: number): string {
  if (days <= 0) return "Expires today";
  return `${days} day${days === 1 ? "" : "s"}`;
}

function ExpiryBadge({ days }: Readonly<{ days: number }>) {
  return <Badge color={expiryColor(days)}>{expiryLabel(days)}</Badge>;
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
            cell: (c) => (
              <Link onFollow={() => navigate(`/certificates/view?id=${encodeURIComponent(c.id)}`)}>
                {commonName(c.subject)}
              </Link>
            ),
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
            // Prefer the CA's server-computed daysRemaining (matches the detail
            // view); fall back to a client estimate only if it's absent.
            cell: (c) => <ExpiryBadge days={c.daysRemaining ?? daysUntil(c.validTo)} />,
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
