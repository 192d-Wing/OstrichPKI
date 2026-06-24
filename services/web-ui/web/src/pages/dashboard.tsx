import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Box,
  ColumnLayout,
  Container,
  ContentLayout,
  Header,
  Link,
  SpaceBetween,
} from "@cloudscape-design/components";

import { fetchCertificates, type CertificateStatus } from "@/lib/ca";

function Stat({
  label,
  value,
  sub,
}: {
  label: string;
  value: string;
  sub: string;
}) {
  return (
    <Container>
      <SpaceBetween size="xxs">
        <Box variant="awsui-key-label">{label}</Box>
        <Box fontSize="display-l" fontWeight="bold">
          {value}
        </Box>
        <Box color="text-status-inactive" fontSize="body-s">
          {sub}
        </Box>
      </SpaceBetween>
    </Container>
  );
}

const QUICK_ACTIONS = [
  { to: "/certificates", label: "Certificates" },
  { to: "/approvals", label: "Review approvals" },
  { to: "/audit", label: "View audit logs" },
  { to: "/scms", label: "Manage tokens" },
];

export function DashboardPage() {
  const navigate = useNavigate();
  // No dedicated stats endpoint yet: derive headline counts from the real
  // certificate inventory. Pending/expiring are left at 0 (no backing endpoint).
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dashboard-certs"],
    queryFn: () => fetchCertificates("page=1&pageSize=1000"),
  });

  const count = (status: CertificateStatus) =>
    data?.certificates.filter((c) => c.status === status).length ?? 0;
  const fmt = (n: number) =>
    isLoading ? "…" : isError ? "—" : n.toLocaleString();

  const follow = (e: CustomEvent<{ href?: string; external?: boolean }>) => {
    if (e.detail.href && !e.detail.external) {
      e.preventDefault();
      navigate(e.detail.href);
    }
  };

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Overview of the certificate inventory.">
          Dashboard
        </Header>
      }
    >
      <SpaceBetween size="l">
        <ColumnLayout columns={4}>
          <Stat label="Active certificates" value={fmt(count("active"))} sub="Currently valid" />
          <Stat label="Pending approvals" value={fmt(0)} sub="No backing endpoint yet" />
          <Stat label="Expiring soon" value={fmt(0)} sub="Within 30 days" />
          <Stat label="Revoked certificates" value={fmt(count("revoked"))} sub="Total revoked" />
        </ColumnLayout>

        <ColumnLayout columns={2}>
          <Container header={<Header variant="h2">Quick actions</Header>}>
            <SpaceBetween size="s">
              {QUICK_ACTIONS.map((a) => (
                <Link key={a.to} href={a.to} onFollow={follow}>
                  {a.label}
                </Link>
              ))}
            </SpaceBetween>
          </Container>
          <Container
            header={
              <Header
                variant="h2"
                actions={
                  <Link href="/audit" onFollow={follow}>
                    View all
                  </Link>
                }
              >
                Recent activity
              </Header>
            }
          >
            <Box color="text-status-inactive">No recent activity to show.</Box>
          </Container>
        </ColumnLayout>
      </SpaceBetween>
    </ContentLayout>
  );
}
