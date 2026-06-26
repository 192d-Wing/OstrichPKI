import { useQuery } from "@tanstack/react-query";
import {
  Box,
  Button,
  ContentLayout,
  Header,
  Link,
  SpaceBetween,
  Table,
} from "@cloudscape-design/components";
import { useNavigate } from "react-router-dom";

import { StatusBadge } from "@/components/status-badge";
import { portalApi, type ApplicationInfo } from "@/lib/portal-api";

export function MyApplicationsPage() {
  const navigate = useNavigate();
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["my-applications"],
    queryFn: portalApi.listMyApplications,
  });

  const items = data?.requests ?? [];

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Certificate applications you have submitted."
          actions={
            <Button iconName="refresh" loading={isFetching} onClick={() => refetch()}>
              Refresh
            </Button>
          }
        >
          View My Certificate Applications
        </Header>
      }
    >
      <Table<ApplicationInfo>
        loading={isLoading}
        items={items}
        variant="container"
        wrapLines
        columnDefinitions={[
          {
            id: "id",
            header: "Request ID",
            cell: (i) => <Link onFollow={() => navigate(`/certificates/status?id=${i.id}`)}>{i.id}</Link>,
          },
          { id: "type", header: "Type", cell: (i) => i.request_type },
          { id: "status", header: "Status", cell: (i) => <StatusBadge status={i.status} /> },
          { id: "created", header: "Submitted", cell: (i) => i.created_at },
          { id: "expires", header: "Expires", cell: (i) => i.expires_at },
        ]}
        empty={
          <Box textAlign="center" color="inherit">
            <SpaceBetween size="xs">
              <b>No applications</b>
              <span>Submit a certificate application to see it here.</span>
            </SpaceBetween>
          </Box>
        }
      />
    </ContentLayout>
  );
}
