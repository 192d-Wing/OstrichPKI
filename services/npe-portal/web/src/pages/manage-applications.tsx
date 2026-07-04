import { useQuery } from "@tanstack/react-query";
import {
  Alert,
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

export function ManageApplicationsPage() {
  const navigate = useNavigate();
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["approval-queue"],
    queryFn: portalApi.listApprovalQueue,
  });

  const items = data?.requests ?? [];

  function openDetail(id: string) {
    navigate(`/ra/applications/view?id=${encodeURIComponent(id)}`);
  }

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Pending certificate applications awaiting Registration Authority review. Open a request to approve, override, or reject it."
          actions={
            <Button iconName="refresh" loading={isFetching} onClick={() => refetch()}>
              Refresh
            </Button>
          }
        >
          Manage Certificate Applications
        </Header>
      }
    >
      <SpaceBetween size="l">
        {isError && (
          <Alert type="error" header="Could not load the approval queue">
            {error?.message ?? "Request failed."} Use Refresh to retry.
          </Alert>
        )}
        <Table<ApplicationInfo>
          loading={isLoading}
          items={items}
          variant="container"
          wrapLines
          columnDefinitions={[
            {
              id: "id",
              header: "Request ID",
              cell: (i) => <Link onFollow={() => openDetail(i.id)}>{i.id}</Link>,
            },
            { id: "type", header: "Type", cell: (i) => i.request_type },
            { id: "requestor", header: "Requestor", cell: (i) => i.requestor_username },
            { id: "status", header: "Status", cell: (i) => <StatusBadge status={i.status} /> },
            { id: "created", header: "Submitted", cell: (i) => i.created_at },
            {
              id: "actions",
              header: "Actions",
              cell: (i) => <Button onClick={() => openDetail(i.id)}>Review</Button>,
            },
          ]}
          empty={
            <Box textAlign="center" color="inherit">
              <SpaceBetween size="xs">
                <b>Queue is empty</b>
                <span>There are no pending applications to review.</span>
              </SpaceBetween>
            </Box>
          }
        />
      </SpaceBetween>
    </ContentLayout>
  );
}
