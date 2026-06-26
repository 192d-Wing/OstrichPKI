import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Box,
  ContentLayout,
  Header,
  Link,
  Table,
  TextFilter,
} from "@cloudscape-design/components";
import { useNavigate } from "react-router-dom";

import { StatusBadge } from "@/components/status-badge";
import { portalApi, type ApplicationInfo } from "@/lib/portal-api";

export function SearchPage() {
  const navigate = useNavigate();
  const [filter, setFilter] = useState("");
  const { data, isLoading } = useQuery({
    queryKey: ["my-applications"],
    queryFn: portalApi.listMyApplications,
  });

  // Client-side search over the caller's own applications. The text filter only
  // applies once it is at least 3 characters (per the portal grid behaviour).
  const items = useMemo(() => {
    const all = data?.requests ?? [];
    const q = filter.trim().toLowerCase();
    if (q.length < 3) return all;
    return all.filter((a) =>
      [a.id, a.request_type, a.status, a.requestor_username]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }, [data, filter]);

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Search your certificate applications.">
          Search
        </Header>
      }
    >
      <Table<ApplicationInfo>
        loading={isLoading}
        items={items}
        variant="container"
        wrapLines
        filter={
          <TextFilter
            filteringText={filter}
            filteringPlaceholder="Search (min. 3 characters)"
            onChange={(e) => setFilter(e.detail.filteringText)}
          />
        }
        columnDefinitions={[
          {
            id: "id",
            header: "Request ID",
            cell: (i) => <Link onFollow={() => navigate(`/certificates/status?id=${i.id}`)}>{i.id}</Link>,
          },
          { id: "type", header: "Type", cell: (i) => i.request_type },
          { id: "status", header: "Status", cell: (i) => <StatusBadge status={i.status} /> },
          { id: "created", header: "Submitted", cell: (i) => i.created_at },
        ]}
        empty={<Box textAlign="center">No matching applications.</Box>}
      />
    </ContentLayout>
  );
}
