import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Box,
  ButtonDropdown,
  ContentLayout,
  Header,
  Link,
  Table,
  TextFilter,
} from "@cloudscape-design/components";
import { useNavigate } from "react-router-dom";

import { StatusBadge } from "@/components/status-badge";
import { exportCsv, exportPdf, type ExportColumn } from "@/lib/export";
import { portalApi, type ApplicationInfo } from "@/lib/portal-api";

// Columns for CSV/PDF export (plain-text values, independent of the table cells).
const EXPORT_COLUMNS: ExportColumn<ApplicationInfo>[] = [
  { header: "Request ID", value: (i) => i.id },
  { header: "Type", value: (i) => i.request_type },
  { header: "Status", value: (i) => i.status },
  { header: "Requestor", value: (i) => i.requestor_username },
  { header: "Submitted", value: (i) => i.created_at },
];

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

  const stamp = new Date().toISOString().slice(0, 10);
  function onExport(id: string) {
    if (items.length === 0) return;
    if (id === "csv") {
      exportCsv(`applications-${stamp}.csv`, EXPORT_COLUMNS, items);
    } else if (id === "pdf") {
      void exportPdf(`applications-${stamp}.pdf`, "Certificate Applications", EXPORT_COLUMNS, items);
    }
  }

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Search your certificate applications."
          counter={`(${items.length})`}
          actions={
            <ButtonDropdown
              disabled={items.length === 0}
              items={[
                { id: "csv", text: "Export as CSV" },
                { id: "pdf", text: "Export as PDF" },
              ]}
              onItemClick={({ detail }) => onExport(detail.id)}
            >
              Export
            </ButtonDropdown>
          }
        >
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
