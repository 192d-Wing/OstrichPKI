import * as React from "react";
import { type ColumnDef, type ColumnFiltersState } from "@tanstack/react-table";
import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { DataTable, type DataTableFilter } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  fetchCertificates,
  type CertificateStatus,
  type CertificateSummary,
} from "@/lib/ca";

const PAGE_SIZE = 20;

function certStatusBadge(status: CertificateStatus) {
  switch (status) {
    case "active":
      return <Badge variant="success">active</Badge>;
    case "revoked":
      return <Badge variant="destructive">revoked</Badge>;
    case "expired":
      return <Badge variant="warning">expired</Badge>;
    default:
      return <Badge variant="secondary">pending</Badge>;
  }
}

const columns: ColumnDef<CertificateSummary>[] = [
  {
    accessorKey: "serialNumber",
    header: "Serial",
    cell: ({ row }) => (
      <span className="font-mono text-xs">{row.original.serialNumber}</span>
    ),
  },
  { accessorKey: "subject", header: "Subject" },
  {
    accessorKey: "issuer",
    header: "Issuer",
    cell: ({ row }) => (
      <span className="text-muted-foreground">{row.original.issuer}</span>
    ),
  },
  {
    accessorKey: "validTo",
    header: "Expires",
    cell: ({ row }) => (
      <span className="font-mono text-xs text-muted-foreground">
        {row.original.validTo}
      </span>
    ),
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => certStatusBadge(row.original.status),
  },
];

const filters: DataTableFilter[] = [
  { columnId: "subject", placeholder: "Search subject…" },
  {
    columnId: "status",
    placeholder: "All statuses",
    kind: "select",
    options: [
      { value: "active", label: "active" },
      { value: "revoked", label: "revoked" },
      { value: "expired", label: "expired" },
      { value: "pending", label: "pending" },
    ],
  },
];

export function CertificatesPage() {
  const [pageIndex, setPageIndex] = React.useState(0);
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>(
    [],
  );

  const status = columnFilters.find((f) => f.id === "status")?.value as
    | string
    | undefined;
  const search = (
    columnFilters.find((f) => f.id === "subject")?.value as string | undefined
  )?.trim();

  // Server-side query (CA paginates + filters). page is 1-based server-side.
  const query = new URLSearchParams();
  query.set("page", String(pageIndex + 1));
  query.set("pageSize", String(PAGE_SIZE));
  if (status) query.set("status", status);
  if (search) query.set("search", search);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["certificates", pageIndex, status ?? "", search ?? ""],
    queryFn: () => fetchCertificates(query.toString()),
    placeholderData: keepPreviousData,
  });

  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Certificates</h1>
        <p className="text-sm text-muted-foreground">
          Issued certificate inventory.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">All certificates</CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={data?.certificates ?? []}
            filters={filters}
            isLoading={isLoading}
            isError={isError}
            emptyMessage="No certificates issued yet."
            noMatchMessage="No certificates match the current filters."
            errorMessage="Failed to load certificates. Retry or check your session."
            manual={{
              pageCount,
              pageIndex,
              pageSize: PAGE_SIZE,
              total,
              onPageChange: setPageIndex,
              columnFilters,
              onColumnFiltersChange: (next) => {
                setColumnFilters(next);
                setPageIndex(0); // filter change resets to the first page
              },
            }}
          />
        </CardContent>
      </Card>
    </div>
  );
}
