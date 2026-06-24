import * as React from "react";
import { type ColumnDef, type ColumnFiltersState } from "@tanstack/react-table";
import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import { ShieldCheck, ShieldX } from "lucide-react";

import { DataTable, type DataTableFilter } from "@/components/data-table";
import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  AUDIT_EVENT_TYPES,
  fetchAuditLogs,
  verifyAudit,
  type AuditEvent,
} from "@/lib/audit";

const PAGE_SIZE = 25;

function outcomeBadge(outcome: string) {
  const ok = outcome.toLowerCase() === "success";
  return (
    <Badge variant={ok ? "success" : "destructive"}>{outcome || "—"}</Badge>
  );
}

const columns: ColumnDef<AuditEvent>[] = [
  {
    accessorKey: "timestamp",
    header: "Timestamp",
    cell: ({ row }) => (
      <span className="font-mono text-xs text-muted-foreground">
        {row.original.timestamp}
      </span>
    ),
  },
  {
    accessorKey: "eventType",
    header: "Event",
    cell: ({ row }) => (
      <span className="font-mono text-xs">{row.original.eventType}</span>
    ),
  },
  { accessorKey: "actor", header: "Actor" },
  {
    accessorKey: "target",
    header: "Target",
    cell: ({ row }) => (
      <span className="text-muted-foreground">{row.original.target}</span>
    ),
  },
  { accessorKey: "action", header: "Action" },
  {
    accessorKey: "outcome",
    header: "Outcome",
    cell: ({ row }) => outcomeBadge(row.original.outcome),
  },
  {
    id: "signed",
    header: "Signed",
    cell: ({ row }) =>
      row.original.signed ? (
        <Badge variant="secondary">signed</Badge>
      ) : (
        <span className="text-xs text-muted-foreground">—</span>
      ),
  },
];

const filters: DataTableFilter[] = [
  {
    columnId: "eventType",
    placeholder: "All events",
    kind: "select",
    options: AUDIT_EVENT_TYPES,
  },
  { columnId: "actor", placeholder: "Filter actor…" },
  {
    columnId: "outcome",
    placeholder: "Any outcome",
    kind: "select",
    options: [
      { value: "success", label: "Success" },
      { value: "failure", label: "Failure" },
    ],
  },
];

function IntegrityCheck() {
  const verify = useMutation({ mutationFn: verifyAudit });
  const r = verify.data;
  return (
    <div className="flex items-center gap-3">
      {r &&
        (r.intact ? (
          <span className="flex items-center gap-1 text-sm text-green-600 dark:text-green-400">
            <ShieldCheck className="size-4" /> Intact — {r.signedRecords}/
            {r.totalRecords} signed
          </span>
        ) : (
          <span className="flex items-center gap-1 text-sm text-destructive">
            <ShieldX className="size-4" /> Integrity check failed
          </span>
        ))}
      {verify.isError && (
        <span className="text-sm text-destructive">Verification failed</span>
      )}
      <Button
        variant="outline"
        size="sm"
        onClick={() => verify.mutate()}
        disabled={verify.isPending}
      >
        {verify.isPending ? "Verifying…" : "Verify integrity"}
      </Button>
    </div>
  );
}

export function AuditPage() {
  const [pageIndex, setPageIndex] = React.useState(0);
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>(
    [],
  );

  const val = (id: string) =>
    (columnFilters.find((f) => f.id === id)?.value as string | undefined)?.trim();
  const eventType = val("eventType");
  const actor = val("actor");
  const outcome = val("outcome");

  const query = new URLSearchParams();
  query.set("page", String(pageIndex + 1));
  query.set("pageSize", String(PAGE_SIZE));
  if (eventType) query.set("eventType", eventType);
  if (actor) query.set("actor", actor);
  if (outcome) query.set("outcome", outcome);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["audit", pageIndex, eventType ?? "", actor ?? "", outcome ?? ""],
    queryFn: () => fetchAuditLogs(query.toString()),
    placeholderData: keepPreviousData,
  });

  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <PageHeader
        title="Audit Logs"
        description="Security-relevant events (append-only, hash-chained)."
        actions={<IntegrityCheck />}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Events</CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={data?.events ?? []}
            filters={filters}
            isLoading={isLoading}
            isError={isError}
            emptyMessage="No audit events recorded yet."
            noMatchMessage="No events match the current filters."
            errorMessage="Failed to load the audit log. Retry or check your session."
            manual={{
              pageCount,
              pageIndex,
              pageSize: PAGE_SIZE,
              total,
              onPageChange: setPageIndex,
              columnFilters,
              onColumnFiltersChange: (next) => {
                setColumnFilters(next);
                setPageIndex(0);
              },
            }}
          />
        </CardContent>
      </Card>
    </div>
  );
}
