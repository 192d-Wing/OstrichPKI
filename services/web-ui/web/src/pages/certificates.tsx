import * as React from "react";
import { type ColumnDef, type ColumnFiltersState } from "@tanstack/react-table";
import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { useAuth } from "@/lib/auth-context";

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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ApiError } from "@/lib/api";
import {
  fetchCertificates,
  REVOCATION_REASONS,
  revokeCertificate,
  type CertificateStatus,
  type CertificateSummary,
  type RevocationReason,
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
  const qc = useQueryClient();
  const { can } = useAuth();
  const [pageIndex, setPageIndex] = React.useState(0);
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>(
    [],
  );

  // Revoke dialog state.
  const [target, setTarget] = React.useState<CertificateSummary | null>(null);
  const [reason, setReason] = React.useState<RevocationReason>("Unspecified");
  const [notes, setNotes] = React.useState("");
  const [revokeError, setRevokeError] = React.useState<string | null>(null);

  const closeDialog = () => {
    setTarget(null);
    setRevokeError(null);
  };

  const revoke = useMutation({
    mutationFn: () => revokeCertificate(target!.id, reason, notes),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["certificates"] });
      closeDialog();
    },
    onError: (e) =>
      setRevokeError(e instanceof ApiError ? e.message : "Failed to revoke"),
  });

  function openRevoke(cert: CertificateSummary) {
    setTarget(cert);
    setReason("Unspecified");
    setNotes("");
    setRevokeError(null);
  }

  const status = columnFilters.find((f) => f.id === "status")?.value as
    | string
    | undefined;
  const search = (
    columnFilters.find((f) => f.id === "subject")?.value as string | undefined
  )?.trim();

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
    {
      id: "actions",
      header: "",
      cell: ({ row }) => (
        <div className="flex justify-end gap-1">
          <Button asChild variant="ghost" size="sm" className="h-auto p-1">
            <Link to={`/certificates/${row.original.id}`}>View</Link>
          </Button>
          {row.original.status === "active" && (
            <Button
              variant="ghost"
              size="sm"
              className="h-auto p-1 text-destructive hover:text-destructive"
              onClick={() => openRevoke(row.original)}
            >
              Revoke
            </Button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <PageHeader
        title="Certificates"
        description="Issued certificate inventory."
        actions={
          can("issue_certificates") ? (
            <Button asChild>
              <Link to="/certificates/issue">Issue certificate</Link>
            </Button>
          ) : undefined
        }
      />

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
                setPageIndex(0);
              },
            }}
          />
        </CardContent>
      </Card>

      <Dialog open={!!target} onOpenChange={(o) => !o && closeDialog()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke certificate</DialogTitle>
            <DialogDescription>
              {target ? (
                <>
                  This permanently revokes{" "}
                  <span className="font-medium">{target.subject}</span> (serial{" "}
                  <span className="font-mono">{target.serialNumber}</span>). It
                  will appear on the next CRL/OCSP response.
                </>
              ) : null}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label>Reason</Label>
              <Select
                value={reason}
                onValueChange={(v) => setReason(v as RevocationReason)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {REVOCATION_REASONS.map((r) => (
                    <SelectItem key={r.value} value={r.value}>
                      {r.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="notes">Notes (optional)</Label>
              <Textarea
                id="notes"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Context for the audit record…"
              />
            </div>
            {revokeError && (
              <div className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {revokeError}
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={closeDialog} disabled={revoke.isPending}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => revoke.mutate()}
              disabled={revoke.isPending}
            >
              {revoke.isPending ? "Revoking…" : "Revoke certificate"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
