import * as React from "react";
import {
  type ColumnDef,
  type ColumnFiltersState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  useReactTable,
} from "@tanstack/react-table";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

/** A per-column filter rendered in the toolbar above the table. */
export interface DataTableFilter {
  columnId: string;
  placeholder: string;
  /** "text" = case-insensitive substring; "select" = exact match. */
  kind?: "text" | "select";
  /** Options for a "select" filter (a leading "All" is added automatically). */
  options?: { value: string; label: string }[];
}

export interface DataTableProps<T> {
  columns: ColumnDef<T, unknown>[];
  data: T[];
  filters?: DataTableFilter[];
  pageSize?: number;
  isLoading?: boolean;
  isError?: boolean;
  errorMessage?: string;
  emptyMessage?: string;
  noMatchMessage?: string;
}

/**
 * Generic filter + paginate table built on TanStack Table. Filtering and
 * pagination are client-side (intended for already-loaded, bounded lists).
 * Reused across pages so per-column filtering/pagination/empty-states stay
 * consistent and aren't re-implemented per table.
 */
export function DataTable<T>({
  columns,
  data,
  filters = [],
  pageSize = 10,
  isLoading = false,
  isError = false,
  errorMessage = "Failed to load data.",
  emptyMessage = "No records.",
  noMatchMessage = "No records match the current filters.",
}: DataTableProps<T>) {
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>(
    [],
  );

  const table = useReactTable({
    data,
    columns,
    state: { columnFilters },
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize } },
  });

  const colCount = table.getAllColumns().length;
  const filterValue = (id: string) =>
    (table.getColumn(id)?.getFilterValue() as string) ?? "";

  return (
    <div className="space-y-3">
      {filters.length > 0 && (
        <div
          className="grid gap-2"
          style={{
            gridTemplateColumns: `repeat(${Math.min(filters.length, 4)}, minmax(0, 1fr))`,
          }}
        >
          {filters.map((f) =>
            f.kind === "select" ? (
              <Select
                key={f.columnId}
                value={filterValue(f.columnId) || "all"}
                onValueChange={(v) =>
                  table
                    .getColumn(f.columnId)
                    ?.setFilterValue(v === "all" ? undefined : v)
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder={f.placeholder} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{f.placeholder}</SelectItem>
                  {(f.options ?? []).map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <Input
                key={f.columnId}
                placeholder={f.placeholder}
                value={filterValue(f.columnId)}
                onChange={(e) =>
                  table.getColumn(f.columnId)?.setFilterValue(e.target.value)
                }
              />
            ),
          )}
        </div>
      )}

      <div className="rounded-md border bg-card">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id}>
                {hg.headers.map((h) => (
                  <TableHead key={h.id}>
                    {h.isPlaceholder
                      ? null
                      : flexRender(h.column.columnDef.header, h.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={colCount} className="text-center text-muted-foreground">
                  Loading…
                </TableCell>
              </TableRow>
            ) : isError ? (
              <TableRow>
                <TableCell colSpan={colCount} className="text-center text-destructive">
                  {errorMessage}
                </TableCell>
              </TableRow>
            ) : table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={colCount} className="text-center text-muted-foreground">
                  {data.length === 0 ? emptyMessage : noMatchMessage}
                </TableCell>
              </TableRow>
            ) : (
              table.getRowModel().rows.map((row) => (
                <TableRow key={row.id}>
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {table.getFilteredRowModel().rows.length} result(s)
        </p>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
          >
            Previous
          </Button>
          <span className="text-sm text-muted-foreground">
            Page {table.getState().pagination.pageIndex + 1} of{" "}
            {Math.max(1, table.getPageCount())}
          </span>
          <Button
            variant="outline"
            size="sm"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  );
}
