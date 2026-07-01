// Reusable table-export helpers (CSV + PDF) for portal list/search views.
// CSV is dependency-free; PDF lazily imports jsPDF so it stays out of the main
// bundle and only loads when a user actually exports a PDF.

import { downloadText } from "@/lib/download";

export interface ExportColumn<T> {
  header: string;
  /** Extract the cell's plain-text value for a row. */
  value: (row: T) => string;
}

function csvCell(s: string): string {
  return `"${s.replace(/"/g, '""')}"`;
}

/** Download `rows` as a CSV file (UTF-8 with BOM so Excel reads it correctly). */
export function exportCsv<T>(filename: string, columns: ExportColumn<T>[], rows: T[]): void {
  const head = columns.map((c) => csvCell(c.header)).join(",");
  const body = rows.map((r) => columns.map((c) => csvCell(c.value(r) ?? "")).join(","));
  downloadText(`﻿${[head, ...body].join("\r\n")}\r\n`, filename, "text/csv;charset=utf-8");
}

/** Download `rows` as a landscape PDF table. Lazily loads jsPDF (+ autotable). */
export async function exportPdf<T>(
  filename: string,
  title: string,
  columns: ExportColumn<T>[],
  rows: T[],
): Promise<void> {
  const { jsPDF } = await import("jspdf");
  const { default: autoTable } = await import("jspdf-autotable");
  const doc = new jsPDF({ orientation: "landscape" });
  doc.setFontSize(14);
  doc.text(title, 14, 16);
  doc.setFontSize(9);
  doc.text(`Generated ${new Date().toISOString().slice(0, 19)}Z · ${rows.length} row(s)`, 14, 22);
  autoTable(doc, {
    startY: 26,
    head: [columns.map((c) => c.header)],
    body: rows.map((r) => columns.map((c) => c.value(r) ?? "")),
    styles: { fontSize: 8, cellPadding: 2, overflow: "linebreak" },
    headStyles: { fillColor: [35, 47, 62] },
  });
  doc.save(filename);
}
