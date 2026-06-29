import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Container,
  ContentLayout,
  CopyToClipboard,
  FileUpload,
  Form,
  FormField,
  Header,
  KeyValuePairs,
  Select,
  type SelectProps,
  SpaceBetween,
  Table,
} from "@cloudscape-design/components";

import { StatusBadge } from "@/components/status-badge";
import { downloadText } from "@/lib/download";
import { portalApi, type BulkItem } from "@/lib/portal-api";

// Bulk enrollment applies one profile to every CSR in the ZIP. EFS is excluded
// (it is server-side keygen, not a CSR submission).
const PROFILES: SelectProps.Option[] = [
  { label: "TLS Client", value: "tls_client" },
  { label: "TLS Server", value: "tls_server" },
  { label: "TLS Server + Client", value: "tls_server_client" },
];

// Build a CSV result sheet (Bulk Identifier header + per-CSR rows) for download.
function resultCsv(bulkIdentifier: string, items: BulkItem[]): string {
  // RFC-4180 quoting + spreadsheet formula-injection neutralization: cells embed
  // attacker-influenced data (ZIP file names, CSR parse errors), and a cell that
  // begins with =,+,-,@ executes as a formula in Excel/Sheets even when quoted.
  // Prefix those with an apostrophe so they render as literal text.
  const esc = (v: string) => {
    const safe = /^[=+\-@]/.test(v) ? `'${v}` : v;
    // Global regex replace (equivalent to replaceAll; replaceAll needs es2021,
    // which is newer than this project's tsconfig lib target).
    return `"${safe.replace(/"/g, '""')}"`;
  };
  const rows = [
    `Bulk Identifier,${esc(bulkIdentifier)}`,
    "",
    "Index,Source,Subject CN,Status,Request ID,Error",
    ...items.map((i) =>
      [
        i.itemIndex,
        esc(i.sourceName),
        esc(i.subjectCn ?? ""),
        esc(i.status),
        esc(i.requestId ?? ""),
        esc(i.error ?? ""),
      ].join(","),
    ),
  ];
  return rows.join("\n");
}

export function SubmitBulkPage() {
  const [profile, setProfile] = useState<SelectProps.Option>(PROFILES[0]);
  const [files, setFiles] = useState<File[]>([]);
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => portalApi.bulkEnroll(String(profile.value), files[0]),
    onSuccess: () => setError(null),
    onError: (e: Error) => setError(e.message),
  });

  const file = files[0];
  const canSubmit = !!file && !mutation.isPending;

  function onSubmit() {
    if (!file) {
      setError("Choose a .zip of CSRs to upload.");
      return;
    }
    setError(null);
    mutation.mutate();
  }

  const result = mutation.data;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Upload a ZIP of PKCS #10 CSRs to enroll as a batch under a single profile."
        >
          Submit Bulk Enrollment
        </Header>
      }
    >
      <SpaceBetween size="l">
        {error && (
          <Alert type="error" dismissible onDismiss={() => setError(null)} header="Upload failed">
            {error}
          </Alert>
        )}

        {result && (
          <Container
            header={
              <Header
                variant="h2"
                actions={
                  <Button
                    iconName="download"
                    onClick={() =>
                      downloadText(
                        resultCsv(result.job.bulkIdentifier, result.items),
                        `${result.job.bulkIdentifier}-result.csv`,
                        "text/csv",
                      )
                    }
                  >
                    Download result sheet
                  </Button>
                }
              >
                Result
              </Header>
            }
          >
            <SpaceBetween size="l">
              <KeyValuePairs
                columns={4}
                items={[
                  {
                    label: "Bulk Identifier",
                    value: (
                      <Box>
                        <Box variant="code" display="inline">
                          {result.job.bulkIdentifier}
                        </Box>{" "}
                        <CopyToClipboard
                          copyButtonText="Copy"
                          copyErrorText="Failed to copy"
                          copySuccessText="Copied"
                          textToCopy={result.job.bulkIdentifier}
                          variant="inline"
                        />
                      </Box>
                    ),
                  },
                  { label: "Total", value: String(result.job.totalCount) },
                  { label: "Queued", value: String(result.job.succeededCount) },
                  { label: "Failed", value: String(result.job.failedCount) },
                ]}
              />
              <Table<BulkItem>
                items={result.items}
                variant="embedded"
                wrapLines
                columnDefinitions={[
                  { id: "index", header: "#", cell: (i) => i.itemIndex },
                  { id: "source", header: "Source", cell: (i) => i.sourceName },
                  { id: "cn", header: "Subject CN", cell: (i) => i.subjectCn ?? "-" },
                  { id: "status", header: "Status", cell: (i) => <StatusBadge status={i.status} /> },
                  { id: "error", header: "Detail", cell: (i) => i.error ?? "-" },
                ]}
                empty="No certificate requests found in the archive"
              />
            </SpaceBetween>
          </Container>
        )}

        <Container>
          <Form
            actions={
              <Button variant="primary" onClick={onSubmit} loading={mutation.isPending} disabled={!canSubmit}>
                Submit batch
              </Button>
            }
          >
            <SpaceBetween size="l">
              <FormField label="Certificate profile" description="Applied to every CSR in the batch.">
                <Select
                  selectedOption={profile}
                  onChange={(e) => {
                    if (mutation.data || mutation.isError) mutation.reset();
                    setProfile(e.detail.selectedOption);
                  }}
                  options={PROFILES}
                />
              </FormField>
              <FormField
                label="CSR archive (.zip)"
                description="A ZIP of up to 100 PKCS #10 CSR files (.csr/.pem)."
              >
                <FileUpload
                  value={files}
                  onChange={(e) => {
                    if (mutation.data || mutation.isError) mutation.reset();
                    setError(null);
                    setFiles(e.detail.value);
                  }}
                  accept=".zip,application/zip"
                  showFileLastModified
                  showFileSize
                  constraintText="Up to 100 CSRs, 8 MiB max."
                  i18nStrings={{
                    uploadButtonText: () => "Choose ZIP",
                    removeFileAriaLabel: (idx) => `Remove file ${idx + 1}`,
                    dropzoneText: () => "Drop a .zip here or choose a file",
                    limitShowFewer: "Show fewer",
                    limitShowMore: "Show more",
                    errorIconAriaLabel: "Error",
                  }}
                />
              </FormField>
            </SpaceBetween>
          </Form>
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
