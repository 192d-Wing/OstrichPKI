import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Container,
  ContentLayout,
  Form,
  FormField,
  Header,
  SpaceBetween,
  Table,
  Textarea,
} from "@cloudscape-design/components";

import { StatusBadge } from "@/components/status-badge";
import { portalApi, type ApplicationInfo } from "@/lib/portal-api";

const MAX_IDS = 100;

export function BulkStatusPage() {
  const [raw, setRaw] = useState("");
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: (ids: string[]) => portalApi.bulkStatus(ids),
    onSuccess: () => setError(null),
    onError: (e: Error) => setError(e.message),
  });

  function lookup() {
    const ids = raw
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (ids.length === 0) {
      setError("Enter one or more Request IDs (comma- or newline-separated).");
      return;
    }
    if (ids.length > MAX_IDS) {
      setError(`Too many IDs (max ${MAX_IDS}).`);
      return;
    }
    mutation.mutate(ids);
  }

  const items = (mutation.data?.requests ?? []) as ApplicationInfo[];

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Check the status of many applications at once.">
          View Bulk Status
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container>
          <Form
            actions={
              <Button variant="primary" onClick={lookup} loading={mutation.isPending}>
                Look up
              </Button>
            }
          >
            <FormField
              label="Request IDs"
              description={`Up to ${MAX_IDS} IDs, separated by commas, spaces, or newlines.`}
            >
              <Textarea value={raw} onChange={(e) => setRaw(e.detail.value)} rows={6} />
            </FormField>
          </Form>
        </Container>

        {error && (
          <Alert type="error" header="Lookup failed">
            {error}
          </Alert>
        )}

        {mutation.data && (
          <Table<ApplicationInfo>
            header={<Header variant="h2" counter={`(${items.length})`}>Results</Header>}
            items={items}
            variant="container"
            wrapLines
            columnDefinitions={[
              { id: "id", header: "Request ID", cell: (i) => i.id },
              { id: "type", header: "Type", cell: (i) => i.request_type },
              { id: "status", header: "Status", cell: (i) => <StatusBadge status={i.status} /> },
              { id: "created", header: "Submitted", cell: (i) => i.created_at },
            ]}
            empty={
              <Box textAlign="center">No applications found for those IDs (or not yours to view).</Box>
            }
          />
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}
