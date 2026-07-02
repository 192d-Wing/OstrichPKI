import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Container,
  ContentLayout,
  Header,
  Input,
  KeyValuePairs,
  SpaceBetween,
  Table,
} from "@cloudscape-design/components";

import { StatusBadge } from "@/components/status-badge";
import { portalApi, type ApplicationDetail } from "@/lib/portal-api";

export function ApplicationStatusPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [id, setId] = useState(params.get("id") ?? "");
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: (requestId: string) => portalApi.getApplication(requestId),
    onSuccess: () => setError(null),
    onError: (e: Error) => setError(e.message),
  });

  function lookup() {
    const trimmed = id.trim();
    if (!trimmed) {
      setError("Enter a Request ID.");
      return;
    }
    mutation.mutate(trimmed);
  }

  const detail = mutation.data as ApplicationDetail | undefined;

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Look up a single application by Request ID.">
          View Certificate Application Status
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container>
          <SpaceBetween direction="horizontal" size="xs">
            <Input
              value={id}
              onChange={(e) => setId(e.detail.value)}
              placeholder="Request ID (UUID)"
            />
            <Button variant="primary" onClick={lookup} loading={mutation.isPending}>
              Look up
            </Button>
          </SpaceBetween>
        </Container>

        {error && (
          <Alert type="error" header="Lookup failed">
            {error}
          </Alert>
        )}

        {detail && (
          <Container
            header={
              <Header
                variant="h2"
                actions={
                  detail.request.certificate_id ? (
                    <Button
                      variant="primary"
                      iconName="download"
                      onClick={() =>
                        navigate(
                          `/certificates/view?id=${encodeURIComponent(detail.request.certificate_id!)}`,
                        )
                      }
                    >
                      View / download certificate
                    </Button>
                  ) : undefined
                }
              >
                Application {detail.request.id}
              </Header>
            }
          >
            <SpaceBetween size="l">
              <KeyValuePairs
                columns={3}
                items={[
                  { label: "Status", value: <StatusBadge status={detail.request.status} /> },
                  { label: "Type", value: detail.request.request_type },
                  { label: "Requestor", value: detail.request.requestor_username },
                  { label: "Submitted", value: detail.request.created_at },
                  { label: "Expires", value: detail.request.expires_at },
                ]}
              />
              <Table
                header={<Header variant="h3">Review decisions</Header>}
                items={detail.decisions}
                variant="embedded"
                columnDefinitions={[
                  { id: "approver", header: "Approver", cell: (d) => d.approver_username },
                  { id: "decision", header: "Decision", cell: (d) => d.decision },
                  { id: "reason", header: "Reason", cell: (d) => d.reason ?? "-" },
                  { id: "at", header: "Decided", cell: (d) => d.decided_at },
                ]}
                empty="No decisions yet"
              />
            </SpaceBetween>
          </Container>
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}
