import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Container,
  ContentLayout,
  FormField,
  Header,
  Input,
  KeyValuePairs,
  Link,
  Modal,
  SpaceBetween,
  StatusIndicator,
  Table,
} from "@cloudscape-design/components";

import { ApiError } from "@/lib/api";
import type { CertificateStatus, CertificateSummary } from "@/lib/ca";
import { fetchFqdnRecord, setFqdnNotification } from "@/lib/fqdn";
import { useAuth } from "@/lib/auth-context";

function statusIndicator(status: CertificateStatus) {
  switch (status) {
    case "active":
      return <StatusIndicator type="success">active</StatusIndicator>;
    case "revoked":
      return <StatusIndicator type="error">revoked</StatusIndicator>;
    case "expired":
      return <StatusIndicator type="warning">expired</StatusIndicator>;
    default:
      return <StatusIndicator type="pending">pending</StatusIndicator>;
  }
}

export function FqdnDetailPage() {
  const { fqdn = "" } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { can } = useAuth();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["fqdn", fqdn],
    queryFn: () => fetchFqdnRecord(fqdn),
  });

  // Renewal-contact edit modal.
  const [editing, setEditing] = React.useState(false);
  const [email, setEmail] = React.useState("");
  const [saveError, setSaveError] = React.useState<string | null>(null);
  const openEdit = () => {
    setEmail(data?.notificationEmail ?? "");
    setSaveError(null);
    setEditing(true);
  };
  const save = useMutation({
    mutationFn: () => setFqdnNotification(fqdn, email.trim()),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["fqdn", fqdn] });
      setEditing(false);
    },
    onError: (e) =>
      setSaveError(e instanceof ApiError ? e.message : "Failed to save contact"),
  });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          actions={<Button onClick={() => navigate("/fqdns")}>Back to list</Button>}
        >
          {fqdn}
        </Header>
      }
    >
      {isLoading ? (
        <StatusIndicator type="loading">Loading</StatusIndicator>
      ) : isError || !data ? (
        <StatusIndicator type="error">Failed to load this FQDN.</StatusIndicator>
      ) : (
        <SpaceBetween size="l">
          <Container header={<Header variant="h2">History</Header>}>
            <KeyValuePairs
              columns={2}
              items={[
                { label: "First seen", value: data.firstSeen ?? "—" },
                { label: "Last renewal / issue", value: data.lastIssued ?? "—" },
                { label: "First requested by", value: data.firstRequestedBy ?? "—" },
                { label: "Last requested by", value: data.lastRequestedBy ?? "—" },
                { label: "Certificates issued", value: String(data.certificateCount) },
                {
                  label: "Renewal notification email",
                  value: (
                    <SpaceBetween direction="horizontal" size="xs" alignItems="center">
                      <span>{data.notificationEmail ?? "not configured"}</span>
                      {can("admin") && (
                        <Link variant="primary" onFollow={openEdit}>
                          {data.notificationEmail ? "Edit" : "Set"}
                        </Link>
                      )}
                    </SpaceBetween>
                  ),
                },
              ]}
            />
          </Container>

          <Table<CertificateSummary>
            variant="container"
            items={data.certificates}
            trackBy="id"
            resizableColumns
            empty={
              <Box textAlign="center" color="inherit">
                No certificates for this FQDN.
              </Box>
            }
            columnDefinitions={[
              {
                id: "serial",
                header: "Serial",
                cell: (c) => <Box fontSize="body-s">{c.serialNumber}</Box>,
              },
              { id: "subject", header: "Subject", cell: (c) => c.subject },
              { id: "issuer", header: "Issuer", cell: (c) => c.issuer },
              { id: "expires", header: "Expires", cell: (c) => c.validTo },
              { id: "status", header: "Status", cell: (c) => statusIndicator(c.status) },
              {
                id: "actions",
                header: "",
                cell: (c) => (
                  <Link onFollow={() => navigate(`/certificates/${c.id}`)}>View</Link>
                ),
              },
            ]}
            header={
              <Header counter={`(${data.certificates.length})`} variant="h2">
                Certificates issued
              </Header>
            }
          />
        </SpaceBetween>
      )}

      <Modal
        visible={editing}
        onDismiss={() => setEditing(false)}
        header="Renewal notification email"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setEditing(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={save.isPending}
                onClick={() => save.mutate()}
              >
                Save
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box>
            Contact notified for renewals of <b>{fqdn}</b>. Stored for reference;
            no mail is sent yet.
          </Box>
          <FormField label="Email">
            <Input
              value={email}
              type="email"
              placeholder="ops@oopl.dev.mil"
              onChange={({ detail }) => setEmail(detail.value)}
            />
          </FormField>
          {saveError && <Alert type="error">{saveError}</Alert>}
        </SpaceBetween>
      </Modal>
    </ContentLayout>
  );
}
