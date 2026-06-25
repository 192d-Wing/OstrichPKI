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
  Select,
  SpaceBetween,
  StatusIndicator,
  Table,
  Tabs,
  Textarea,
} from "@cloudscape-design/components";

import { ApiError } from "@/lib/api";
import {
  REVOCATION_REASONS,
  revokeCertificate,
  type CertificateStatus,
  type CertificateSummary,
  type RevocationReason,
} from "@/lib/ca";
import {
  fetchFqdnEstTokens,
  fetchFqdnRecord,
  setFqdnNotification,
  type EstToken,
} from "@/lib/fqdn";
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

function tokenStatus(status: string) {
  switch (status) {
    case "live":
      return <StatusIndicator type="success">live</StatusIndicator>;
    case "used":
      return <StatusIndicator type="info">used</StatusIndicator>;
    case "revoked":
      return <StatusIndicator type="error">revoked</StatusIndicator>;
    case "expired":
      return <StatusIndicator type="warning">expired</StatusIndicator>;
    default:
      return <>{status}</>;
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

  // EST tab: shown only when the FQDN has EST-issued certs and the operator may
  // view enrollment tokens (the endpoint is gated by generate_est_token).
  const estEnabled = !!data?.usesEst && can("generate_est_token");
  const estTokens = useQuery({
    queryKey: ["fqdn-est", fqdn],
    queryFn: () => fetchFqdnEstTokens(fqdn),
    enabled: estEnabled,
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

  // Revoke modal.
  const [target, setTarget] = React.useState<CertificateSummary | null>(null);
  const [reason, setReason] = React.useState<RevocationReason>("Unspecified");
  const [notes, setNotes] = React.useState("");
  const [revokeError, setRevokeError] = React.useState<string | null>(null);
  const closeRevoke = () => {
    setTarget(null);
    setRevokeError(null);
  };
  const openRevoke = (cert: CertificateSummary) => {
    setTarget(cert);
    setReason("Unspecified");
    setNotes("");
    setRevokeError(null);
  };
  const revoke = useMutation({
    mutationFn: () => revokeCertificate(target!.id, reason, notes),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["fqdn", fqdn] });
      closeRevoke();
    },
    onError: (e) =>
      setRevokeError(e instanceof ApiError ? e.message : "Failed to revoke"),
  });

  const certColumns = [
    {
      id: "serial",
      header: "Serial",
      cell: (c: CertificateSummary) => <Box fontSize="body-s">{c.serialNumber}</Box>,
    },
    { id: "subject", header: "Subject", cell: (c: CertificateSummary) => c.subject },
    { id: "issuer", header: "Issuer", cell: (c: CertificateSummary) => c.issuer },
    { id: "expires", header: "Expires", cell: (c: CertificateSummary) => c.validTo },
    {
      id: "status",
      header: "Status",
      cell: (c: CertificateSummary) => statusIndicator(c.status),
    },
    {
      id: "actions",
      header: "",
      cell: (c: CertificateSummary) => (
        <SpaceBetween direction="horizontal" size="xs">
          <Link onFollow={() => navigate(`/certificates/${c.id}`)}>View</Link>
          {c.status === "active" && can("revoke_certificates") && (
            <Link variant="secondary" onFollow={() => openRevoke(c)}>
              Revoke
            </Link>
          )}
        </SpaceBetween>
      ),
    },
  ];

  const certsTab = (
    <Table<CertificateSummary>
      variant="borderless"
      items={data?.certificates ?? []}
      trackBy="id"
      wrapLines
      empty={
        <Box textAlign="center" color="inherit">
          No certificates for this FQDN.
        </Box>
      }
      columnDefinitions={certColumns}
    />
  );

  const estTab = (
    <Table<EstToken>
      variant="borderless"
      loading={estTokens.isFetching}
      loadingText="Loading EST tokens"
      items={estTokens.data?.tokens ?? []}
      trackBy="id"
      wrapLines
      empty={
        <Box textAlign="center" color="inherit">
          {estTokens.isError
            ? "Failed to load EST tokens."
            : "No EST tokens for this FQDN."}
        </Box>
      }
      columnDefinitions={[
        { id: "identity", header: "Identity", cell: (t) => t.identity },
        { id: "status", header: "Status", cell: (t) => tokenStatus(t.status) },
        { id: "createdBy", header: "Created by", cell: (t) => t.createdBy },
        {
          id: "createdAt",
          header: "Created",
          cell: (t) => <Box fontSize="body-s">{t.createdAt}</Box>,
        },
        {
          id: "expiresAt",
          header: "Expires",
          cell: (t) => <Box fontSize="body-s">{t.expiresAt}</Box>,
        },
        {
          id: "cert",
          header: "Issued cert",
          cell: (t) =>
            t.usedByCert ? (
              <Link onFollow={() => navigate(`/certificates/${t.usedByCert}`)}>View</Link>
            ) : (
              "—"
            ),
        },
      ]}
    />
  );

  const tabs = [
    {
      id: "certs",
      label: `Certificates (${data?.certificates.length ?? 0})`,
      content: certsTab,
    },
    ...(estEnabled ? [{ id: "est", label: "EST Tokens", content: estTab }] : []),
  ];

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

          <Tabs variant="container" tabs={tabs} />
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

      <Modal
        visible={!!target}
        onDismiss={closeRevoke}
        header="Revoke certificate"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={closeRevoke}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={revoke.isPending}
                onClick={() => revoke.mutate()}
              >
                Revoke certificate
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box>
            This permanently revokes <b>{target?.subject}</b> (serial{" "}
            {target?.serialNumber}). It will appear on the next CRL/OCSP response.
          </Box>
          <FormField label="Reason">
            <Select
              selectedOption={{ label: reason, value: reason }}
              options={REVOCATION_REASONS.map((r) => ({ label: r.label, value: r.value }))}
              onChange={({ detail }) =>
                setReason(detail.selectedOption.value as RevocationReason)
              }
            />
          </FormField>
          <FormField label="Notes (optional)">
            <Textarea
              value={notes}
              onChange={({ detail }) => setNotes(detail.value)}
              placeholder="Context for the audit record"
            />
          </FormField>
          {revokeError && <Alert type="error">{revokeError}</Alert>}
        </SpaceBetween>
      </Modal>
    </ContentLayout>
  );
}
