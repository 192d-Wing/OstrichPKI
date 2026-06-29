import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
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
  Modal,
  Select,
  type SelectProps,
  SpaceBetween,
  Textarea,
} from "@cloudscape-design/components";

import { StatusBadge } from "@/components/status-badge";
import { portalApi, REVOCATION_REASONS, type CertificateSummary } from "@/lib/portal-api";

const REASON_OPTIONS: SelectProps.Option[] = REVOCATION_REASONS.map((r) => ({
  label: r.label,
  value: r.value,
}));

function isRevoked(status: string): boolean {
  return status.toLowerCase().includes("revok");
}

export function RevokeCertificatesPage() {
  const [id, setId] = useState("");
  const [reason, setReason] = useState<SelectProps.Option>(REASON_OPTIONS[1]); // Key compromise
  const [justification, setJustification] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [flash, setFlash] = useState<string | null>(null);

  const lookup = useMutation({
    mutationFn: (certId: string) => portalApi.getCertificate(certId),
    onSuccess: () => {
      setError(null);
      // Start each certificate from a clean revoke form so a reason/justification
      // typed for a previous certificate can never carry over to a different one.
      setReason(REASON_OPTIONS[1]);
      setJustification("");
    },
    onError: (e: Error) => setError(e.message),
  });

  const revoke = useMutation({
    mutationFn: () => portalApi.revokeCertificate(id.trim(), String(reason.value), justification.trim()),
    onSuccess: (res) => {
      setConfirmOpen(false);
      setFlash(`Certificate ${id.trim()} revoked at ${res.revocation_time}.`);
      setError(null);
      lookup.mutate(id.trim()); // refresh the summary so the status reflects revocation
    },
    onError: (e: Error) => {
      setConfirmOpen(false);
      setError(e.message);
    },
  });

  const cert = lookup.data as CertificateSummary | undefined;
  const alreadyRevoked = cert ? isRevoked(cert.status) : false;

  function onLookup() {
    const trimmed = id.trim();
    if (!trimmed) {
      setError("Enter a certificate ID.");
      return;
    }
    setFlash(null);
    lookup.mutate(trimmed);
  }

  function onRevokeClick() {
    if (!justification.trim()) {
      setError("A justification is required to revoke a certificate.");
      return;
    }
    setError(null);
    setConfirmOpen(true);
  }

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Look up an issued certificate and revoke it.">
          Revoke Certificates
        </Header>
      }
    >
      <SpaceBetween size="l">
        {flash && (
          <Alert type="success" dismissible onDismiss={() => setFlash(null)} header="Certificate revoked">
            {flash}
          </Alert>
        )}
        {error && (
          <Alert type="error" dismissible onDismiss={() => setError(null)} header="Error">
            {error}
          </Alert>
        )}

        <Container header={<Header variant="h2">Find certificate</Header>}>
          <SpaceBetween direction="horizontal" size="xs">
            <Input
              value={id}
              onChange={(e) => setId(e.detail.value)}
              placeholder="Certificate ID (UUID)"
            />
            <Button variant="primary" onClick={onLookup} loading={lookup.isPending}>
              Look up
            </Button>
          </SpaceBetween>
        </Container>

        {cert && (
          <Container header={<Header variant="h2">Certificate</Header>}>
            <SpaceBetween size="l">
              <KeyValuePairs
                columns={3}
                items={[
                  { label: "Subject", value: cert.subjectDn },
                  { label: "Serial", value: cert.serialNumber },
                  { label: "Status", value: <StatusBadge status={cert.status} /> },
                  { label: "Valid to", value: cert.validTo },
                  {
                    label: "Days remaining",
                    value: cert.daysRemaining == null ? "-" : String(cert.daysRemaining),
                  },
                ]}
              />

              {alreadyRevoked ? (
                <Alert type="info">This certificate is already revoked.</Alert>
              ) : (
                <>
                  <FormField label="Revocation reason" description="RFC 5280 reason code.">
                    <Select
                      selectedOption={reason}
                      onChange={(e) => setReason(e.detail.selectedOption)}
                      options={REASON_OPTIONS}
                    />
                  </FormField>
                  <FormField
                    label="Justification"
                    description="Required. Recorded against your identity in the audit trail."
                  >
                    <Textarea
                      value={justification}
                      onChange={(e) => setJustification(e.detail.value)}
                      rows={3}
                      placeholder="Why is this certificate being revoked?"
                    />
                  </FormField>
                  <Box>
                    <Button variant="primary" onClick={onRevokeClick}>
                      Revoke certificate
                    </Button>
                  </Box>
                </>
              )}
            </SpaceBetween>
          </Container>
        )}
      </SpaceBetween>

      {confirmOpen && cert && (
        <Modal
          visible
          onDismiss={() => setConfirmOpen(false)}
          header="Revoke certificate"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setConfirmOpen(false)} disabled={revoke.isPending}>
                  Cancel
                </Button>
                <Button variant="primary" onClick={() => revoke.mutate()} loading={revoke.isPending}>
                  Confirm revocation
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="m">
            <Alert type="warning" header="This action cannot be undone">
              Revoking a certificate is permanent and publishes its serial to the CRL/OCSP. Relying
              parties will reject it.
            </Alert>
            <KeyValuePairs
              columns={2}
              items={[
                { label: "Subject", value: cert.subjectDn },
                { label: "Serial", value: cert.serialNumber },
                { label: "Reason", value: reason.label ?? String(reason.value) },
              ]}
            />
          </SpaceBetween>
        </Modal>
      )}
    </ContentLayout>
  );
}
