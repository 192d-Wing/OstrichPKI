import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Container,
  ContentLayout,
  Form,
  FormField,
  Header,
  KeyValuePairs,
  SpaceBetween,
  StatusIndicator,
  Textarea,
} from "@cloudscape-design/components";

import { checkOcsp, type OcspResult } from "@/lib/ocsp";
import { portalApi } from "@/lib/portal-api";

const CERT_MARKER = "-----BEGIN CERTIFICATE-----";

function OcspStatusBadge({ status }: Readonly<{ status: OcspResult["status"] }>) {
  if (status === "good") return <StatusIndicator type="success">Good (not revoked)</StatusIndicator>;
  if (status === "revoked") return <StatusIndicator type="error">Revoked</StatusIndicator>;
  return <StatusIndicator type="warning">Unknown</StatusIndicator>;
}

export function OcspCheckerPage() {
  const [pem, setPem] = useState("");

  // The issuing CA certificate is needed to build the OCSP CertID.
  const caInfo = useQuery({ queryKey: ["ca-info"], queryFn: portalApi.caInfo, staleTime: 5 * 60_000 });

  const check = useMutation({
    mutationFn: () => {
      const issuer = caInfo.data?.chain_pem;
      if (!issuer) throw new Error("The issuing CA certificate is unavailable; try again shortly.");
      return checkOcsp(pem, issuer);
    },
  });

  const valid = pem.includes(CERT_MARKER);
  const result = check.data;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Check a certificate's live revocation status against the OCSP responder (RFC 6960)."
        >
          OCSP Status Check
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container>
          <Form
            actions={
              <Button
                variant="primary"
                loading={check.isPending}
                disabled={!valid || !caInfo.data}
                onClick={() => check.mutate()}
              >
                Check status
              </Button>
            }
          >
            <FormField
              label="Certificate (PEM)"
              description="Paste the PEM-encoded certificate to check. It is checked in your browser against the issuing CA and the OCSP responder — it is not stored."
              errorText={pem && !valid ? "Not a PEM certificate." : undefined}
            >
              <Textarea
                value={pem}
                onChange={(e) => {
                  check.reset();
                  setPem(e.detail.value);
                }}
                rows={10}
                placeholder={CERT_MARKER}
              />
            </FormField>
          </Form>
        </Container>

        {check.isError && (
          <Alert type="error" header="OCSP check failed">
            {(check.error as Error).message}
          </Alert>
        )}

        {result && (
          <Container header={<Header variant="h2">Result</Header>}>
            <KeyValuePairs
              columns={2}
              items={[
                { label: "Status", value: <OcspStatusBadge status={result.status} /> },
                { label: "Serial number", value: <Box variant="code">{result.serial}</Box> },
                { label: "Produced at", value: result.producedAt ?? "—" },
                { label: "This update", value: result.thisUpdate ?? "—" },
                { label: "Next update", value: result.nextUpdate ?? "—" },
                ...(result.status === "revoked"
                  ? [
                      { label: "Revoked at", value: result.revocationTime ?? "—" },
                      { label: "Reason", value: result.revocationReason ?? "—" },
                    ]
                  : []),
              ]}
            />
          </Container>
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}
