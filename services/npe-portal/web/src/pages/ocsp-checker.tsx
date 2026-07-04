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
  Input,
  KeyValuePairs,
  SegmentedControl,
  SpaceBetween,
  StatusIndicator,
  Textarea,
} from "@cloudscape-design/components";

import { checkOcsp, type OcspQuery, type OcspResult } from "@/lib/ocsp";
import { portalApi } from "@/lib/portal-api";

const CERT_MARKER = "-----BEGIN CERTIFICATE-----";

function OcspStatusBadge({ status }: Readonly<{ status: OcspResult["status"] }>) {
  if (status === "good") return <StatusIndicator type="success">Good (not revoked)</StatusIndicator>;
  if (status === "revoked") return <StatusIndicator type="error">Revoked</StatusIndicator>;
  return <StatusIndicator type="warning">Unknown</StatusIndicator>;
}

export function OcspCheckerPage() {
  const [mode, setMode] = useState<"cert" | "serial">("cert");
  const [pem, setPem] = useState("");
  const [serial, setSerial] = useState("");

  // The issuing CA certificate is needed to build the OCSP CertID and to verify
  // the response signature.
  const caInfo = useQuery({ queryKey: ["ca-info"], queryFn: portalApi.caInfo, staleTime: 5 * 60_000 });

  const check = useMutation({
    mutationFn: () => {
      const issuer = caInfo.data?.chain_pem;
      if (!issuer) throw new Error("The issuing CA certificate is unavailable; try again shortly.");
      const query: OcspQuery = mode === "cert" ? { certPem: pem } : { serialHex: serial };
      return checkOcsp(query, issuer);
    },
  });

  const certValid = pem.includes(CERT_MARKER);
  const serialValid = /[0-9a-fA-F]/.test(serial);
  const inputValid = mode === "cert" ? certValid : serialValid;
  const result = check.data;

  function reset() {
    check.reset();
  }

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Check a certificate's live revocation status against the OCSP responder (RFC 6960). The signed response is verified against the issuing CA."
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
                disabled={!inputValid || !caInfo.data}
                onClick={() => check.mutate()}
              >
                Check status
              </Button>
            }
          >
            <SpaceBetween size="m">
              <SegmentedControl
                selectedId={mode}
                onChange={(e) => {
                  reset();
                  setMode(e.detail.selectedId as "cert" | "serial");
                }}
                options={[
                  { id: "cert", text: "Certificate (PEM)" },
                  { id: "serial", text: "Serial number" },
                ]}
              />

              {mode === "cert" ? (
                <FormField
                  label="Certificate (PEM)"
                  description="Paste the PEM-encoded certificate. It is checked in your browser — not stored."
                  errorText={pem && !certValid ? "Not a PEM certificate." : undefined}
                >
                  <Textarea
                    value={pem}
                    onChange={(e) => {
                      reset();
                      setPem(e.detail.value);
                    }}
                    rows={10}
                    placeholder={CERT_MARKER}
                  />
                </FormField>
              ) : (
                <FormField
                  label="Serial number (hex)"
                  description="The certificate serial in hex (e.g. from an audit record). Checked against the current issuing CA."
                  errorText={serial && !serialValid ? "Enter a hex serial number." : undefined}
                >
                  <Input
                    value={serial}
                    onChange={(e) => {
                      reset();
                      setSerial(e.detail.value);
                    }}
                    placeholder="08e47691e954c1fc16cbdfe1173347d1d8a6274a"
                  />
                </FormField>
              )}
            </SpaceBetween>
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
