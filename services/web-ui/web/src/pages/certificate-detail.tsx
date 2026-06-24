import { type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import {
  Badge,
  Box,
  Button,
  Container,
  ContentLayout,
  CopyToClipboard,
  Header,
  KeyValuePairs,
  SpaceBetween,
  StatusIndicator,
} from "@cloudscape-design/components";

import {
  fetchCertificateDetail,
  type CertificateDetails,
  type CertificateStatus,
} from "@/lib/ca";

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

function mono(value?: ReactNode): ReactNode {
  return <Box fontSize="body-s">{value ?? "—"}</Box>;
}

function Tags({ items }: Readonly<{ items: string[] }>) {
  if (items.length === 0) return <Box color="text-status-inactive">—</Box>;
  return (
    <SpaceBetween direction="horizontal" size="xxs">
      {items.map((i) => (
        <Badge key={i}>{i}</Badge>
      ))}
    </SpaceBetween>
  );
}

function DetailBody({ c }: Readonly<{ c: CertificateDetails }>) {
  return (
    <SpaceBetween size="l">
      <Container header={<Header variant="h2">Overview</Header>}>
        <KeyValuePairs
          columns={2}
          items={[
            { label: "Subject", value: mono(c.subjectDn) },
            { label: "Issuer", value: mono(c.issuerDn) },
            { label: "Serial", value: mono(c.serialNumber) },
            { label: "Version", value: `v${c.version}` },
            { label: "Status", value: statusIndicator(c.status) },
            {
              label: "Days remaining",
              value: c.daysRemaining != null ? String(c.daysRemaining) : "—",
            },
            { label: "Valid from", value: mono(c.validFrom) },
            { label: "Valid to", value: mono(c.validTo) },
          ]}
        />
      </Container>

      <Container header={<Header variant="h2">Key &amp; signature</Header>}>
        <KeyValuePairs
          columns={2}
          items={[
            { label: "Key algorithm", value: `${c.keyAlgorithm} (${c.keySize})` },
            { label: "Signature", value: c.signatureAlgorithm },
            { label: "SHA-256", value: mono(c.fingerprintSha256) },
            { label: "SHA-1", value: mono(c.fingerprintSha1) },
            { label: "Authority key id", value: mono(c.authorityKeyId) },
            { label: "Subject key id", value: mono(c.subjectKeyId) },
            { label: "Key usage", value: <Tags items={c.keyUsage} /> },
            { label: "Extended key usage", value: <Tags items={c.extendedKeyUsage} /> },
            {
              label: "Subject alt names",
              value: (
                <Tags items={c.subjectAltNames.map((s) => `${s.nameType}:${s.value}`)} />
              ),
            },
            { label: "CRL distribution", value: <Tags items={c.crlDistributionPoints} /> },
            { label: "OCSP", value: <Tags items={c.ocspResponderUrls} /> },
          ]}
        />
      </Container>

      {c.status === "revoked" && (
        <Container header={<Header variant="h2">Revocation</Header>}>
          <KeyValuePairs
            columns={2}
            items={[
              { label: "Revoked at", value: mono(c.revocationTime) },
              { label: "Reason", value: c.revocationReason ?? "—" },
            ]}
          />
        </Container>
      )}

      {c.extensions.length > 0 && (
        <Container header={<Header variant="h2">Extensions</Header>}>
          <SpaceBetween size="s">
            {c.extensions.map((e) => (
              <Box key={e.oid} padding="xs">
                <SpaceBetween direction="horizontal" size="xs">
                  <Box fontWeight="bold">{e.name}</Box>
                  <Box fontSize="body-s" color="text-status-inactive">
                    {e.oid}
                  </Box>
                  {e.critical && <Badge color="severity-medium">critical</Badge>}
                </SpaceBetween>
                <Box fontSize="body-s" color="text-body-secondary">
                  {e.value}
                </Box>
              </Box>
            ))}
          </SpaceBetween>
        </Container>
      )}

      <Container
        header={
          <Header
            variant="h2"
            actions={
              <CopyToClipboard
                variant="button"
                textToCopy={c.pem}
                copyButtonText="Copy PEM"
                copySuccessText="Copied"
                copyErrorText="Copy failed"
              />
            }
          >
            PEM
          </Header>
        }
      >
        <Box variant="code">
          <pre style={{ margin: 0, maxHeight: 288, overflow: "auto" }}>{c.pem}</pre>
        </Box>
      </Container>
    </SpaceBetween>
  );
}

export function CertificateDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["certificate", id],
    queryFn: () => fetchCertificateDetail(id),
  });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          actions={
            <Button onClick={() => navigate("/certificates")}>Back to list</Button>
          }
        >
          Certificate
        </Header>
      }
    >
      {isLoading ? (
        <StatusIndicator type="loading">Loading</StatusIndicator>
      ) : isError || !data ? (
        <StatusIndicator type="error">
          Failed to load this certificate.
        </StatusIndicator>
      ) : (
        <DetailBody c={data} />
      )}
    </ContentLayout>
  );
}
