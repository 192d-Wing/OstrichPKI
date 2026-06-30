import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  ButtonDropdown,
  Container,
  ContentLayout,
  Header,
  KeyValuePairs,
  SpaceBetween,
  Spinner,
  Table,
} from "@cloudscape-design/components";

import { StatusBadge } from "@/components/status-badge";
import { downloadBase64, downloadPemAsDer, downloadText } from "@/lib/download";
import {
  portalApi,
  type CertificateDetail,
  type CertificateExtension,
} from "@/lib/portal-api";

/** Common Name from an RFC 4514 subject DN, falling back to the full DN. */
function commonName(subjectDn: string): string {
  const match = /CN=([^,]+)/i.exec(subjectDn);
  return match ? match[1].trim() : subjectDn;
}

/** A filesystem-safe base name for the downloaded files. */
function fileBase(cert: CertificateDetail): string {
  const cn = commonName(cert.subjectDn).replace(/[^A-Za-z0-9._-]+/g, "_");
  return cn || `cert-${cert.serialNumber}`;
}

export function CertificateDetailPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const id = params.get("id") ?? "";

  const { data: cert, isLoading, isError, error } = useQuery({
    queryKey: ["certificate-detail", id],
    queryFn: () => portalApi.certificateDetail(id),
    enabled: !!id,
    retry: false,
  });

  // The CA chain (for the "Full chain (PEM)" download). Best-effort: the leaf
  // PEM alone still downloads if this fails.
  const caInfo = useQuery({
    queryKey: ["ca-info"],
    queryFn: () => portalApi.caInfo(),
    staleTime: 5 * 60_000,
  });

  const sanItems = useMemo(
    () => cert?.subjectAltNames.map((s) => `${s.nameType}:${s.value}`) ?? [],
    [cert],
  );

  if (!id) {
    return (
      <ContentLayout header={<Header variant="h1">Certificate</Header>}>
        <Alert type="error" header="No certificate specified">
          This page needs a <code>?id=</code> certificate identifier.
        </Alert>
      </ContentLayout>
    );
  }

  if (isLoading) {
    return (
      <Box padding="xxl" textAlign="center">
        <Spinner size="large" />
      </Box>
    );
  }

  if (isError || !cert) {
    return (
      <ContentLayout header={<Header variant="h1">Certificate</Header>}>
        <Alert type="error" header="Certificate not found">
          {(error as Error)?.message ?? "The certificate could not be loaded."}
        </Alert>
      </ContentLayout>
    );
  }

  function downloadPem() {
    downloadText(cert!.pem, `${fileBase(cert!)}.pem`, "application/x-pem-file");
  }
  function downloadDer() {
    downloadPemAsDer(cert!.pem, `${fileBase(cert!)}.cer`);
  }
  function downloadChain() {
    const chainPem = caInfo.data?.chain_pem ?? "";
    const bundle = `${cert!.pem.trim()}\n${chainPem.trim()}\n`;
    downloadText(bundle, `${fileBase(cert!)}-chain.pem`, "application/x-pem-file");
  }
  async function downloadPkcs7() {
    const res = await portalApi.certificatePkcs7(cert!.id);
    downloadBase64(res.pkcs7, `${fileBase(cert!)}.p7b`, "application/pkcs7-mime");
  }

  const isRevoked = cert.status.toLowerCase() === "revoked";

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={cert.subjectDn}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={() => navigate(`/certificates/rekey?renewFrom=${encodeURIComponent(cert.id)}`)}>
                Renew / Rekey
              </Button>
              <ButtonDropdown
                items={[
                  { id: "pem", text: "PEM (.pem)" },
                  { id: "der", text: "DER (.cer)" },
                  {
                    id: "chain",
                    text: "Full chain (PEM)",
                    disabled: !caInfo.data?.chain_pem,
                  },
                  { id: "p7b", text: "PKCS#7 (.p7b)" },
                ]}
                onItemClick={({ detail }) => {
                  if (detail.id === "pem") downloadPem();
                  else if (detail.id === "der") downloadDer();
                  else if (detail.id === "chain") downloadChain();
                  else if (detail.id === "p7b") void downloadPkcs7();
                }}
                variant="primary"
              >
                Download
              </ButtonDropdown>
            </SpaceBetween>
          }
        >
          {commonName(cert.subjectDn)}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {isRevoked && (
          <Alert type="warning" header="This certificate is revoked">
            Revoked
            {cert.revocationTime ? ` on ${cert.revocationTime.slice(0, 10)}` : ""}
            {cert.revocationReason ? ` (${cert.revocationReason})` : ""}.
          </Alert>
        )}

        <Container header={<Header variant="h2">Overview</Header>}>
          <KeyValuePairs
            columns={3}
            items={[
              { label: "Status", value: <StatusBadge status={cert.status} /> },
              { label: "Serial number", value: cert.serialNumber },
              { label: "Version", value: `v${cert.version}` },
              { label: "Subject", value: cert.subjectDn },
              { label: "Issuer", value: cert.issuerDn },
              {
                label: "Validity",
                value: `${cert.validFrom.slice(0, 10)} → ${cert.validTo.slice(0, 10)}`,
              },
              {
                label: "Days remaining",
                value: cert.daysRemaining != null ? String(cert.daysRemaining) : "—",
              },
              {
                label: "Key",
                value: `${cert.keyAlgorithm}${cert.keySize ? ` ${cert.keySize}-bit` : ""}`,
              },
              { label: "Signature algorithm", value: cert.signatureAlgorithm || "—" },
            ]}
          />
        </Container>

        <Container header={<Header variant="h2">Identifiers & fingerprints</Header>}>
          <KeyValuePairs
            columns={1}
            items={[
              { label: "SHA-256 fingerprint", value: cert.fingerprintSha256 || "—" },
              { label: "SHA-1 fingerprint", value: cert.fingerprintSha1 || "—" },
              { label: "Subject Key Identifier", value: cert.subjectKeyId ?? "—" },
              { label: "Authority Key Identifier", value: cert.authorityKeyId ?? "—" },
            ]}
          />
        </Container>

        <Container header={<Header variant="h2">Subject Alternative Names</Header>}>
          {sanItems.length > 0 ? (
            <Box>{sanItems.join(", ")}</Box>
          ) : (
            <Box color="text-status-inactive">None</Box>
          )}
        </Container>

        <Container header={<Header variant="h2">Usage</Header>}>
          <KeyValuePairs
            columns={2}
            items={[
              {
                label: "Key usage",
                value: cert.keyUsage.length ? cert.keyUsage.join(", ") : "—",
              },
              {
                label: "Extended key usage",
                value: cert.extendedKeyUsage.length
                  ? cert.extendedKeyUsage.join(", ")
                  : "—",
              },
              {
                label: "CRL distribution points",
                value: cert.crlDistributionPoints.length
                  ? cert.crlDistributionPoints.join(", ")
                  : "—",
              },
              {
                label: "OCSP responders",
                value: cert.ocspResponderUrls.length
                  ? cert.ocspResponderUrls.join(", ")
                  : "—",
              },
            ]}
          />
        </Container>

        <Container header={<Header variant="h2">Extensions</Header>}>
          <Table<CertificateExtension>
            variant="embedded"
            items={cert.extensions}
            columnDefinitions={[
              { id: "name", header: "Extension", cell: (e) => e.name || e.oid },
              { id: "oid", header: "OID", cell: (e) => <Box variant="code">{e.oid}</Box> },
              { id: "critical", header: "Critical", cell: (e) => (e.critical ? "Yes" : "No") },
              { id: "value", header: "Value", cell: (e) => e.value },
            ]}
            empty={<Box color="text-status-inactive">No parsed extensions.</Box>}
          />
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
