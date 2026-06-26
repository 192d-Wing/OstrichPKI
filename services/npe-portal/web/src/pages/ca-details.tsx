import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Container,
  ContentLayout,
  CopyToClipboard,
  Header,
  KeyValuePairs,
  SpaceBetween,
  Spinner,
} from "@cloudscape-design/components";

import { portalApi } from "@/lib/portal-api";

export function CaDetailsPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["ca-info"],
    queryFn: portalApi.caInfo,
    retry: false,
  });

  function downloadChain() {
    if (!data?.chain_pem) return;
    const blob = new Blob([data.chain_pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ca-certificate.pem";
    // The anchor must be in the DOM for a synthetic click to trigger a download
    // in some browsers; revoke the object URL only after the click is dispatched.
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Certificate authority key type, algorithm, and chain.">
          View Certificate Authorities Details
        </Header>
      }
    >
      <SpaceBetween size="l">
        {isLoading && <Spinner size="large" />}
        {error && (
          <Alert type="error" header="Failed to load CA details">
            {(error as Error).message}
          </Alert>
        )}
        {data && (
          <Container
            header={
              <Header
                variant="h2"
                actions={
                  data.chain_pem ? (
                    <Button iconName="download" onClick={downloadChain}>
                      Download chain (PEM)
                    </Button>
                  ) : undefined
                }
              >
                {data.ca_dn}
              </Header>
            }
          >
            <KeyValuePairs
              columns={3}
              items={[
                { label: "CA ID", value: data.ca_id },
                { label: "Key type", value: data.key_type ?? "-" },
                { label: "Signature algorithm", value: data.signature_algorithm ?? "-" },
                { label: "Issuer", value: data.issuer_dn ?? "-" },
                { label: "Serial", value: data.serial ?? "-" },
                { label: "Valid from", value: data.not_before ?? "-" },
                { label: "Valid to", value: data.not_after ?? "-" },
                {
                  label: "Certificate (PEM)",
                  value: data.chain_pem ? (
                    <CopyToClipboard
                      copyButtonText="Copy PEM"
                      copyErrorText="Failed to copy"
                      copySuccessText="Copied"
                      textToCopy={data.chain_pem}
                      variant="button"
                    />
                  ) : (
                    <Box variant="span">-</Box>
                  ),
                },
              ]}
            />
          </Container>
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}
