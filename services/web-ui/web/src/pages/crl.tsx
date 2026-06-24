import { useMutation } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  ColumnLayout,
  Container,
  ContentLayout,
  Header,
  KeyValuePairs,
  SpaceBetween,
} from "@cloudscape-design/components";

import { ApiError } from "@/lib/api";
import { generateCrl } from "@/lib/ca";
import { useAuth } from "@/lib/auth-context";

function CrlCard({
  title,
  description,
  endpoint,
  canGenerate,
}: {
  title: string;
  description: string;
  endpoint: string;
  canGenerate: boolean;
}) {
  const gen = useMutation({ mutationFn: () => generateCrl(endpoint) });
  const r = gen.data;
  return (
    <Container header={<Header variant="h2" description={description}>{title}</Header>}>
      <SpaceBetween size="m">
        {r && (
          <KeyValuePairs
            columns={2}
            items={[
              { label: "CRL number", value: String(r.crl_number) },
              { label: "Revoked entries", value: String(r.revoked_count) },
              { label: "This update", value: r.this_update },
              { label: "Next update", value: r.next_update },
            ]}
          />
        )}
        {gen.isError && (
          <Alert type="error">
            {gen.error instanceof ApiError
              ? gen.error.message
              : "Generation failed."}
          </Alert>
        )}
        <SpaceBetween direction="horizontal" size="xs">
          {canGenerate && (
            <Button loading={gen.isPending} onClick={() => gen.mutate()}>
              Generate
            </Button>
          )}
          <Button iconName="download" href={`/api${endpoint}`}>
            Download
          </Button>
        </SpaceBetween>
      </SpaceBetween>
    </Container>
  );
}

export function CrlPage() {
  const { can } = useAuth();
  const canGenerate = can("generate_crl");
  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Generate and download Certificate Revocation Lists (RFC 5280)."
        >
          Revocation Lists
        </Header>
      }
    >
      <SpaceBetween size="l">
        {!canGenerate && (
          <Box color="text-status-inactive">
            You can download published CRLs. Generating one requires the
            Operations role.
          </Box>
        )}
        <ColumnLayout columns={2}>
          <CrlCard
            title="Full CRL"
            description="A complete list of all revoked certificates."
            endpoint="/ca/api/v1/crl"
            canGenerate={canGenerate}
          />
          <CrlCard
            title="Delta CRL"
            description="Only entries revoked since the last full CRL (RFC 5280 §5.2.4)."
            endpoint="/ca/api/v1/crl/delta"
            canGenerate={canGenerate}
          />
        </ColumnLayout>
      </SpaceBetween>
    </ContentLayout>
  );
}
