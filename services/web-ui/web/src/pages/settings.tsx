import { useQuery } from "@tanstack/react-query";
import {
  Box,
  ColumnLayout,
  Container,
  ContentLayout,
  Header,
  KeyValuePairs,
  SpaceBetween,
  StatusIndicator,
} from "@cloudscape-design/components";

import { fetchCaInfo, serviceUp } from "@/lib/ca";
import { config } from "@/lib/config";

const SERVICES: { name: string; svc: string }[] = [
  { name: "Certificate Authority", svc: "ca" },
  { name: "EST Enrollment", svc: "est" },
  { name: "ACME", svc: "acme" },
  { name: "OCSP Responder", svc: "ocsp" },
  { name: "SCMS", svc: "scms" },
  { name: "Key Recovery (KRA)", svc: "kra" },
];

function ServiceHealth({ name, svc }: Readonly<{ name: string; svc: string }>) {
  const { data, isLoading } = useQuery({
    queryKey: ["service-health", svc],
    queryFn: () => serviceUp(svc),
    retry: false,
  });
  return (
    <Box>
      <Box variant="awsui-key-label">{name}</Box>
      {isLoading ? (
        <StatusIndicator type="loading">Checking</StatusIndicator>
      ) : data ? (
        <StatusIndicator type="success">Up</StatusIndicator>
      ) : (
        <StatusIndicator type="error">Down</StatusIndicator>
      )}
    </Box>
  );
}

export function SettingsPage() {
  const { data: ca, isLoading, isError } = useQuery({
    queryKey: ["ca-info"],
    queryFn: fetchCaInfo,
  });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Certificate authority identity and live service status."
        >
          System
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Certificate Authority</Header>}>
          {isLoading ? (
            <StatusIndicator type="loading">Loading</StatusIndicator>
          ) : isError || !ca ? (
            <StatusIndicator type="error">Failed to load CA info.</StatusIndicator>
          ) : (
            <KeyValuePairs
              columns={1}
              items={[
                { label: "CA ID", value: <Box fontSize="body-s">{ca.ca_id}</Box> },
                {
                  label: "Distinguished name",
                  value: <Box fontSize="body-s">{ca.ca_dn}</Box>,
                },
              ]}
            />
          )}
        </Container>

        <Container header={<Header variant="h2">Services</Header>}>
          <ColumnLayout columns={3} borders="vertical">
            {SERVICES.map((s) => (
              <ServiceHealth key={s.svc} name={s.name} svc={s.svc} />
            ))}
          </ColumnLayout>
        </Container>

        <Box color="text-body-secondary" fontSize="body-s">
          Policy and configuration (password policy, MFA, CRL cadence, CA
          parameters) are managed via service configuration and are read-only
          here.
        </Box>

        <Box textAlign="center" color="text-status-inactive" fontSize="body-s">
          OstrichPKI Web UI v{config.version}
        </Box>
      </SpaceBetween>
    </ContentLayout>
  );
}
