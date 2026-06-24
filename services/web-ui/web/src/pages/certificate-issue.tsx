import * as React from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Container,
  ContentLayout,
  CopyToClipboard,
  Form,
  FormField,
  Header,
  Select,
  type SelectProps,
  SpaceBetween,
  Textarea,
} from "@cloudscape-design/components";

import { ApiError } from "@/lib/api";
import {
  fetchProfiles,
  issueCertificate,
  pemToCsrB64,
  type IssueResponse,
} from "@/lib/ca";

export function CertificateIssuePage() {
  const navigate = useNavigate();
  const { data: profilesData } = useQuery({
    queryKey: ["profiles"],
    queryFn: fetchProfiles,
  });
  const profileOptions: SelectProps.Option[] = React.useMemo(
    () =>
      (profilesData?.profiles ?? []).map((p) => ({
        label: p.name,
        value: p.profile_type,
      })),
    [profilesData],
  );

  const [profile, setProfile] = React.useState<SelectProps.Option | null>(null);
  const [csr, setCsr] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);

  // Default to the first profile once loaded.
  React.useEffect(() => {
    if (!profile && profileOptions.length > 0) setProfile(profileOptions[0]);
  }, [profileOptions, profile]);

  const issue = useMutation({
    mutationFn: (): Promise<IssueResponse> =>
      issueCertificate(profile?.value ?? "", pemToCsrB64(csr)),
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Issuance failed"),
  });

  function onSubmit() {
    setError(null);
    if (!pemToCsrB64(csr)) {
      setError("Paste a PEM-encoded certificate request (CSR).");
      return;
    }
    issue.reset();
    issue.mutate();
  }

  const r = issue.data;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Paste a PKCS#10 CSR and choose a profile; the CA derives the subject, key, and SANs from the request."
          actions={
            <Button onClick={() => navigate("/certificates")}>
              Back to list
            </Button>
          }
        >
          Issue Certificate
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container
          header={
            <Header variant="h2" description="RFC 7030 / RFC 2986 PKCS#10.">
              Request
            </Header>
          }
        >
          <Form
            actions={
              <Button
                variant="primary"
                loading={issue.isPending}
                disabled={!profile}
                onClick={onSubmit}
              >
                Issue certificate
              </Button>
            }
          >
            <SpaceBetween size="l">
              <FormField label="Profile">
                <Select
                  selectedOption={profile}
                  options={profileOptions}
                  placeholder="Select a profile"
                  onChange={({ detail }) => setProfile(detail.selectedOption)}
                />
              </FormField>
              <FormField label="Certificate request (PEM)">
                <Textarea
                  value={csr}
                  onChange={({ detail }) => setCsr(detail.value)}
                  rows={9}
                  placeholder={
                    "-----BEGIN CERTIFICATE REQUEST-----\n…\n-----END CERTIFICATE REQUEST-----"
                  }
                />
              </FormField>
              {error && <Alert type="error">{error}</Alert>}
            </SpaceBetween>
          </Form>
        </Container>

        {r && (
          <Container
            header={
              <Header
                variant="h2"
                description={`Serial ${r.serial_number} · valid ${r.not_before} → ${r.not_after}`}
                actions={
                  <Button onClick={() => navigate(`/certificates/${r.certificate_id}`)}>
                    View details
                  </Button>
                }
              >
                Issued
              </Header>
            }
          >
            <SpaceBetween size="s">
              <CopyToClipboard
                variant="button"
                textToCopy={r.pem_encoded}
                copyButtonText="Copy PEM"
                copySuccessText="Copied"
                copyErrorText="Copy failed"
              />
              <Box variant="code">
                <pre style={{ margin: 0, maxHeight: 288, overflow: "auto" }}>
                  {r.pem_encoded}
                </pre>
              </Box>
            </SpaceBetween>
          </Container>
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}
