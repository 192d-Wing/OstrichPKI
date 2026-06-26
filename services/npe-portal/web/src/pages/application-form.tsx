import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
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
  Input,
  Select,
  SpaceBetween,
  Textarea,
} from "@cloudscape-design/components";

import { portalApi, type SubmitApplicationResponse } from "@/lib/portal-api";

const PROFILES = [
  { label: "TLS Client", value: "tls_client" },
  { label: "TLS Server", value: "tls_server" },
  { label: "TLS Server + Client", value: "tls_server_client" },
];

const CSR_MARKER = "-----BEGIN CERTIFICATE REQUEST-----";

export function ApplicationForm({
  mode,
  title,
  description,
}: Readonly<{ mode: "issuance" | "renewal"; title: string; description: string }>) {
  const [csr, setCsr] = useState("");
  const [profile, setProfile] = useState(PROFILES[0]);
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      portalApi.submitApplication(mode, {
        csr_pem: csr.trim(),
        profile: profile.value,
        notification_email: email.trim(),
      }),
    onSuccess: () => setError(null),
    onError: (e: Error) => setError(e.message),
  });

  const emailValid = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim());
  const csrValid = csr.trim().includes(CSR_MARKER);
  const canSubmit = csrValid && emailValid && !mutation.isPending;

  function onSubmit() {
    if (!csrValid) {
      setError("Paste a valid PKCS #10 PEM certificate request.");
      return;
    }
    if (!emailValid) {
      setError("Enter a valid notification email address.");
      return;
    }
    mutation.mutate();
  }

  const result = mutation.data as SubmitApplicationResponse | undefined;

  return (
    <ContentLayout header={<Header variant="h1" description={description}>{title}</Header>}>
      <SpaceBetween size="l">
        {result && (
          <Alert type="success" header="Application queued for review">
            <SpaceBetween size="xs">
              <Box>
                Your application was submitted and is awaiting Registration Authority review.
              </Box>
              <Box>
                Request ID:{" "}
                <Box variant="code" display="inline">
                  {result.id}
                </Box>{" "}
                <CopyToClipboard
                  copyButtonText="Copy"
                  copyErrorText="Failed to copy"
                  copySuccessText="Copied"
                  textToCopy={result.id}
                  variant="inline"
                />
              </Box>
            </SpaceBetween>
          </Alert>
        )}
        {error && (
          <Alert type="error" header="Submission failed">
            {error}
          </Alert>
        )}
        <Container>
          <Form
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  variant="primary"
                  onClick={onSubmit}
                  loading={mutation.isPending}
                  disabled={!canSubmit}
                >
                  Submit
                </Button>
              </SpaceBetween>
            }
          >
            <SpaceBetween size="l">
              <FormField
                label="Notification email address"
                description="Where status notifications for this request are sent."
                errorText={email && !emailValid ? "Enter a valid email address." : undefined}
              >
                <Input
                  value={email}
                  onChange={(e) => setEmail(e.detail.value)}
                  type="email"
                  placeholder="first.last@example.mil"
                />
              </FormField>
              <FormField label="Certificate profile">
                <Select
                  selectedOption={profile}
                  onChange={(e) =>
                    setProfile(
                      PROFILES.find((p) => p.value === e.detail.selectedOption.value) ?? PROFILES[0],
                    )
                  }
                  options={PROFILES}
                />
              </FormField>
              <FormField
                label="Certificate request (PKCS #10 PEM)"
                description="Paste the PEM-encoded CSR generated on the device."
                errorText={csr && !csrValid ? "Not a PEM certificate request." : undefined}
              >
                <Textarea
                  value={csr}
                  onChange={(e) => setCsr(e.detail.value)}
                  rows={10}
                  placeholder={CSR_MARKER}
                />
              </FormField>
            </SpaceBetween>
          </Form>
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
