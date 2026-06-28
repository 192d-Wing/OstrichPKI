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

import { downloadBase64 } from "@/lib/download";
import { portalApi } from "@/lib/portal-api";

const PROFILES = [
  { label: "TLS Client", value: "tls_client" },
  { label: "TLS Server", value: "tls_server" },
  { label: "TLS Server + Client", value: "tls_server_client" },
  { label: "EFS (File Encryption)", value: "efs" },
];

// EFS keys are generated server-side; the form only offers what the EFS profile
// actually issues today (RSA-2048). Adding strengths here is the single change
// needed once the profile supports them.
const EFS_ALGORITHMS = [{ label: "RSA", value: "rsa" }];
const EFS_KEY_STRENGTHS = [{ label: "2048", value: "2048" }];

const CSR_MARKER = "-----BEGIN CERTIFICATE REQUEST-----";

// Profiles whose certificates carry the id-kp-serverAuth EKU (TLS server),
// which Apple/iOS cap at 397 days. The CA enforces the cap; this drives the
// advisory banner.
const SERVER_AUTH_PROFILES = new Set(["tls_server", "tls_server_client"]);

export function ApplicationForm({
  mode,
  title,
  description,
}: Readonly<{ mode: "issuance" | "renewal"; title: string; description: string }>) {
  const [csr, setCsr] = useState("");
  const [profile, setProfile] = useState(PROFILES[0]);
  const [email, setEmail] = useState("");
  const [algorithm, setAlgorithm] = useState(EFS_ALGORITHMS[0]);
  const [keyStrength, setKeyStrength] = useState(EFS_KEY_STRENGTHS[0]);
  const [error, setError] = useState<string | null>(null);

  const isEfs = profile.value === "efs";

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

  // EFS is auto-issued via server-side keygen, NOT queued for RA review.
  const efsMutation = useMutation({
    mutationFn: () => portalApi.efsServerKeygen(Number(keyStrength.value)),
    onSuccess: () => setError(null),
    onError: (e: Error) => setError(e.message),
  });

  const emailValid = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim());
  const csrValid = csr.trim().includes(CSR_MARKER);
  const pending = mutation.isPending || efsMutation.isPending;
  const canSubmit = (isEfs ? emailValid : csrValid && emailValid) && !pending;
  const isServerAuth = SERVER_AUTH_PROFILES.has(profile.value);

  // Editing any field after a submission clears the stale success/result banner
  // so it can never appear to describe the current (edited) input.
  function clearStale() {
    if (mutation.data || mutation.isError) mutation.reset();
    if (efsMutation.data || efsMutation.isError) efsMutation.reset();
    if (error) setError(null);
  }

  function onSubmit() {
    if (isEfs) {
      if (!emailValid) {
        setError("Enter a valid notification email address.");
        return;
      }
      efsMutation.mutate();
      return;
    }
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

  const result = mutation.data;
  const efsResult = efsMutation.data;

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
        {efsResult && (
          <Alert type="success" header="EFS certificate issued — save it now">
            <SpaceBetween size="s">
              <Box>
                Your key and certificate were generated and bundled into an encrypted PKCS#12
                (.p12) file. <strong>The one-time password below is shown only once and cannot be
                recovered after you leave this page.</strong> Download the file and record the
                password before continuing.
              </Box>
              <Box>
                One-time PKCS#12 password:{" "}
                <Box variant="code" display="inline">
                  {efsResult.password}
                </Box>{" "}
                <CopyToClipboard
                  copyButtonText="Copy"
                  copyErrorText="Failed to copy"
                  copySuccessText="Copied"
                  textToCopy={efsResult.password}
                  variant="inline"
                />
              </Box>
              <Box>
                Certificate ID:{" "}
                <Box variant="code" display="inline">
                  {efsResult.certificateId}
                </Box>
              </Box>
              <Button
                iconName="download"
                onClick={() =>
                  downloadBase64(
                    efsResult.pkcs12,
                    `efs-${efsResult.certificateId}.p12`,
                    "application/x-pkcs12",
                  )
                }
              >
                Download .p12
              </Button>
            </SpaceBetween>
          </Alert>
        )}
        {error && (
          <Alert type="error" header="Submission failed">
            {error}
          </Alert>
        )}
        {isServerAuth && (
          <Alert type="warning" header="397-day validity limit">
            Certificates from this TLS server profile are issued for at most 397 days, because
            Apple/iOS and other mainstream TLS clients reject server certificates valid for
            longer.
          </Alert>
        )}
        {isEfs && (
          <Alert type="info" header="Server-side key generation">
            The EFS key is generated on the server for the signed-in identity and delivered as a
            password-protected PKCS#12. No certificate request is required, and this request is
            issued immediately rather than queued for review.
          </Alert>
        )}
        <Container>
          <Form
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  variant="primary"
                  onClick={onSubmit}
                  loading={pending}
                  disabled={!canSubmit}
                >
                  {isEfs ? "Generate certificate" : "Submit"}
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
                  onChange={(e) => {
                    clearStale();
                    setEmail(e.detail.value);
                  }}
                  type="email"
                  placeholder="first.last@example.mil"
                />
              </FormField>
              <FormField label="Certificate profile">
                <Select
                  selectedOption={profile}
                  onChange={(e) => {
                    clearStale();
                    setProfile(
                      PROFILES.find((p) => p.value === e.detail.selectedOption.value) ?? PROFILES[0],
                    );
                  }}
                  options={PROFILES}
                />
              </FormField>
              {isEfs ? (
                <>
                  <FormField
                    label="Key algorithm"
                    description="EFS certificates use RSA keys."
                  >
                    <Select
                      selectedOption={algorithm}
                      onChange={(e) => {
                        clearStale();
                        setAlgorithm(
                          EFS_ALGORITHMS.find((a) => a.value === e.detail.selectedOption.value) ??
                            EFS_ALGORITHMS[0],
                        );
                      }}
                      options={EFS_ALGORITHMS}
                    />
                  </FormField>
                  <FormField label="Key strength (bits)">
                    <Select
                      selectedOption={keyStrength}
                      onChange={(e) => {
                        clearStale();
                        setKeyStrength(
                          EFS_KEY_STRENGTHS.find(
                            (k) => k.value === e.detail.selectedOption.value,
                          ) ?? EFS_KEY_STRENGTHS[0],
                        );
                      }}
                      options={EFS_KEY_STRENGTHS}
                    />
                  </FormField>
                </>
              ) : (
                <FormField
                  label="Certificate request (PKCS #10 PEM)"
                  description="Paste the PEM-encoded CSR generated on the device."
                  errorText={csr && !csrValid ? "Not a PEM certificate request." : undefined}
                >
                  <Textarea
                    value={csr}
                    onChange={(e) => {
                      clearStale();
                      setCsr(e.detail.value);
                    }}
                    rows={10}
                    placeholder={CSR_MARKER}
                  />
                </FormField>
              )}
            </SpaceBetween>
          </Form>
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
