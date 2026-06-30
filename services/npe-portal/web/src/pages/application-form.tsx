import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  ColumnLayout,
  Container,
  ContentLayout,
  CopyToClipboard,
  FileUpload,
  Form,
  FormField,
  Grid,
  Header,
  Input,
  Multiselect,
  type MultiselectProps,
  Select,
  type SelectProps,
  SpaceBetween,
  Textarea,
  TokenGroup,
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
const CSR_END_MARKER = "-----END CERTIFICATE REQUEST-----";

// Combatant Command / Service / Agency the certificate belongs to.
const CCSA_OPTIONS: SelectProps.Options = [
  {
    label: "Military Services",
    options: [
      { label: "Air Force (USAF)", value: "USAF" },
      { label: "Army (USA)", value: "USA" },
      { label: "Navy (USN)", value: "USN" },
      { label: "Marine Corps (USMC)", value: "USMC" },
      { label: "Space Force (USSF)", value: "USSF" },
      { label: "Coast Guard (USCG)", value: "USCG" },
    ],
  },
  {
    label: "Combatant Commands",
    options: [
      { label: "AFRICOM", value: "AFRICOM" },
      { label: "CENTCOM", value: "CENTCOM" },
      { label: "CYBERCOM", value: "CYBERCOM" },
      { label: "EUCOM", value: "EUCOM" },
      { label: "INDOPACOM", value: "INDOPACOM" },
      { label: "NORTHCOM", value: "NORTHCOM" },
      { label: "SOCOM", value: "SOCOM" },
      { label: "SOUTHCOM", value: "SOUTHCOM" },
      { label: "SPACECOM", value: "SPACECOM" },
      { label: "STRATCOM", value: "STRATCOM" },
      { label: "TRANSCOM", value: "TRANSCOM" },
    ],
  },
  {
    label: "Agencies & Field Activities",
    options: [
      { label: "DISA", value: "DISA" },
      { label: "DLA", value: "DLA" },
      { label: "DIA", value: "DIA" },
      { label: "NSA", value: "NSA" },
      { label: "NGA", value: "NGA" },
      { label: "DCSA", value: "DCSA" },
      { label: "DCMA", value: "DCMA" },
      { label: "DFAS", value: "DFAS" },
      { label: "DHA", value: "DHA" },
      { label: "DTRA", value: "DTRA" },
      { label: "MDA", value: "MDA" },
      { label: "OSD / WHS", value: "OSD" },
    ],
  },
];

// Subject Alternative Name kinds (the prefix mirrors how the CA/x509 parser
// renders SANs, e.g. "DNS:host.mil").
const SAN_TYPES: SelectProps.Option[] = [
  { label: "DNS", value: "DNS" },
  { label: "IP Address", value: "IP" },
  { label: "Email", value: "email" },
  { label: "URI", value: "URI" },
  { label: "UPN", value: "UPN" },
];

const KEY_USAGE_OPTIONS: MultiselectProps.Options = [
  { label: "Digital Signature", value: "digitalSignature" },
  { label: "Non-Repudiation", value: "nonRepudiation" },
  { label: "Key Encipherment", value: "keyEncipherment" },
  { label: "Data Encipherment", value: "dataEncipherment" },
  { label: "Key Agreement", value: "keyAgreement" },
  { label: "Certificate Signing", value: "keyCertSign" },
  { label: "CRL Signing", value: "cRLSign" },
  { label: "Encipher Only", value: "encipherOnly" },
  { label: "Decipher Only", value: "decipherOnly" },
];

// Example placeholder for the SAN value input by kind (203.0.113.x is the RFC
// 5737 documentation range, never a real host).
function sanPlaceholder(type: string | undefined): string {
  switch (type) {
    case "IP":
      return "203.0.113.10";
    case "email":
      return "user@example.mil";
    default:
      return "host.example.mil";
  }
}

const EKU_OPTIONS: MultiselectProps.Options = [
  { label: "TLS Server Authentication", value: "serverAuth" },
  { label: "TLS Client Authentication", value: "clientAuth" },
  { label: "Code Signing", value: "codeSigning" },
  { label: "Email Protection", value: "emailProtection" },
  { label: "Time Stamping", value: "timeStamping" },
  { label: "OCSP Signing", value: "OCSPSigning" },
  { label: "Smartcard Logon", value: "smartcardLogon" },
  { label: "IPsec IKE", value: "ipsecIKE" },
];

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
  const [csrFiles, setCsrFiles] = useState<File[]>([]);
  const [profile, setProfile] = useState(PROFILES[0]);
  const [email, setEmail] = useState("");
  const [issmEmail, setIssmEmail] = useState("");
  const [pmEmail, setPmEmail] = useState("");
  const [algorithm, setAlgorithm] = useState(EFS_ALGORITHMS[0]);
  const [keyStrength, setKeyStrength] = useState(EFS_KEY_STRENGTHS[0]);
  const [ccsa, setCcsa] = useState<SelectProps.Option | null>(null);
  const [sanType, setSanType] = useState<SelectProps.Option>(SAN_TYPES[0]);
  const [sanValue, setSanValue] = useState("");
  const [sans, setSans] = useState<string[]>([]);
  const [keyUsage, setKeyUsage] = useState<readonly MultiselectProps.Option[]>([]);
  const [eku, setEku] = useState<readonly MultiselectProps.Option[]>([]);
  const [error, setError] = useState<string | null>(null);

  const isEfs = profile.value === "efs";

  const mutation = useMutation({
    mutationFn: () =>
      portalApi.submitApplication(mode, {
        csr_pem: csr.trim(),
        profile: profile.value,
        notification_email: email.trim(),
        issm_email: issmEmail.trim() || null,
        pm_email: pmEmail.trim() || null,
        ccsa: ccsa?.value ?? null,
        subject_alt_names: sans,
        key_usage: keyUsage.map((o) => o.value),
        extended_key_usage: eku.map((o) => o.value),
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

  const isEmail = (v: string) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.trim());
  const emailValid = isEmail(email);
  // ISSM/PM addresses are optional, but must be well-formed if provided.
  const issmValid = !issmEmail.trim() || isEmail(issmEmail);
  const pmValid = !pmEmail.trim() || isEmail(pmEmail);
  const csrValid = csr.trim().includes(CSR_MARKER);
  // A complete PEM block (both markers) is worth parsing for the CN/SAN preview;
  // an in-progress paste is not.
  const csrComplete =
    !isEfs && csr.includes(CSR_MARKER) && csr.includes(CSR_END_MARKER);
  const csrPreview = useQuery({
    queryKey: ["parse-csr", csr.trim()],
    queryFn: () => portalApi.parseCsr(csr.trim()),
    enabled: csrComplete,
    retry: false,
    staleTime: Infinity,
  });
  const pending = mutation.isPending || efsMutation.isPending;
  const canSubmit =
    (isEfs ? emailValid : csrValid && emailValid) && issmValid && pmValid && !pending;
  const isServerAuth = SERVER_AUTH_PROFILES.has(profile.value);

  // Editing any field after a submission clears the stale success/result banner
  // so it can never appear to describe the current (edited) input.
  function clearStale() {
    if (mutation.data || mutation.isError) mutation.reset();
    if (efsMutation.data || efsMutation.isError) efsMutation.reset();
    if (error) setError(null);
  }

  function addSan() {
    const value = sanValue.trim();
    if (!value) return;
    const token = `${sanType.value}:${value}`;
    if (!sans.includes(token)) setSans([...sans, token]);
    setSanValue("");
    clearStale();
  }

  // A dropped/chosen CSR file populates the same textarea, so paste and file
  // upload share one code path (preview, validation, submit).
  async function onCsrFile(files: File[]) {
    setCsrFiles(files);
    const file = files[0];
    if (!file) return;
    try {
      const text = await file.text();
      clearStale();
      setCsr(text);
    } catch {
      setError("Could not read the selected file.");
    }
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
              <FormField
                label="ISSM email address"
                description="Information System Security Manager — also notified before this certificate expires."
                errorText={issmValid ? undefined : "Enter a valid email address."}
              >
                <Input
                  value={issmEmail}
                  onChange={(e) => {
                    clearStale();
                    setIssmEmail(e.detail.value);
                  }}
                  type="email"
                  placeholder="issm@example.mil"
                />
              </FormField>
              <FormField
                label="PM email address"
                description="Program Manager — also notified before this certificate expires."
                errorText={pmValid ? undefined : "Enter a valid email address."}
              >
                <Input
                  value={pmEmail}
                  onChange={(e) => {
                    clearStale();
                    setPmEmail(e.detail.value);
                  }}
                  type="email"
                  placeholder="pm@example.mil"
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
              <FormField
                label="CC/S/A"
                description="Combatant Command, Service, or Agency this certificate belongs to."
              >
                <Select
                  selectedOption={ccsa}
                  onChange={(e) => {
                    clearStale();
                    setCcsa(e.detail.selectedOption);
                  }}
                  options={CCSA_OPTIONS}
                  filteringType="auto"
                  placeholder="Select CC/S/A"
                  empty="No matches"
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
                <>
                <FormField
                  label="Certificate request (PKCS #10 PEM)"
                  description="Paste the PEM-encoded CSR generated on the device. Its Common Name and Subject Alternative Names are shown below."
                  errorText={csr && !csrValid ? "Not a PEM certificate request." : undefined}
                >
                  <SpaceBetween size="s">
                    <FileUpload
                      value={csrFiles}
                      onChange={({ detail }) => onCsrFile(detail.value)}
                      accept=".csr,.pem,.req,.txt,application/x-pem-file"
                      constraintText="Drop or choose a .csr, .pem, or .req file, or paste the PEM below."
                      showFileSize
                      showFileLastModified={false}
                      i18nStrings={{
                        uploadButtonText: () => "Choose CSR file",
                        dropzoneText: () => "Drop CSR file to upload",
                        removeFileAriaLabel: (i) => `Remove file ${i + 1}`,
                        limitShowFewer: "Show fewer files",
                        limitShowMore: "Show more files",
                        errorIconAriaLabel: "Error",
                      }}
                    />
                    <Textarea
                      value={csr}
                      onChange={(e) => {
                        clearStale();
                        setCsr(e.detail.value);
                        if (csrFiles.length > 0) setCsrFiles([]);
                      }}
                      rows={10}
                      placeholder={CSR_MARKER}
                    />
                    {csrComplete && (
                      <Box>
                        {csrPreview.isFetching && (
                          <Box color="text-status-inactive">Reading request…</Box>
                        )}
                        {csrPreview.data && (
                          <ColumnLayout columns={2} variant="text-grid">
                            <div>
                              <Box variant="awsui-key-label">Common Name (CN)</Box>
                              <div>{csrPreview.data.commonName ?? "—"}</div>
                            </div>
                            <div>
                              <Box variant="awsui-key-label">
                                Subject Alternative Names
                              </Box>
                              <div>
                                {csrPreview.data.sans.length > 0 ? (
                                  <SpaceBetween size="xxs">
                                    {csrPreview.data.sans.map((san) => (
                                      <div key={san}>{san}</div>
                                    ))}
                                  </SpaceBetween>
                                ) : (
                                  "—"
                                )}
                              </div>
                            </div>
                          </ColumnLayout>
                        )}
                        {csrPreview.isError && (
                          <Box color="text-status-warning">
                            Could not read the CN/SANs from this request.
                          </Box>
                        )}
                      </Box>
                    )}
                  </SpaceBetween>
                </FormField>
                <FormField
                  label="Subject Alternative Names"
                  description="Add one or more SANs to request, in addition to any already in the CSR."
                >
                  <SpaceBetween size="xs">
                    <Grid gridDefinition={[{ colspan: 3 }, { colspan: 7 }, { colspan: 2 }]}>
                      <Select
                        selectedOption={sanType}
                        onChange={(e) => setSanType(e.detail.selectedOption)}
                        options={SAN_TYPES}
                        ariaLabel="SAN type"
                      />
                      <Input
                        value={sanValue}
                        onChange={(e) => setSanValue(e.detail.value)}
                        onKeyDown={(e) => {
                          if (e.detail.key === "Enter") {
                            addSan();
                          }
                        }}
                        placeholder={sanPlaceholder(sanType.value)}
                      />
                      <Button onClick={addSan} disabled={!sanValue.trim()}>
                        Add
                      </Button>
                    </Grid>
                    {sans.length > 0 && (
                      <TokenGroup
                        items={sans.map((s) => ({ label: s, dismissLabel: `Remove ${s}` }))}
                        onDismiss={({ detail }) =>
                          setSans(sans.filter((_, i) => i !== detail.itemIndex))
                        }
                      />
                    )}
                  </SpaceBetween>
                </FormField>
                <FormField
                  label="Key usage"
                  description="Key usages to request for the certificate."
                >
                  <Multiselect
                    selectedOptions={keyUsage}
                    onChange={(e) => {
                      clearStale();
                      setKeyUsage(e.detail.selectedOptions);
                    }}
                    options={KEY_USAGE_OPTIONS}
                    placeholder="Select key usages"
                  />
                </FormField>
                <FormField
                  label="Extended key usage"
                  description="Extended key usages (EKUs) to request for the certificate."
                >
                  <Multiselect
                    selectedOptions={eku}
                    onChange={(e) => {
                      clearStale();
                      setEku(e.detail.selectedOptions);
                    }}
                    options={EKU_OPTIONS}
                    placeholder="Select extended key usages"
                  />
                </FormField>
                </>
              )}
            </SpaceBetween>
          </Form>
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
