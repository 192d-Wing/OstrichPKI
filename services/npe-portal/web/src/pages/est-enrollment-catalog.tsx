import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  ColumnLayout,
  Container,
  ContentLayout,
  CopyToClipboard,
  FormField,
  Header,
  Input,
  KeyValuePairs,
  Select,
  type SelectProps,
  SpaceBetween,
  Spinner,
  Table,
} from "@cloudscape-design/components";

import {
  portalApi,
  type EstCatalogKeyAlgo,
  type EstCatalogProfile,
} from "@/lib/portal-api";

// Best-guess EST base URL from the current host (npe.<domain> -> est.<domain>).
// Editable on the page, since EST is served on its own hostname.
function defaultEstUrl(): string {
  const host = globalThis.location?.hostname ?? "";
  const parts = host.split(".");
  if (parts.length >= 2 && host !== "localhost") {
    parts[0] = "est";
    return `https://${parts.join(".")}`;
  }
  return "https://est.example.mil";
}

const NONE_OPTION: SelectProps.Option = { label: "(default)", value: "" };

type AuthMode = "token" | "mtls";

export function EstEnrollmentCatalogPage() {
  const catalog = useQuery({
    queryKey: ["est-catalog"],
    queryFn: portalApi.estCatalog,
    retry: false,
    staleTime: 5 * 60_000,
  });
  const caInfo = useQuery({
    queryKey: ["ca-info"],
    queryFn: portalApi.caInfo,
    retry: false,
    staleTime: 5 * 60_000,
  });

  const [estUrl, setEstUrl] = useState(defaultEstUrl);
  const [profileTok, setProfileTok] = useState<string | null>(null);
  const [algoTok, setAlgoTok] = useState("");
  const [validity, setValidity] = useState("");
  const [ccsa, setCcsa] = useState("");
  const [authMode, setAuthMode] = useState<AuthMode>("token");

  const issuable = useMemo(
    () => catalog.data?.profiles.filter((p) => p.issuable) ?? [],
    [catalog.data],
  );

  // Default the builder to the first issuable profile once loaded.
  const selectedProfile: EstCatalogProfile | undefined =
    issuable.find((p) => p.token === profileTok) ?? issuable[0];

  const profileOptions: SelectProps.Option[] = issuable.map((p) => ({
    label: `${p.display} (PT${p.token})`,
    value: p.token,
  }));
  const algoOptions: SelectProps.Option[] = [
    NONE_OPTION,
    ...(catalog.data?.keyAlgorithms ?? []).map((a) => ({
      label: `${a.display} (AK${a.token})`,
      value: a.token,
    })),
  ];

  // Assemble the label from the builder, mirroring the PT/AK/VP/CC scheme.
  const label = useMemo(() => {
    const p = selectedProfile;
    if (!p) return "";
    let l = `PT${p.token}`;
    // EFS pins the key to server-side RSA-2048, so an AK token is meaningless.
    if (algoTok && !p.serverKeygen) l += `-AK${algoTok}`;
    if (/^\d+$/.test(validity.trim())) l += `-VP${validity.trim()}`;
    if (ccsa.trim()) l += `-CC${ccsa.trim()}`;
    return l;
  }, [selectedProfile, algoTok, validity, ccsa]);

  const command = useMemo(() => {
    const p = selectedProfile;
    if (!p) return "";
    const base = estUrl.replace(/\/+$/, "");
    const authLine =
      authMode === "token"
        ? '  -H "Authorization: Bearer $EST_TOKEN" \\'
        : "  --cert client.crt --key client.key \\";
    const authNote =
      authMode === "token"
        ? "# Mint an enrollment password first under Password Management, then:\n# export EST_TOKEN=<password>\n"
        : "# Authenticate with your issued client certificate (mTLS).\n";

    if (p.serverKeygen) {
      // EFS: the server generates the key; the response is an encrypted PKCS#12.
      return (
        `${authNote}` +
        `curl ${base}/.well-known/est/${label}/serverkeygen \\\n` +
        authLine +
        `\n  -H "Content-Type: application/pkcs10" \\\n` +
        `  --data-binary @request.csr \\\n` +
        `  -o keystore.p12`
      );
    }
    return (
      `# 1) Generate a key + CSR (or use the in-browser generator on the Submit form):\n` +
      `openssl req -new -newkey rsa:2048 -nodes \\\n` +
      `  -keyout device.key -out request.csr -subj "/CN=device01.example.mil"\n\n` +
      `# 2) Enroll against the label.\n` +
      authNote +
      `curl ${base}/.well-known/est/${label}/simpleenroll \\\n` +
      authLine +
      `\n  -H "Content-Type: application/pkcs10" \\\n` +
      `  --data-binary @request.csr \\\n` +
      `  -o cert.p7\n\n` +
      `# 3) Convert the PKCS#7 response to PEM.\n` +
      `openssl pkcs7 -inform DER -in cert.p7 -print_certs -out cert.pem`
    );
  }, [selectedProfile, estUrl, label, authMode]);

  const loading = catalog.isLoading;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Available certificate profiles and EST labels, with ready-to-run enrollment commands for device administrators."
        >
          EST / Enrollment Catalog
        </Header>
      }
    >
      <SpaceBetween size="l">
        {loading && <Spinner size="large" />}
        {catalog.isError && (
          <Alert type="error" header="Failed to load the enrollment catalog">
            {(catalog.error as Error).message}
          </Alert>
        )}

        {catalog.data && (
          <>
            <Container header={<Header variant="h2">Issuing certificate authority</Header>}>
              <KeyValuePairs
                columns={3}
                items={[
                  { label: "CA", value: caInfo.data?.ca_dn ?? "—" },
                  { label: "Key type", value: caInfo.data?.key_type ?? "—" },
                  {
                    label: "Signature algorithm",
                    value: caInfo.data?.signature_algorithm ?? "—",
                  },
                ]}
              />
            </Container>

            <Container
              header={
                <Header variant="h2" description="Pick a profile to build a label and command.">
                  Build an enrollment command
                </Header>
              }
            >
              <SpaceBetween size="m">
                <ColumnLayout columns={2}>
                  <FormField label="Profile">
                    <Select
                      selectedOption={
                        profileOptions.find((o) => o.value === selectedProfile?.token) ?? null
                      }
                      onChange={(e) => setProfileTok(e.detail.selectedOption.value ?? null)}
                      options={profileOptions}
                      placeholder="Select a profile"
                    />
                  </FormField>
                  <FormField label="Authentication">
                    <Select
                      selectedOption={
                        authMode === "token"
                          ? { label: "Enrollment password (bearer)", value: "token" }
                          : { label: "Client certificate (mTLS)", value: "mtls" }
                      }
                      onChange={(e) => setAuthMode(e.detail.selectedOption.value as AuthMode)}
                      options={[
                        { label: "Enrollment password (bearer)", value: "token" },
                        { label: "Client certificate (mTLS)", value: "mtls" },
                      ]}
                    />
                  </FormField>
                  <FormField
                    label="Key algorithm"
                    description={
                      selectedProfile?.serverKeygen
                        ? "EFS pins the key to server-side RSA-2048."
                        : "Selects the issuing CA backend."
                    }
                  >
                    <Select
                      selectedOption={algoOptions.find((o) => o.value === algoTok) ?? NONE_OPTION}
                      onChange={(e) => setAlgoTok(e.detail.selectedOption.value ?? "")}
                      options={algoOptions}
                      disabled={selectedProfile?.serverKeygen}
                    />
                  </FormField>
                  <FormField
                    label="Validity (days)"
                    description={`Optional; up to ${catalog.data.maxValidityDays}.`}
                  >
                    <Input
                      value={validity}
                      onChange={(e) => setValidity(e.detail.value.replace(/[^\d]/g, ""))}
                      placeholder="e.g. 397"
                      inputMode="numeric"
                    />
                  </FormField>
                  <FormField label="CC/S/A code" description="Optional DoD organizational code.">
                    <Input
                      value={ccsa}
                      onChange={(e) =>
                        setCcsa(e.detail.value.replace(/[^A-Za-z0-9]/g, "").slice(0, catalog.data!.maxCcsaLen))
                      }
                      placeholder="e.g. USAF"
                    />
                  </FormField>
                  <FormField label="EST server URL" description="Edit if your EST host differs.">
                    <Input value={estUrl} onChange={(e) => setEstUrl(e.detail.value)} />
                  </FormField>
                </ColumnLayout>

                <FormField label="EST label">
                  <SpaceBetween direction="horizontal" size="xs">
                    <Box variant="code" fontSize="heading-s">
                      {label}
                    </Box>
                    <CopyToClipboard
                      copyButtonText="Copy"
                      copyErrorText="Failed to copy"
                      copySuccessText="Copied"
                      textToCopy={label}
                      variant="inline"
                    />
                  </SpaceBetween>
                </FormField>

                <FormField
                  label="Enrollment command"
                  secondaryControl={
                    <CopyToClipboard
                      copyButtonText="Copy"
                      copyErrorText="Failed to copy"
                      copySuccessText="Copied"
                      textToCopy={command}
                      variant="button"
                    />
                  }
                >
                  <Box variant="code">
                    <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{command}</pre>
                  </Box>
                </FormField>
              </SpaceBetween>
            </Container>

            <Container
              header={
                <Header variant="h2" description={catalog.data.labelFormat}>
                  Profiles
                </Header>
              }
            >
              <Table<EstCatalogProfile>
                variant="embedded"
                items={catalog.data.profiles}
                columnDefinitions={[
                  { id: "token", header: "Label (PT)", cell: (p) => <Box variant="code">PT{p.token}</Box> },
                  { id: "display", header: "Profile", cell: (p) => p.display },
                  { id: "desc", header: "Description", cell: (p) => p.description },
                  {
                    id: "issuable",
                    header: "Issuable",
                    cell: (p) => (p.issuable ? "Yes" : "Reserved"),
                  },
                ]}
              />
            </Container>

            <Container header={<Header variant="h2">Key algorithms</Header>}>
              <Table<EstCatalogKeyAlgo>
                variant="embedded"
                items={catalog.data.keyAlgorithms}
                columnDefinitions={[
                  { id: "token", header: "Token (AK)", cell: (a) => <Box variant="code">AK{a.token}</Box> },
                  { id: "display", header: "Algorithm", cell: (a) => a.display },
                  { id: "desc", header: "Description", cell: (a) => a.description },
                ]}
              />
            </Container>
          </>
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}
