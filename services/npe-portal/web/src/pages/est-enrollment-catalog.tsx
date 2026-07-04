import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
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
  Link,
  Select,
  type SelectProps,
  SpaceBetween,
  Spinner,
  Table,
  type TableProps,
} from "@cloudscape-design/components";

import { config } from "@/lib/config";
import {
  portalApi,
  type EstCatalog,
  type EstCatalogKeyAlgo,
  type EstCatalogProfile,
} from "@/lib/portal-api";

// Best-guess EST base URL from the current host (npe.<domain> -> est.<domain>),
// used only when the deployment doesn't supply config.estBaseUrl. The field is
// editable on the page so an operator can correct a wrong guess.
function defaultEstUrl(): string {
  if (config.estBaseUrl) return config.estBaseUrl;
  const host = globalThis.location?.hostname ?? "";
  const parts = host.split(".");
  // Only swap when it looks like sub.domain.tld (>=3 labels, not an IP).
  if (parts.length >= 3 && !/^\d+$/.test(parts[parts.length - 1])) {
    parts[0] = "est";
    return `https://${parts.join(".")}`;
  }
  return "https://est.example.mil";
}

const NONE_OPTION: SelectProps.Option = { label: "(default)", value: "" };

type AuthMode = "token" | "mtls";

const PROFILE_COLUMNS: TableProps.ColumnDefinition<EstCatalogProfile>[] = [
  { id: "token", header: "Label (PT)", cell: (p) => <Box variant="code">PT{p.token}</Box> },
  { id: "display", header: "Profile", cell: (p) => p.display },
  { id: "desc", header: "Description", cell: (p) => p.description },
  { id: "issuable", header: "Issuable", cell: (p) => (p.issuable ? "Yes" : "Reserved") },
];

const KEY_ALGO_COLUMNS: TableProps.ColumnDefinition<EstCatalogKeyAlgo>[] = [
  { id: "token", header: "Token (AK)", cell: (a) => <Box variant="code">AK{a.token}</Box> },
  { id: "display", header: "Algorithm", cell: (a) => a.display },
  { id: "desc", header: "Description", cell: (a) => a.description },
];

const AUTH_OPTIONS: SelectProps.Option[] = [
  { label: "Enrollment password (bearer)", value: "token" },
  { label: "Client certificate (mTLS)", value: "mtls" },
];

/** Build the openssl/curl enrollment command for a non-serverkeygen profile. */
function buildCommand(estUrl: string, path: string, authMode: AuthMode): string {
  const base = estUrl.replace(/\/+$/, "");
  const authLine =
    authMode === "token"
      ? '  -H "Authorization: Bearer $EST_TOKEN" \\'
      : "  --cert client.crt --key client.key \\";
  const authNote =
    authMode === "token"
      ? "# Mint an enrollment password under Password Management, then:\n# export EST_TOKEN=<password>\n"
      : "# Authenticate with your issued client certificate (mTLS).\n";
  return (
    `# 1) Generate a key + CSR (or use the in-browser generator on the Submit form):\n` +
    `openssl req -new -newkey rsa:2048 -nodes \\\n` +
    `  -keyout device.key -out request.csr -subj "/CN=device01.example.mil"\n\n` +
    `# 2) Enroll.\n` +
    authNote +
    `curl ${base}${path} \\\n` +
    authLine +
    `\n  -H "Content-Type: application/pkcs10" \\\n` +
    `  --data-binary @request.csr \\\n` +
    `  -o cert.p7\n\n` +
    `# 3) Convert the PKCS#7 response to PEM.\n` +
    `openssl pkcs7 -inform DER -in cert.p7 -print_certs -out cert.pem`
  );
}

export function EstEnrollmentCatalogPage() {
  const navigate = useNavigate();
  const catalogQuery = useQuery({
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

  if (catalogQuery.isLoading) {
    return (
      <Box padding="xxl" textAlign="center">
        <Spinner size="large" />
      </Box>
    );
  }
  if (catalogQuery.isError || !catalogQuery.data) {
    return (
      <ContentLayout header={<Header variant="h1">EST / Enrollment Catalog</Header>}>
        <Alert type="error" header="Failed to load the enrollment catalog">
          {(catalogQuery.error as Error)?.message ?? "The catalog could not be loaded."}
        </Alert>
      </ContentLayout>
    );
  }

  // `cat` is non-null past the guards above.
  const cat: EstCatalog = catalogQuery.data;
  const labeled = cat.labeledEnrollment;
  const issuable = cat.profiles.filter((p) => p.issuable);
  const selectedProfile =
    issuable.find((p) => p.token === profileTok) ?? issuable[0];

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
        <Container
          header={
            <Header
              variant="h2"
              description={
                labeled
                  ? "The issuing CA depends on the selected key algorithm."
                  : undefined
              }
            >
              Issuing certificate authority
            </Header>
          }
        >
          <KeyValuePairs
            columns={3}
            items={[
              { label: "CA", value: caInfo.data?.ca_dn ?? "—" },
              { label: "Key type", value: caInfo.data?.key_type ?? "—" },
              { label: "Signature algorithm", value: caInfo.data?.signature_algorithm ?? "—" },
            ]}
          />
        </Container>

        {labeled ? (
          <LabelBuilder
            cat={cat}
            issuable={issuable}
            selectedProfile={selectedProfile}
            profileTok={profileTok}
            setProfileTok={setProfileTok}
            algoTok={algoTok}
            setAlgoTok={setAlgoTok}
            validity={validity}
            setValidity={setValidity}
            ccsa={ccsa}
            setCcsa={setCcsa}
            authMode={authMode}
            setAuthMode={setAuthMode}
            estUrl={estUrl}
            setEstUrl={setEstUrl}
            onMintToken={() => navigate("/passwords/single-use")}
          />
        ) : (
          <UnlabeledEnroll
            cat={cat}
            authMode={authMode}
            setAuthMode={setAuthMode}
            estUrl={estUrl}
            setEstUrl={setEstUrl}
            onMintToken={() => navigate("/passwords/single-use")}
          />
        )}

        <Container header={<Header variant="h2" description={cat.labelFormat}>Profiles</Header>}>
          <Table<EstCatalogProfile>
            variant="embedded"
            items={cat.profiles}
            columnDefinitions={PROFILE_COLUMNS}
          />
        </Container>

        {cat.keyAlgorithms.length > 0 && (
          <Container header={<Header variant="h2">Key algorithms</Header>}>
            <Table<EstCatalogKeyAlgo>
              variant="embedded"
              items={cat.keyAlgorithms}
              columnDefinitions={KEY_ALGO_COLUMNS}
            />
          </Container>
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}

interface SharedProps {
  cat: EstCatalog;
  authMode: AuthMode;
  setAuthMode: (m: AuthMode) => void;
  estUrl: string;
  setEstUrl: (s: string) => void;
  onMintToken: () => void;
}

function AuthFields({
  authMode,
  setAuthMode,
  estUrl,
  setEstUrl,
}: Readonly<Pick<SharedProps, "authMode" | "setAuthMode" | "estUrl" | "setEstUrl">>) {
  return (
    <>
      <FormField label="Authentication">
        <Select
          selectedOption={AUTH_OPTIONS.find((o) => o.value === authMode) ?? AUTH_OPTIONS[0]}
          onChange={(e) => setAuthMode(e.detail.selectedOption.value as AuthMode)}
          options={AUTH_OPTIONS}
        />
      </FormField>
      <FormField label="EST server URL" description="Edit if your EST host differs.">
        <Input value={estUrl} onChange={(e) => setEstUrl(e.detail.value)} />
      </FormField>
    </>
  );
}

function TokenHint({ authMode, onMintToken }: Readonly<{ authMode: AuthMode; onMintToken: () => void }>) {
  if (authMode !== "token") return null;
  return (
    <Box color="text-status-info">
      Need a password?{" "}
      <Link onFollow={onMintToken}>Generate an enrollment password</Link> under Password
      Management, then set <Box variant="code" display="inline">EST_TOKEN</Box>.
    </Box>
  );
}

function CommandField({ command }: Readonly<{ command: string }>) {
  return (
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
  );
}

/** EFS is delivered via server-side keygen as a one-time PKCS#12, which is a
 *  portal flow — not a raw EST curl. Point the user at it instead of emitting a
 *  command that doesn't match the server contract. */
function EfsNotice() {
  return (
    <Alert type="info" header="EFS uses server-side key generation">
      The EFS profile generates the key on the server and delivers it as a one-time, password-
      protected PKCS#12. Request it from <strong>Submit Application</strong> with the EFS profile —
      the key, certificate, and one-time password are returned in your browser (no CSR or curl
      needed).
    </Alert>
  );
}

function UnlabeledEnroll(props: Readonly<SharedProps>) {
  const { cat, authMode, setAuthMode, estUrl, setEstUrl, onMintToken } = props;
  const command = useMemo(
    () => buildCommand(estUrl, "/.well-known/est/simpleenroll", authMode),
    [estUrl, authMode],
  );
  return (
    <Container
      header={
        <Header variant="h2" description="Enrollment uses this deployment's default profile.">
          Enroll a certificate
        </Header>
      }
    >
      <SpaceBetween size="m">
        <Alert type="info">
          Label-routed profile selection is not enabled on this deployment. Enrollment issues the
          default profile <Box variant="code" display="inline">{cat.defaultProfile}</Box> from the
          unlabeled EST endpoint.
        </Alert>
        <ColumnLayout columns={2}>
          <AuthFields authMode={authMode} setAuthMode={setAuthMode} estUrl={estUrl} setEstUrl={setEstUrl} />
        </ColumnLayout>
        <TokenHint authMode={authMode} onMintToken={onMintToken} />
        <CommandField command={command} />
      </SpaceBetween>
    </Container>
  );
}

interface LabelBuilderProps extends SharedProps {
  issuable: EstCatalogProfile[];
  selectedProfile: EstCatalogProfile | undefined;
  profileTok: string | null;
  setProfileTok: (s: string | null) => void;
  algoTok: string;
  setAlgoTok: (s: string) => void;
  validity: string;
  setValidity: (s: string) => void;
  ccsa: string;
  setCcsa: (s: string) => void;
}

function LabelBuilder(props: Readonly<LabelBuilderProps>) {
  const {
    cat,
    issuable,
    selectedProfile,
    setProfileTok,
    algoTok,
    setAlgoTok,
    validity,
    setValidity,
    ccsa,
    setCcsa,
    authMode,
    setAuthMode,
    estUrl,
    setEstUrl,
    onMintToken,
  } = props;

  const profileOptions = useMemo<SelectProps.Option[]>(
    () => issuable.map((p) => ({ label: `${p.display} (PT${p.token})`, value: p.token })),
    [issuable],
  );
  const algoOptions = useMemo<SelectProps.Option[]>(
    () => [
      NONE_OPTION,
      ...cat.keyAlgorithms.map((a) => ({ label: `${a.display} (AK${a.token})`, value: a.token })),
    ],
    [cat.keyAlgorithms],
  );

  const isEfs = selectedProfile?.serverKeygen ?? false;

  // Assemble the label, mirroring the PT/AK/VP/CC scheme. Constraints (max
  // validity, AK suppression for server-keygen) come from the catalog payload.
  const label = useMemo(() => {
    const p = selectedProfile;
    if (!p) return "";
    let l = `PT${p.token}`;
    if (algoTok && !p.serverKeygen) l += `-AK${algoTok}`;
    const days = Number(validity);
    if (validity && days >= 1 && days <= cat.maxValidityDays) l += `-VP${days}`;
    if (ccsa.trim()) l += `-CC${ccsa.trim()}`;
    return l;
  }, [selectedProfile, algoTok, validity, ccsa, cat.maxValidityDays]);

  const command = useMemo(
    () => buildCommand(estUrl, `/.well-known/est/${label}/simpleenroll`, authMode),
    [estUrl, label, authMode],
  );

  function onValidity(raw: string) {
    const digits = raw.replace(/[^\d]/g, "");
    if (!digits) return setValidity("");
    setValidity(String(Math.min(Number(digits), cat.maxValidityDays)));
  }

  return (
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
              selectedOption={AUTH_OPTIONS.find((o) => o.value === authMode) ?? AUTH_OPTIONS[0]}
              onChange={(e) => setAuthMode(e.detail.selectedOption.value as AuthMode)}
              options={AUTH_OPTIONS}
            />
          </FormField>
          <FormField
            label="Key algorithm"
            description={
              isEfs ? "EFS pins the key to server-side RSA-2048." : "Selects the issuing CA backend."
            }
          >
            <Select
              selectedOption={algoOptions.find((o) => o.value === algoTok) ?? NONE_OPTION}
              onChange={(e) => setAlgoTok(e.detail.selectedOption.value ?? "")}
              options={algoOptions}
              disabled={isEfs}
            />
          </FormField>
          <FormField label="Validity (days)" description={`Optional; up to ${cat.maxValidityDays}.`}>
            <Input
              value={validity}
              onChange={(e) => onValidity(e.detail.value)}
              placeholder="e.g. 397"
              inputMode="numeric"
            />
          </FormField>
          <FormField label="CC/S/A code" description="Optional DoD organizational code.">
            <Input
              value={ccsa}
              onChange={(e) =>
                setCcsa(e.detail.value.replace(/[^A-Za-z0-9]/g, "").slice(0, cat.maxCcsaLen))
              }
              placeholder="e.g. USAF"
            />
          </FormField>
          <AuthFields authMode={authMode} setAuthMode={setAuthMode} estUrl={estUrl} setEstUrl={setEstUrl} />
        </ColumnLayout>

        <FormField label="EST label">
          <SpaceBetween direction="horizontal" size="xs">
            <Box variant="code" fontSize="heading-s">{label}</Box>
            <CopyToClipboard
              copyButtonText="Copy"
              copyErrorText="Failed to copy"
              copySuccessText="Copied"
              textToCopy={label}
              variant="inline"
            />
          </SpaceBetween>
        </FormField>

        {isEfs ? (
          <EfsNotice />
        ) : (
          <>
            <TokenHint authMode={authMode} onMintToken={onMintToken} />
            <CommandField command={command} />
          </>
        )}
      </SpaceBetween>
    </Container>
  );
}
