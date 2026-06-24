import * as React from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  ColumnLayout,
  Container,
  ContentLayout,
  CopyToClipboard,
  Form,
  FormField,
  Header,
  Input,
  Link,
  Pagination,
  Select,
  type SelectProps,
  SpaceBetween,
  StatusIndicator,
  Table,
  TextFilter,
} from "@cloudscape-design/components";

import { api, ApiError } from "@/lib/api";

const TOKENS_URL = "/est/api/v1/est/enrollment-tokens";
const PAGE_SIZE = 10;

interface TokenSummary {
  id: string;
  identity: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  status: string;
}
interface MintTokenResponse {
  token: string;
  identity: string;
  expiresAt: string;
}

const TTL_OPTIONS: SelectProps.Option[] = [
  { label: "15 minutes", value: "900" },
  { label: "1 hour", value: "3600" },
  { label: "8 hours", value: "28800" },
  { label: "24 hours", value: "86400" },
];
const PROFILE_OPTIONS: SelectProps.Option[] = [
  { label: "TLS client (clientAuth)", value: "tls_client" },
  { label: "TLS server (serverAuth)", value: "tls_server" },
  { label: "TLS server + client", value: "tls_server_client" },
];
const STATUS_OPTIONS: SelectProps.Option[] = [
  { label: "All statuses", value: "" },
  { label: "live", value: "live" },
  { label: "used", value: "used" },
  { label: "revoked", value: "revoked" },
  { label: "expired", value: "expired" },
];

function tokenStatus(status: string) {
  switch (status) {
    case "live":
      return <StatusIndicator type="success">live</StatusIndicator>;
    case "revoked":
      return <StatusIndicator type="error">revoked</StatusIndicator>;
    case "used":
      return <StatusIndicator type="stopped">used</StatusIndicator>;
    default:
      return <StatusIndicator type="warning">expired</StatusIndicator>;
  }
}

function HealthBadge() {
  const { data, isLoading } = useQuery({
    queryKey: ["est-health"],
    queryFn: async () => {
      await api.get("/est/health");
      return true;
    },
    retry: false,
  });
  if (isLoading) return <StatusIndicator type="loading">Checking</StatusIndicator>;
  return data ? (
    <StatusIndicator type="success">Online</StatusIndicator>
  ) : (
    <StatusIndicator type="error">Unreachable</StatusIndicator>
  );
}

function MintForm() {
  const qc = useQueryClient();
  const [identity, setIdentity] = React.useState("");
  const [ttl, setTtl] = React.useState<SelectProps.Option>(TTL_OPTIONS[1]);
  const [profile, setProfile] = React.useState<SelectProps.Option>(
    PROFILE_OPTIONS[0],
  );
  const [result, setResult] = React.useState<MintTokenResponse | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const mint = useMutation({
    mutationFn: () =>
      api.post<MintTokenResponse>(TOKENS_URL, {
        identity: identity.trim(),
        ttlSeconds: Number(ttl.value),
        profile: profile.value,
      }),
    onSuccess: (r) => {
      setResult(r);
      setError(null);
      void qc.invalidateQueries({ queryKey: ["est-tokens"] });
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Failed to mint token"),
  });

  const curl = result
    ? `curl -k https://est.oopl.dev.mil/.well-known/est/simpleenroll \\\n  -H "Authorization: Bearer ${result.token}" \\\n  -H "Content-Type: application/pkcs10" \\\n  --data-binary @device.csr.b64`
    : "";

  return (
    <Container header={<Header variant="h2">Generate enrollment token</Header>}>
      <SpaceBetween size="l">
        <Form
          actions={
            <Button
              variant="primary"
              loading={mint.isPending}
              onClick={() => {
                if (!identity.trim()) {
                  setError("Enter the device identity (certificate CN).");
                  return;
                }
                setResult(null);
                mint.mutate();
              }}
            >
              Generate token
            </Button>
          }
        >
          <ColumnLayout columns={2}>
            <FormField label="Device identity (CN)">
              <Input
                value={identity}
                placeholder="device-01.example.com"
                onChange={({ detail }) => setIdentity(detail.value)}
              />
            </FormField>
            <FormField label="Valid for">
              <Select
                selectedOption={ttl}
                options={TTL_OPTIONS}
                onChange={({ detail }) => setTtl(detail.selectedOption)}
              />
            </FormField>
            <FormField label="Certificate profile">
              <Select
                selectedOption={profile}
                options={PROFILE_OPTIONS}
                onChange={({ detail }) => setProfile(detail.selectedOption)}
              />
            </FormField>
          </ColumnLayout>
        </Form>

        {error && <Alert type="error">{error}</Alert>}

        {result && (
          <SpaceBetween size="s">
            <Alert type="warning">
              Copy this token now — it is shown only once.
            </Alert>
            <FormField
              label={`Token for ${result.identity} (expires ${result.expiresAt})`}
            >
              <CopyToClipboard
                variant="inline"
                textToCopy={result.token}
                copyButtonText="Copy"
                copySuccessText="Copied"
                copyErrorText="Copy failed"
              />
            </FormField>
            <FormField label="Enroll the device with">
              <Box variant="code">
                <SpaceBetween size="xs">
                  <CopyToClipboard
                    variant="button"
                    textToCopy={curl}
                    copyButtonText="Copy command"
                    copySuccessText="Copied"
                    copyErrorText="Copy failed"
                  />
                  <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{curl}</pre>
                </SpaceBetween>
              </Box>
            </FormField>
          </SpaceBetween>
        )}
      </SpaceBetween>
    </Container>
  );
}

function OutstandingTokens() {
  const qc = useQueryClient();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["est-tokens"],
    queryFn: () => api.get<{ tokens: TokenSummary[] }>(TOKENS_URL),
  });
  const tokens = data?.tokens ?? [];

  const [filterText, setFilterText] = React.useState("");
  const [statusOpt, setStatusOpt] = React.useState<SelectProps.Option>(
    STATUS_OPTIONS[0],
  );
  const [pageIndex, setPageIndex] = React.useState(0);

  const [revokeError, setRevokeError] = React.useState<string | null>(null);
  const revoke = useMutation({
    mutationFn: (id: string) => api.del(`${TOKENS_URL}/${id}`),
    onSuccess: () => {
      setRevokeError(null);
      void qc.invalidateQueries({ queryKey: ["est-tokens"] });
    },
    onError: (e) =>
      setRevokeError(e instanceof ApiError ? e.message : "Failed to revoke"),
  });

  const ft = filterText.trim().toLowerCase();
  const filtered = tokens.filter(
    (t) =>
      (!ft ||
        t.identity.toLowerCase().includes(ft) ||
        t.createdBy.toLowerCase().includes(ft)) &&
      (!statusOpt.value || t.status === statusOpt.value),
  );
  const pagesCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const cur = Math.min(pageIndex, pagesCount - 1);
  const pageItems = filtered.slice(cur * PAGE_SIZE, cur * PAGE_SIZE + PAGE_SIZE);

  return (
    <SpaceBetween size="s">
      {revokeError && <Alert type="error">{revokeError}</Alert>}
      <Table<TokenSummary>
        variant="container"
        loading={isLoading}
        loadingText="Loading tokens"
        items={pageItems}
        trackBy="id"
        empty={
          <Box textAlign="center" color="inherit">
            {isError ? "Failed to load tokens." : "No enrollment tokens minted yet."}
          </Box>
        }
        columnDefinitions={[
          { id: "identity", header: "Identity", cell: (t) => t.identity },
          { id: "createdBy", header: "Created by", cell: (t) => t.createdBy },
          {
            id: "expiresAt",
            header: "Expires",
            cell: (t) => <Box fontSize="body-s">{t.expiresAt}</Box>,
          },
          { id: "status", header: "Status", cell: (t) => tokenStatus(t.status) },
          {
            id: "actions",
            header: "",
            cell: (t) =>
              t.status === "live" ? (
                <Link
                  variant="secondary"
                  onFollow={() => revoke.mutate(t.id)}
                >
                  Revoke
                </Link>
              ) : null,
          },
        ]}
        filter={
          <SpaceBetween direction="horizontal" size="xs">
            <TextFilter
              filteringText={filterText}
              filteringPlaceholder="Filter identity / creator"
              onChange={({ detail }) => {
                setFilterText(detail.filteringText);
                setPageIndex(0);
              }}
            />
            <Select
              selectedOption={statusOpt}
              options={STATUS_OPTIONS}
              onChange={({ detail }) => {
                setStatusOpt(detail.selectedOption);
                setPageIndex(0);
              }}
            />
          </SpaceBetween>
        }
        pagination={
          <Pagination
            currentPageIndex={cur + 1}
            pagesCount={pagesCount}
            onChange={({ detail }) => setPageIndex(detail.currentPageIndex - 1)}
          />
        }
        header={
          <Header counter={`(${filtered.length})`}>Outstanding tokens</Header>
        }
      />
    </SpaceBetween>
  );
}

export function EstPage() {
  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Enrollment over Secure Transport (RFC 7030)."
          actions={<HealthBadge />}
        >
          EST Enrollment
        </Header>
      }
    >
      <SpaceBetween size="l">
        <MintForm />
        <OutstandingTokens />
      </SpaceBetween>
    </ContentLayout>
  );
}
