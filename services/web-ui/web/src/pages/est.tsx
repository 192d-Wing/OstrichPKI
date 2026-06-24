import * as React from "react";
import { type ColumnDef } from "@tanstack/react-table";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";

import { DataTable, type DataTableFilter } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { CopyButton } from "@/components/copy-button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api, ApiError } from "@/lib/api";

const TOKENS_URL = "/est/api/v1/est/enrollment-tokens";

interface TokenSummary {
  id: string;
  identity: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  status: string; // live | used | revoked | expired
}

interface MintTokenResponse {
  token: string;
  identity: string;
  expiresAt: string;
}

function EstHealthBadge() {
  const { data, isLoading } = useQuery({
    queryKey: ["est-health"],
    queryFn: async () => {
      await api.get("/est/health");
      return true;
    },
    retry: false,
  });
  if (isLoading) return <Badge variant="secondary">Checking…</Badge>;
  return data ? (
    <Badge variant="success">Online</Badge>
  ) : (
    <Badge variant="destructive">Unreachable</Badge>
  );
}

function tokenStatusBadge(status: string) {
  switch (status) {
    case "live":
      return <Badge variant="success">live</Badge>;
    case "used":
      return <Badge variant="secondary">used</Badge>;
    case "revoked":
      return <Badge variant="destructive">revoked</Badge>;
    default:
      return <Badge variant="warning">expired</Badge>;
  }
}

function MintTokenForm() {
  const qc = useQueryClient();
  const [identity, setIdentity] = React.useState("");
  const [ttl, setTtl] = React.useState("3600");
  const [profile, setProfile] = React.useState("tls_client");
  const [result, setResult] = React.useState<MintTokenResponse | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const mint = useMutation({
    mutationFn: () =>
      api.post<MintTokenResponse>(TOKENS_URL, {
        identity: identity.trim(),
        ttlSeconds: Number(ttl),
        profile,
      }),
    onSuccess: (r) => {
      setResult(r);
      setError(null);
      void qc.invalidateQueries({ queryKey: ["est-tokens"] });
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Failed to mint token"),
  });

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!identity.trim()) {
      setError("Enter the device identity (certificate CN).");
      return;
    }
    setResult(null);
    mint.mutate();
  }

  const curl = result
    ? `curl -k https://est.oopl.dev.mil/.well-known/est/simpleenroll \\\n  -H "Authorization: Bearer ${result.token}" \\\n  -H "Content-Type: application/pkcs10" \\\n  --data-binary @device.csr.b64`
    : "";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Generate enrollment token</CardTitle>
        <CardDescription>
          Mint a single-use, time-limited bearer token for a device's initial
          EST enrollment. The device must enroll with a CSR whose Common Name
          equals the identity below.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="identity">Device identity (CN)</Label>
              <Input
                id="identity"
                placeholder="device-01.example.com"
                value={identity}
                onChange={(e) => setIdentity(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label>Valid for</Label>
              <Select value={ttl} onValueChange={setTtl}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="900">15 minutes</SelectItem>
                  <SelectItem value="3600">1 hour</SelectItem>
                  <SelectItem value="28800">8 hours</SelectItem>
                  <SelectItem value="86400">24 hours</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>Certificate profile</Label>
              <Select value={profile} onValueChange={setProfile}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="tls_client">
                    TLS client (clientAuth)
                  </SelectItem>
                  <SelectItem value="tls_server">
                    TLS server (serverAuth)
                  </SelectItem>
                  <SelectItem value="tls_server_client">
                    TLS server + client
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <Button type="submit" disabled={mint.isPending}>
            {mint.isPending ? "Generating…" : "Generate token"}
          </Button>
        </form>

        {error && (
          <div className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-3">
            <div className="rounded-md border border-yellow-300 bg-yellow-50 px-3 py-2 text-sm text-yellow-800">
              Copy this token now — it is shown only once and cannot be
              retrieved again.
            </div>
            <div className="space-y-1.5">
              <Label>
                Token for {result.identity} (expires {result.expiresAt})
              </Label>
              <div className="relative">
                <Input
                  readOnly
                  value={result.token}
                  className="pr-20 font-mono text-xs"
                  onClick={(e) => e.currentTarget.select()}
                />
                <div className="absolute inset-y-0 right-1.5 flex items-center">
                  <CopyButton value={result.token} />
                </div>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>Enroll the device with:</Label>
              <div className="relative">
                <pre className="overflow-x-auto whitespace-pre rounded-md bg-muted p-3 pr-20 text-xs">
                  {curl}
                </pre>
                <div className="absolute right-2 top-2">
                  <CopyButton value={curl} />
                </div>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function OutstandingTokens() {
  const qc = useQueryClient();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["est-tokens"],
    queryFn: () => api.get<{ tokens: TokenSummary[] }>(TOKENS_URL),
  });
  const tokens = data?.tokens ?? [];

  const [revokeError, setRevokeError] = React.useState<string | null>(null);
  const revoke = useMutation({
    mutationFn: (id: string) => api.del(`${TOKENS_URL}/${id}`),
    onSuccess: () => {
      setRevokeError(null);
      void qc.invalidateQueries({ queryKey: ["est-tokens"] });
    },
    onError: (e) =>
      setRevokeError(
        e instanceof ApiError ? e.message : "Failed to revoke token",
      ),
  });

  const columns: ColumnDef<TokenSummary>[] = [
    {
      accessorKey: "identity",
      header: "Identity",
      cell: ({ row }) => (
        <span className="font-mono">{row.original.identity}</span>
      ),
    },
    {
      accessorKey: "createdBy",
      header: "Created by",
      cell: ({ row }) => (
        <span className="text-muted-foreground">{row.original.createdBy}</span>
      ),
    },
    {
      accessorKey: "expiresAt",
      header: "Expires",
      cell: ({ row }) => (
        <span className="font-mono text-xs text-muted-foreground">
          {row.original.expiresAt}
        </span>
      ),
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ row }) => tokenStatusBadge(row.original.status),
      filterFn: (row, id, value) => row.getValue(id) === value,
    },
    {
      id: "actions",
      header: "",
      cell: ({ row }) =>
        row.original.status === "live" ? (
          <div className="text-right">
            <Button
              variant="link"
              size="sm"
              className="h-auto p-0 text-destructive"
              disabled={revoke.isPending && revoke.variables === row.original.id}
              onClick={() => revoke.mutate(row.original.id)}
            >
              Revoke
            </Button>
          </div>
        ) : null,
    },
  ];

  const filters: DataTableFilter[] = [
    { columnId: "identity", placeholder: "Filter identity…" },
    { columnId: "createdBy", placeholder: "Filter creator…" },
    {
      columnId: "status",
      placeholder: "All statuses",
      kind: "select",
      options: [
        { value: "live", label: "live" },
        { value: "used", label: "used" },
        { value: "revoked", label: "revoked" },
        { value: "expired", label: "expired" },
      ],
    },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Outstanding tokens</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {revokeError && (
          <div className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {revokeError}
          </div>
        )}
        <DataTable
          columns={columns}
          data={tokens}
          filters={filters}
          isLoading={isLoading}
          isError={isError}
          emptyMessage="No enrollment tokens minted yet."
          noMatchMessage="No tokens match the current filters."
          errorMessage="Failed to load tokens. Retry or check your session."
        />
      </CardContent>
    </Card>
  );
}

export function EstPage() {
  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">EST Enrollment</h1>
          <p className="text-sm text-muted-foreground">
            Enrollment over Secure Transport (RFC 7030).
          </p>
        </div>
        <EstHealthBadge />
      </div>
      <MintTokenForm />
      <OutstandingTokens />
    </div>
  );
}
