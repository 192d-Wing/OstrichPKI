import { useMutation } from "@tanstack/react-query";
import { Download } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
import { generateCrl } from "@/lib/ca";
import { useAuth } from "@/lib/auth-context";

function CrlCard({
  title,
  description,
  endpoint,
  downloadName,
  canGenerate,
}: {
  title: string;
  description: string;
  endpoint: string;
  downloadName: string;
  canGenerate: boolean;
}) {
  const gen = useMutation({ mutationFn: () => generateCrl(endpoint) });
  const r = gen.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {r && (
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 rounded-md border bg-muted/40 p-3 text-sm">
            <dt className="text-muted-foreground">CRL number</dt>
            <dd className="font-mono">{r.crl_number}</dd>
            <dt className="text-muted-foreground">This update</dt>
            <dd className="font-mono text-xs">{r.this_update}</dd>
            <dt className="text-muted-foreground">Next update</dt>
            <dd className="font-mono text-xs">{r.next_update}</dd>
            <dt className="text-muted-foreground">Revoked entries</dt>
            <dd>{r.revoked_count}</dd>
          </dl>
        )}
        {gen.isError && (
          <p className="text-sm text-destructive">
            {gen.error instanceof ApiError
              ? gen.error.message
              : "Generation failed."}
          </p>
        )}
        <div className="flex gap-2">
          {canGenerate && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => gen.mutate()}
              disabled={gen.isPending}
            >
              {gen.isPending ? "Generating…" : "Generate"}
            </Button>
          )}
          <Button asChild variant="outline" size="sm">
            <a href={`/api${endpoint}`} download={downloadName}>
              <Download className="size-4" />
              Download
            </a>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export function CrlPage() {
  const { can } = useAuth();
  const canGenerate = can("generate_crl");

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">
      <PageHeader
        title="Revocation Lists"
        description="Generate and download Certificate Revocation Lists (RFC 5280)."
      />

      {!canGenerate && (
        <div className="rounded-md border bg-muted/40 px-4 py-3 text-sm text-muted-foreground">
          You can download published CRLs. Generating one requires the
          Operations role.
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-2">
        <CrlCard
          title="Full CRL"
          description="A complete list of all revoked certificates."
          endpoint="/ca/api/v1/crl"
          downloadName="crl.crl"
          canGenerate={canGenerate}
        />
        <CrlCard
          title="Delta CRL"
          description="Only entries revoked since the last full CRL (RFC 5280 §5.2.4)."
          endpoint="/ca/api/v1/crl/delta"
          downloadName="delta.crl"
          canGenerate={canGenerate}
        />
      </div>
    </div>
  );
}
