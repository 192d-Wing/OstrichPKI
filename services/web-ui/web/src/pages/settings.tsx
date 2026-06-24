import { useQuery } from "@tanstack/react-query";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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

function ServiceHealth({ name, svc }: { name: string; svc: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["service-health", svc],
    queryFn: () => serviceUp(svc),
    retry: false,
  });
  return (
    <div className="flex items-center justify-between rounded-md border px-3 py-2">
      <span className="text-sm">{name}</span>
      {isLoading ? (
        <Badge variant="secondary">…</Badge>
      ) : data ? (
        <Badge variant="success">Up</Badge>
      ) : (
        <Badge variant="destructive">Down</Badge>
      )}
    </div>
  );
}

export function SettingsPage() {
  const { data: ca, isLoading, isError } = useQuery({
    queryKey: ["ca-info"],
    queryFn: fetchCaInfo,
  });

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">
      <PageHeader
        title="System"
        description="Certificate authority identity and live service status."
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Certificate Authority</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : isError || !ca ? (
            <p className="text-sm text-destructive">Failed to load CA info.</p>
          ) : (
            <dl className="grid grid-cols-[8rem_1fr] gap-x-4 gap-y-2 text-sm">
              <dt className="text-muted-foreground">CA ID</dt>
              <dd className="font-mono text-xs">{ca.ca_id}</dd>
              <dt className="text-muted-foreground">Distinguished name</dt>
              <dd className="font-mono text-xs">{ca.ca_dn}</dd>
            </dl>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Services</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
            {SERVICES.map((s) => (
              <ServiceHealth key={s.svc} name={s.name} svc={s.svc} />
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="rounded-md border bg-muted/40 px-4 py-3 text-sm text-muted-foreground">
        Policy and configuration (password policy, MFA, CRL cadence, CA
        parameters) are managed via service configuration and are read-only
        here.
      </div>

      <p className="text-center text-xs text-muted-foreground">
        OstrichPKI Web UI v{config.version}
      </p>
    </div>
  );
}
