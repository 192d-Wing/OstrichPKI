import { type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { CopyButton } from "@/components/copy-button";
import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  fetchCertificateDetail,
  type CertificateDetails,
  type CertificateStatus,
} from "@/lib/ca";

function statusBadge(status: CertificateStatus) {
  const variant =
    status === "active"
      ? "success"
      : status === "revoked"
        ? "destructive"
        : status === "expired"
          ? "warning"
          : "secondary";
  return <Badge variant={variant}>{status}</Badge>;
}

function Row({ label, value, mono }: { label: string; value?: ReactNode; mono?: boolean }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "break-all"}>
        {value ?? "—"}
      </dd>
    </>
  );
}

function Tags({ items }: { items: string[] }) {
  if (items.length === 0) return <span className="text-muted-foreground">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((i) => (
        <Badge key={i} variant="secondary">
          {i}
        </Badge>
      ))}
    </div>
  );
}

function DetailBody({ c }: { c: CertificateDetails }) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Overview</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-2 text-sm">
            <Row label="Subject" value={c.subjectDn} mono />
            <Row label="Issuer" value={c.issuerDn} mono />
            <Row label="Serial" value={c.serialNumber} mono />
            <Row label="Version" value={`v${c.version}`} />
            <Row label="Status" value={statusBadge(c.status)} />
            <Row label="Valid from" value={c.validFrom} mono />
            <Row label="Valid to" value={c.validTo} mono />
            <Row
              label="Days remaining"
              value={c.daysRemaining != null ? String(c.daysRemaining) : "—"}
            />
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Key & signature</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-2 text-sm">
            <Row label="Key algorithm" value={`${c.keyAlgorithm} (${c.keySize})`} />
            <Row label="Signature" value={c.signatureAlgorithm} />
            <Row label="SHA-256" value={c.fingerprintSha256} mono />
            <Row label="SHA-1" value={c.fingerprintSha1} mono />
            <Row label="Authority key id" value={c.authorityKeyId ?? undefined} mono />
            <Row label="Subject key id" value={c.subjectKeyId ?? undefined} mono />
            <Row label="Key usage" value={<Tags items={c.keyUsage} />} />
            <Row label="Extended key usage" value={<Tags items={c.extendedKeyUsage} />} />
            <Row
              label="Subject alt names"
              value={<Tags items={c.subjectAltNames.map((s) => `${s.nameType}:${s.value}`)} />}
            />
            <Row label="CRL distribution" value={<Tags items={c.crlDistributionPoints} />} />
            <Row label="OCSP" value={<Tags items={c.ocspResponderUrls} />} />
          </dl>
        </CardContent>
      </Card>

      {c.status === "revoked" && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg text-destructive">Revocation</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-2 text-sm">
              <Row label="Revoked at" value={c.revocationTime ?? undefined} mono />
              <Row label="Reason" value={c.revocationReason ?? undefined} />
            </dl>
          </CardContent>
        </Card>
      )}

      {c.extensions.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Extensions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {c.extensions.map((e) => (
              <div key={e.oid} className="rounded-md border p-2 text-sm">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{e.name}</span>
                  <span className="font-mono text-xs text-muted-foreground">
                    {e.oid}
                  </span>
                  {e.critical && <Badge variant="warning">critical</Badge>}
                </div>
                <p className="mt-1 break-all font-mono text-xs text-muted-foreground">
                  {e.value}
                </p>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-lg">PEM</CardTitle>
          <CopyButton value={c.pem} />
        </CardHeader>
        <CardContent>
          <pre className="max-h-72 overflow-auto rounded-md bg-muted p-3 text-xs">
            {c.pem}
          </pre>
        </CardContent>
      </Card>
    </div>
  );
}

export function CertificateDetailPage() {
  const { id = "" } = useParams();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["certificate", id],
    queryFn: () => fetchCertificateDetail(id),
  });

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">
      <PageHeader
        title="Certificate"
        actions={
          <Button asChild variant="outline" size="sm">
            <Link to="/certificates">Back to list</Link>
          </Button>
        }
      />

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : isError || !data ? (
        <p className="text-sm text-destructive">
          Failed to load this certificate.
        </p>
      ) : (
        <DetailBody c={data} />
      )}
    </div>
  );
}
