import * as React from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { CopyButton } from "@/components/copy-button";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ApiError } from "@/lib/api";
import {
  fetchProfiles,
  issueCertificate,
  pemToCsrB64,
  type IssueResponse,
} from "@/lib/ca";

export function CertificateIssuePage() {
  const { data: profilesData } = useQuery({
    queryKey: ["profiles"],
    queryFn: fetchProfiles,
  });
  const profiles = React.useMemo(
    () => profilesData?.profiles ?? [],
    [profilesData],
  );

  const [profile, setProfile] = React.useState("");
  const [csr, setCsr] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);

  // Default to the first profile once loaded.
  React.useEffect(() => {
    if (!profile && profiles.length > 0) setProfile(profiles[0].profile_type);
  }, [profiles, profile]);

  const issue = useMutation({
    mutationFn: (): Promise<IssueResponse> =>
      issueCertificate(profile, pemToCsrB64(csr)),
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Issuance failed"),
  });

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!pemToCsrB64(csr)) {
      setError("Paste a PEM-encoded certificate request (CSR).");
      return;
    }
    issue.reset();
    issue.mutate();
  }

  const r = issue.data;

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-6">
      <PageHeader
        title="Issue Certificate"
        description="Paste a PKCS#10 CSR and choose a profile; the CA derives the subject, key, and SANs from the request."
        actions={
          <Button asChild variant="outline" size="sm">
            <Link to="/certificates">Back to list</Link>
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Request</CardTitle>
          <CardDescription>RFC 7030 / RFC 2986 PKCS#10.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label>Profile</Label>
              <Select value={profile} onValueChange={setProfile}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a profile" />
                </SelectTrigger>
                <SelectContent>
                  {profiles.map((p) => (
                    <SelectItem key={p.name} value={p.profile_type}>
                      {p.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="csr">Certificate request (PEM)</Label>
              <Textarea
                id="csr"
                value={csr}
                onChange={(e) => setCsr(e.target.value)}
                placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;…&#10;-----END CERTIFICATE REQUEST-----"
                className="min-h-[180px] font-mono text-xs"
              />
            </div>
            {error && (
              <div className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {error}
              </div>
            )}
            <Button type="submit" disabled={issue.isPending || !profile}>
              {issue.isPending ? "Issuing…" : "Issue certificate"}
            </Button>
          </form>
        </CardContent>
      </Card>

      {r && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Issued</CardTitle>
            <CardDescription>
              Serial {r.serial_number} · valid {r.not_before} → {r.not_after}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>Certificate (PEM)</Label>
              <CopyButton value={r.pem_encoded} />
            </div>
            <pre className="max-h-72 overflow-auto rounded-md bg-muted p-3 text-xs">
              {r.pem_encoded}
            </pre>
            <Button asChild variant="outline" size="sm">
              <Link to={`/certificates/${r.certificate_id}`}>View details</Link>
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
