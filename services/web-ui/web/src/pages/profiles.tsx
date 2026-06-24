import { useQuery } from "@tanstack/react-query";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { fetchProfiles, type CertProfile } from "@/lib/ca";

function ProfileCard({ p }: { p: CertProfile }) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">{p.name}</CardTitle>
          {p.basic_constraints_ca && <Badge variant="warning">CA</Badge>}
        </div>
        {p.description && (
          <p className="text-sm text-muted-foreground">{p.description}</p>
        )}
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1">
          <dt className="text-muted-foreground">Type</dt>
          <dd className="font-mono text-xs">{p.profile_type}</dd>
          <dt className="text-muted-foreground">Validity</dt>
          <dd>{p.validity_days} days</dd>
          <dt className="text-muted-foreground">Key</dt>
          <dd className="font-mono text-xs">
            {p.key_type} / {p.algorithm}
          </dd>
          <dt className="text-muted-foreground">SAN required</dt>
          <dd>{p.subject_alt_name_required ? "yes" : "no"}</dd>
        </dl>
        {(p.key_usages?.length ?? 0) > 0 && (
          <div className="flex flex-wrap gap-1">
            {p.key_usages!.map((u) => (
              <Badge key={u} variant="secondary">
                {u}
              </Badge>
            ))}
          </div>
        )}
        {(p.extended_key_usages?.length ?? 0) > 0 && (
          <div className="flex flex-wrap gap-1">
            {p.extended_key_usages!.map((u) => (
              <Badge key={u} variant="outline">
                {u}
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function ProfilesPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["profiles"],
    queryFn: fetchProfiles,
  });
  const profiles = data?.profiles ?? [];

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Certificate Profiles</h1>
        <p className="text-sm text-muted-foreground">
          The CA's code-defined issuance profiles (read-only).
        </p>
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : isError ? (
        <p className="text-sm text-destructive">Failed to load profiles.</p>
      ) : profiles.length === 0 ? (
        <p className="text-sm text-muted-foreground">No profiles defined.</p>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {profiles.map((p) => (
            <ProfileCard key={p.name} p={p} />
          ))}
        </div>
      )}
    </div>
  );
}
