import { useQuery } from "@tanstack/react-query";
import {
  Badge,
  Box,
  Cards,
  ContentLayout,
  Header,
  SpaceBetween,
} from "@cloudscape-design/components";

import { fetchProfiles, type CertProfile } from "@/lib/ca";

export function ProfilesPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["profiles"],
    queryFn: fetchProfiles,
  });
  const profiles = data?.profiles ?? [];

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={isLoading ? undefined : `(${profiles.length})`}
          description="The CA's code-defined issuance profiles (read-only)."
        >
          Certificate Profiles
        </Header>
      }
    >
      <Cards<CertProfile>
        items={profiles}
        loading={isLoading}
        loadingText="Loading profiles"
        trackBy="name"
        cardsPerRow={[{ cards: 1 }, { minWidth: 500, cards: 2 }, { minWidth: 900, cards: 3 }]}
        empty={
          <Box textAlign="center" color="inherit">
            {isError ? "Failed to load profiles." : "No profiles defined."}
          </Box>
        }
        cardDefinition={{
          header: (p) => (
            <SpaceBetween direction="horizontal" size="xs">
              <span>{p.name}</span>
              {p.basic_constraints_ca && <Badge color="severity-medium">CA</Badge>}
            </SpaceBetween>
          ),
          sections: [
            {
              id: "description",
              content: (p) =>
                p.description ? (
                  <Box color="text-body-secondary">{p.description}</Box>
                ) : null,
            },
            {
              id: "type",
              header: "Type",
              content: (p) => <Box fontSize="body-s">{p.profile_type}</Box>,
            },
            {
              id: "validity",
              header: "Validity",
              content: (p) => `${p.validity_days} days`,
            },
            {
              id: "key",
              header: "Key",
              content: (p) => (
                <Box fontSize="body-s">
                  {p.key_type} / {p.algorithm}
                </Box>
              ),
            },
            {
              id: "san",
              header: "SAN required",
              content: (p) => (p.subject_alt_name_required ? "yes" : "no"),
            },
            {
              id: "usages",
              content: (p) => (
                <SpaceBetween size="xxs">
                  {(p.key_usages?.length ?? 0) > 0 && (
                    <SpaceBetween direction="horizontal" size="xxs">
                      {p.key_usages!.map((u) => (
                        <Badge key={u}>{u}</Badge>
                      ))}
                    </SpaceBetween>
                  )}
                  {(p.extended_key_usages?.length ?? 0) > 0 && (
                    <SpaceBetween direction="horizontal" size="xxs">
                      {p.extended_key_usages!.map((u) => (
                        <Badge key={u} color="blue">
                          {u}
                        </Badge>
                      ))}
                    </SpaceBetween>
                  )}
                </SpaceBetween>
              ),
            },
          ],
        }}
      />
    </ContentLayout>
  );
}
