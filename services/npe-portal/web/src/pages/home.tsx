import {
  Container,
  ContentLayout,
  Header,
  KeyValuePairs,
  SpaceBetween,
} from "@cloudscape-design/components";

import { primaryRole, roleLabel } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";

export function HomePage() {
  const { user } = useAuth();
  const role = primaryRole(user);

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Non-Person Entity certificate enrollment portal">
          Welcome
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Your identity</Header>}>
          <KeyValuePairs
            columns={3}
            items={[
              { label: "Common Name", value: user?.commonName ?? "-" },
              { label: "Role", value: roleLabel(role) },
              { label: "Subject DN", value: user?.subjectDn ?? "-" },
            ]}
          />
        </Container>
        <Container header={<Header variant="h2">Getting started</Header>}>
          Use the navigation menu to submit certificate applications, manage EST enrollment
          passwords, or search your records. Available menus depend on your certificate role.
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
