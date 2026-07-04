import { Container, ContentLayout, Header, SpaceBetween } from "@cloudscape-design/components";

// Shell placeholder for menu targets implemented in later milestones (M2-M5).
// The header `?` help target and form behaviors are added per page as built.
export function PlaceholderPage({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <ContentLayout header={<Header variant="h1" description={description}>{title}</Header>}>
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Coming soon</Header>}>
          This screen is part of the NPE Portal and will be implemented in a later milestone.
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
