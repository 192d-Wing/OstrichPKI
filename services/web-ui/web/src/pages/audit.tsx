import * as React from "react";
import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import {
  Box,
  Button,
  ContentLayout,
  Header,
  Pagination,
  Select,
  type SelectProps,
  SpaceBetween,
  StatusIndicator,
  Table,
  TextFilter,
} from "@cloudscape-design/components";

import {
  AUDIT_EVENT_TYPES,
  fetchAuditLogs,
  verifyAudit,
  type AuditEvent,
} from "@/lib/audit";

const PAGE_SIZE = 25;

const EVENT_OPTIONS: SelectProps.Option[] = [
  { label: "All events", value: "" },
  ...AUDIT_EVENT_TYPES,
];
const OUTCOME_OPTIONS: SelectProps.Option[] = [
  { label: "Any outcome", value: "" },
  { label: "Success", value: "success" },
  { label: "Failure", value: "failure" },
];

function IntegrityButton() {
  const verify = useMutation({ mutationFn: verifyAudit });
  const r = verify.data;
  return (
    <SpaceBetween direction="horizontal" size="s" alignItems="center">
      {r &&
        (r.intact ? (
          <StatusIndicator type="success">
            Intact — {r.signedRecords}/{r.totalRecords} signed
          </StatusIndicator>
        ) : (
          <StatusIndicator type="error">Integrity check failed</StatusIndicator>
        ))}
      {verify.isError && (
        <StatusIndicator type="error">Verification failed</StatusIndicator>
      )}
      <Button loading={verify.isPending} onClick={() => verify.mutate()}>
        Verify integrity
      </Button>
    </SpaceBetween>
  );
}

export function AuditPage() {
  const [pageIndex, setPageIndex] = React.useState(0);
  const [actor, setActor] = React.useState("");
  const [eventOpt, setEventOpt] = React.useState<SelectProps.Option>(
    EVENT_OPTIONS[0],
  );
  const [outcomeOpt, setOutcomeOpt] = React.useState<SelectProps.Option>(
    OUTCOME_OPTIONS[0],
  );
  const eventType = eventOpt.value ?? "";
  const outcome = outcomeOpt.value ?? "";

  const query = new URLSearchParams();
  query.set("page", String(pageIndex + 1));
  query.set("pageSize", String(PAGE_SIZE));
  if (eventType) query.set("eventType", eventType);
  if (actor.trim()) query.set("actor", actor.trim());
  if (outcome) query.set("outcome", outcome);

  const { data, isFetching, isError } = useQuery({
    queryKey: ["audit", pageIndex, eventType, actor.trim(), outcome],
    queryFn: () => fetchAuditLogs(query.toString()),
    placeholderData: keepPreviousData,
  });

  const total = data?.total ?? 0;
  const pagesCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const reset = () => setPageIndex(0);

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Security-relevant events (append-only, hash-chained)."
          actions={<IntegrityButton />}
        >
          Audit Logs
        </Header>
      }
    >
      <Table<AuditEvent>
        variant="container"
        loading={isFetching}
        loadingText="Loading audit log"
        items={data?.events ?? []}
        trackBy="id"
        empty={
          <Box textAlign="center" color="inherit">
            {isError ? "Failed to load the audit log." : "No audit events."}
          </Box>
        }
        columnDefinitions={[
          {
            id: "timestamp",
            header: "Timestamp",
            cell: (e) => <Box fontSize="body-s">{e.timestamp}</Box>,
          },
          {
            id: "eventType",
            header: "Event",
            cell: (e) => <Box fontSize="body-s">{e.eventType}</Box>,
          },
          { id: "actor", header: "Actor", cell: (e) => e.actor },
          { id: "target", header: "Target", cell: (e) => e.target },
          { id: "action", header: "Action", cell: (e) => e.action },
          {
            id: "outcome",
            header: "Outcome",
            cell: (e) =>
              e.outcome.toLowerCase() === "success" ? (
                <StatusIndicator type="success">{e.outcome}</StatusIndicator>
              ) : (
                <StatusIndicator type="error">
                  {e.outcome || "—"}
                </StatusIndicator>
              ),
          },
          {
            id: "signed",
            header: "Signed",
            cell: (e) =>
              e.signed ? (
                <StatusIndicator type="success">signed</StatusIndicator>
              ) : (
                "—"
              ),
          },
        ]}
        filter={
          <SpaceBetween direction="horizontal" size="xs">
            <Select
              selectedOption={eventOpt}
              options={EVENT_OPTIONS}
              onChange={({ detail }) => {
                setEventOpt(detail.selectedOption);
                reset();
              }}
            />
            <TextFilter
              filteringText={actor}
              filteringPlaceholder="Filter actor"
              onChange={({ detail }) => {
                setActor(detail.filteringText);
                reset();
              }}
            />
            <Select
              selectedOption={outcomeOpt}
              options={OUTCOME_OPTIONS}
              onChange={({ detail }) => {
                setOutcomeOpt(detail.selectedOption);
                reset();
              }}
            />
          </SpaceBetween>
        }
        pagination={
          <Pagination
            currentPageIndex={pageIndex + 1}
            pagesCount={pagesCount}
            onChange={({ detail }) => setPageIndex(detail.currentPageIndex - 1)}
          />
        }
        header={<Header counter={`(${total})`}>Events</Header>}
      />
    </ContentLayout>
  );
}
