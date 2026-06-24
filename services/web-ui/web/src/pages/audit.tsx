import * as React from "react";
import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import {
  Box,
  Button,
  CollectionPreferences,
  type CollectionPreferencesProps,
  ContentLayout,
  Header,
  Pagination,
  Select,
  type SelectProps,
  SpaceBetween,
  StatusIndicator,
  Table,
  type TableProps,
  TextFilter,
} from "@cloudscape-design/components";

import {
  AUDIT_EVENT_TYPES,
  fetchAuditLogs,
  verifyAudit,
  type AuditEvent,
} from "@/lib/audit";

const PAGE_SIZE_OPTIONS = [25, 50, 100].map((v) => ({ value: v, label: `${v}` }));

// Page size flows into the server query; column visibility is client-side.
const DEFAULT_PREFERENCES: CollectionPreferencesProps.Preferences = {
  pageSize: 25,
  contentDisplay: [
    { id: "timestamp", visible: true },
    { id: "eventType", visible: true },
    { id: "actor", visible: true },
    { id: "target", visible: true },
    { id: "action", visible: true },
    { id: "outcome", visible: true },
    { id: "signed", visible: true },
  ],
};

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
  const [preferences, setPreferences] =
    React.useState<CollectionPreferencesProps.Preferences>(DEFAULT_PREFERENCES);
  const [sortingColumn, setSortingColumn] =
    React.useState<TableProps.SortingColumn<AuditEvent>>();
  const [sortingDescending, setSortingDescending] = React.useState(true);
  const eventType = eventOpt.value ?? "";
  const outcome = outcomeOpt.value ?? "";
  const pageSize = preferences.pageSize ?? 25;
  const sortField = sortingColumn?.sortingField;

  const query = new URLSearchParams();
  query.set("page", String(pageIndex + 1));
  query.set("pageSize", String(pageSize));
  if (eventType) query.set("eventType", eventType);
  if (actor.trim()) query.set("actor", actor.trim());
  if (outcome) query.set("outcome", outcome);
  if (sortField) {
    query.set("sort", sortField);
    query.set("order", sortingDescending ? "desc" : "asc");
  }

  const { data, isFetching, isError } = useQuery({
    queryKey: [
      "audit",
      pageIndex,
      pageSize,
      eventType,
      actor.trim(),
      outcome,
      sortField ?? "",
      sortingDescending,
    ],
    queryFn: () => fetchAuditLogs(query.toString()),
    placeholderData: keepPreviousData,
  });

  const total = data?.total ?? 0;
  const pagesCount = Math.max(1, Math.ceil(total / pageSize));
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
        resizableColumns
        stickyHeader
        columnDisplay={preferences.contentDisplay}
        sortingColumn={sortingColumn}
        sortingDescending={sortingDescending}
        onSortingChange={({ detail }) => {
          setSortingColumn(detail.sortingColumn);
          setSortingDescending(detail.isDescending ?? true);
          setPageIndex(0);
        }}
        empty={
          <Box textAlign="center" color="inherit">
            {isError ? "Failed to load the audit log." : "No audit events."}
          </Box>
        }
        columnDefinitions={[
          {
            id: "timestamp",
            header: "Timestamp",
            sortingField: "timestamp",
            cell: (e) => <Box fontSize="body-s">{e.timestamp}</Box>,
          },
          {
            id: "eventType",
            header: "Event",
            sortingField: "eventType",
            cell: (e) => <Box fontSize="body-s">{e.eventType}</Box>,
          },
          { id: "actor", header: "Actor", sortingField: "actor", cell: (e) => e.actor },
          { id: "target", header: "Target", sortingField: "target", cell: (e) => e.target },
          { id: "action", header: "Action", sortingField: "action", cell: (e) => e.action },
          {
            id: "outcome",
            header: "Outcome",
            sortingField: "outcome",
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
        preferences={
          <CollectionPreferences
            title="Preferences"
            confirmLabel="Confirm"
            cancelLabel="Cancel"
            preferences={preferences}
            pageSizePreference={{ title: "Page size", options: PAGE_SIZE_OPTIONS }}
            contentDisplayPreference={{
              title: "Column visibility",
              options: [
                { id: "timestamp", label: "Timestamp", alwaysVisible: true },
                { id: "eventType", label: "Event" },
                { id: "actor", label: "Actor" },
                { id: "target", label: "Target" },
                { id: "action", label: "Action" },
                { id: "outcome", label: "Outcome" },
                { id: "signed", label: "Signed" },
              ],
            }}
            onConfirm={({ detail }) => {
              setPreferences(detail);
              setPageIndex(0);
            }}
          />
        }
        header={<Header counter={`(${total})`}>Events</Header>}
      />
    </ContentLayout>
  );
}
