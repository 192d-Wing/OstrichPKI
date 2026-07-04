import { StatusIndicator } from "@cloudscape-design/components";

// Map an application status to a Cloudscape status indicator.
export function StatusBadge({ status }: Readonly<{ status: string }>) {
  switch (status) {
    case "approved":
    case "completed":
    case "issued":
    case "success": // audit-log outcome
      return <StatusIndicator type="success">{status}</StatusIndicator>;
    case "rejected":
    case "expired":
    case "revoked":
    case "failure": // audit-log outcomes: a failed/errored event must read red,
    case "error": //  not neutral, so an auditor can spot it at a glance.
      return <StatusIndicator type="error">{status}</StatusIndicator>;
    case "pending":
      return <StatusIndicator type="pending">{status}</StatusIndicator>;
    default:
      return <StatusIndicator type="info">{status}</StatusIndicator>;
  }
}
