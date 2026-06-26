import { StatusIndicator } from "@cloudscape-design/components";

// Map an application status to a Cloudscape status indicator.
export function StatusBadge({ status }: Readonly<{ status: string }>) {
  switch (status) {
    case "approved":
    case "completed":
    case "issued":
      return <StatusIndicator type="success">{status}</StatusIndicator>;
    case "rejected":
    case "expired":
      return <StatusIndicator type="error">{status}</StatusIndicator>;
    case "pending":
      return <StatusIndicator type="pending">{status}</StatusIndicator>;
    default:
      return <StatusIndicator type="info">{status}</StatusIndicator>;
  }
}
