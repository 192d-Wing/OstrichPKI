import { ApplicationForm } from "@/pages/application-form";

export function SubmitRekeyPage() {
  return (
    <ApplicationForm
      mode="renewal"
      title="Submit Certificate Rekey"
      description="Re-key an existing certificate with a new key pair."
    />
  );
}
