import { ApplicationForm } from "@/pages/application-form";

export function SubmitApplicationPage() {
  return (
    <ApplicationForm
      mode="issuance"
      title="Submit Certificate Application"
      description="Submit a PKCS #10 CSR for a new certificate."
    />
  );
}
