import { useEffect, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Container,
  ContentLayout,
  CopyToClipboard,
  Form,
  FormField,
  Header,
  Input,
  KeyValuePairs,
  SpaceBetween,
} from "@cloudscape-design/components";

import { portalApi } from "@/lib/portal-api";

const MAX_USES_CAP = 1000;

export function PasswordManagementPage({ multi }: Readonly<{ multi: boolean }>) {
  const [identity, setIdentity] = useState("");
  const [maxUses, setMaxUses] = useState("5");
  const [show, setShow] = useState(false);
  const [pendingPrint, setPendingPrint] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Print is the credential handout, so it must contain the real token, not the
  // masked dots. Reveal first (setShow), then print on the next render.
  useEffect(() => {
    if (pendingPrint && show) {
      globalThis.print();
      setPendingPrint(false);
    }
  }, [pendingPrint, show]);

  const mutation = useMutation({
    mutationFn: () => portalApi.mintToken(identity.trim(), multi ? Number(maxUses) : 1),
    onSuccess: () => {
      setError(null);
      setShow(false);
    },
    onError: (e: Error) => setError(e.message),
  });

  const usesValid = !multi || (Number.isInteger(Number(maxUses)) && Number(maxUses) >= 2 && Number(maxUses) <= MAX_USES_CAP);
  const canSubmit = identity.trim().length > 0 && usesValid && !mutation.isPending;

  function generate() {
    if (!identity.trim()) {
      setError("Enter the device identity (CN) the password is bound to.");
      return;
    }
    if (!usesValid) {
      setError(`Enter a use count between 2 and ${MAX_USES_CAP}.`);
      return;
    }
    mutation.mutate();
  }

  const result = mutation.data;
  const title = multi ? "Generate Multi-Use Token" : "Generate Single-Use Token";
  const description = multi
    ? "Mint an EST enrollment password several devices may enroll with (8-hour expiry)."
    : "Mint a single-use EST enrollment password (8-hour expiry).";

  return (
    <ContentLayout header={<Header variant="h1" description={description}>{title}</Header>}>
      <SpaceBetween size="l">
        {error && (
          <Alert type="error" header="Generation failed">
            {error}
          </Alert>
        )}

        {result ? (
          <Container header={<Header variant="h2">Enrollment password generated</Header>}>
            <SpaceBetween size="m">
              <Alert type="warning">
                Copy this password now. It cannot be retrieved again once you leave this page.
              </Alert>
              <FormField label="Enrollment password">
                <SpaceBetween direction="horizontal" size="xs">
                  <Box variant="code">{show ? result.token : "•".repeat(32)}</Box>
                  <CopyToClipboard
                    copyButtonText="Copy"
                    copyErrorText="Failed to copy"
                    copySuccessText="Copied"
                    textToCopy={result.token}
                    variant="inline"
                  />
                </SpaceBetween>
              </FormField>
              {/* Show is available ONLY immediately after generation; it is gone
                  once the user navigates away (the token lives only in state). */}
              <Checkbox checked={show} onChange={(e) => setShow(e.detail.checked)}>
                Show password
              </Checkbox>
              <KeyValuePairs
                columns={3}
                items={[
                  { label: "Bound identity", value: result.identity },
                  { label: "Uses", value: String(result.maxUses) },
                  {
                    label: "Expires",
                    value: result.expiresAt,
                  },
                ]}
              />
              <Button
                iconName="file"
                onClick={() => {
                  setShow(true);
                  setPendingPrint(true);
                }}
              >
                Print
              </Button>
            </SpaceBetween>
          </Container>
        ) : (
          <Container>
            <Form
              actions={
                <Button variant="primary" onClick={generate} loading={mutation.isPending} disabled={!canSubmit}>
                  Generate
                </Button>
              }
            >
              <SpaceBetween size="l">
                <FormField
                  label="Device identity (CN)"
                  description="The certificate identity each enrolling device must present (H1 binding)."
                >
                  <Input
                    value={identity}
                    onChange={(e) => setIdentity(e.detail.value)}
                    placeholder="device-01.example.mil"
                  />
                </FormField>
                {multi && (
                  <FormField
                    label="Number of devices"
                    description={`How many devices may enroll with this password (2–${MAX_USES_CAP}).`}
                    errorText={usesValid ? undefined : `Enter a number between 2 and ${MAX_USES_CAP}.`}
                  >
                    <Input
                      value={maxUses}
                      onChange={(e) => setMaxUses(e.detail.value)}
                      type="number"
                      inputMode="numeric"
                    />
                  </FormField>
                )}
              </SpaceBetween>
            </Form>
          </Container>
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}
