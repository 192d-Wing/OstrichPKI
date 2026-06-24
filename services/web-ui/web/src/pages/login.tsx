import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Container,
  Form,
  FormField,
  Header,
  Input,
  SpaceBetween,
} from "@cloudscape-design/components";

import { internalLogin, oidcLoginUrl, SessionLimitError } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";

export function LoginPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { isAuthenticated } = useAuth();
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);
  const [limitReached, setLimitReached] = React.useState(false);

  // If a session already exists, don't show the form.
  React.useEffect(() => {
    if (isAuthenticated) navigate("/", { replace: true });
  }, [isAuthenticated, navigate]);

  // `evict` resubmits the same (already-typed) credentials asking the server to
  // sign out the user's other sessions first — recovers from the session cap.
  async function attempt(evict: boolean) {
    setSubmitting(true);
    setError(null);
    try {
      await internalLogin(username.trim(), password, evict);
      // Re-probe the session BEFORE navigating so the route guard sees the new
      // identity and doesn't bounce back here.
      await qc.refetchQueries({ queryKey: ["userinfo"] });
      navigate("/", { replace: true });
    } catch (err) {
      if (err instanceof SessionLimitError) {
        setLimitReached(true);
      } else {
        setError(err instanceof Error ? err.message : "Login failed");
        setLimitReached(false);
      }
      setSubmitting(false);
    }
  }

  function onSubmit() {
    setLimitReached(false);
    void attempt(false);
  }

  return (
    <div
      style={{
        display: "flex",
        minHeight: "100vh",
        alignItems: "center",
        justifyContent: "center",
        padding: "1rem",
        background: "var(--color-background-layout-main, #f4f4f4)",
      }}
    >
      <div style={{ width: "100%", maxWidth: 380 }}>
        <Container
          header={
            <Header
              variant="h1"
              description="Sign in to the administration console."
            >
              OstrichPKI
            </Header>
          }
        >
          <SpaceBetween size="l">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                onSubmit();
              }}
            >
              <Form
                actions={
                  limitReached ? (
                    <Button
                      formAction="none"
                      loading={submitting}
                      onClick={() => void attempt(true)}
                    >
                      Sign out other sessions &amp; sign in
                    </Button>
                  ) : (
                    <Button variant="primary" loading={submitting}>
                      Sign in
                    </Button>
                  )
                }
              >
                <SpaceBetween size="m">
                  <FormField label="Username">
                    <Input
                      type="text"
                      autoComplete="username"
                      value={username}
                      onChange={({ detail }) => setUsername(detail.value)}
                      autoFocus
                    />
                  </FormField>
                  <FormField label="Password">
                    <Input
                      type="password"
                      autoComplete="current-password"
                      value={password}
                      onChange={({ detail }) => setPassword(detail.value)}
                    />
                  </FormField>
                  {error && <Alert type="error">{error}</Alert>}
                  {limitReached && (
                    <Alert type="warning">
                      Your account has reached its active-session limit. Sign out
                      your other sessions to continue.
                    </Alert>
                  )}
                </SpaceBetween>
              </Form>
            </form>

            <Box textAlign="center" color="text-status-inactive" fontSize="body-s">
              or
            </Box>
            <Button href={oidcLoginUrl()}>Sign in with SSO</Button>
          </SpaceBetween>
        </Container>
      </div>
    </div>
  );
}
