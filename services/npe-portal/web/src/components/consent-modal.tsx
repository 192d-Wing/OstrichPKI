import { useState } from "react";
import { Box, Button, Modal, SpaceBetween } from "@cloudscape-design/components";

import { acceptConsent } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";

// Mandatory USG Access Consent window (NPE portal requirements §1). Intercepts the user
// immediately after the mTLS handshake; the session cannot reach any API until
// OK is clicked. NIST 800-53: AC-8 (System Use Notification).
const CONSENT_TEXT = `You are accessing a U.S. Government (USG) Information System (IS) that is \
provided for USG-authorized use only. By using this IS (which includes any device attached to \
this IS), you consent to the following conditions:

- The USG routinely intercepts and monitors communications on this IS for purposes including, but \
not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel \
misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
- At any time, the USG may inspect and seize data stored on this IS.
- Communications using, or data stored on, this IS are not private, are subject to routine \
monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
- This IS includes security measures (e.g., authentication and access controls) to protect USG \
interests -- not for your personal benefit or privacy.`;

export function ConsentModal() {
  const { refresh } = useAuth();
  const [submitting, setSubmitting] = useState(false);

  async function onAccept() {
    setSubmitting(true);
    try {
      await acceptConsent();
      refresh();
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal
      visible
      header="U.S. Government Access Consent"
      closeAriaLabel="Consent required"
      footer={
        <Box float="right">
          <Button variant="primary" loading={submitting} onClick={onAccept}>
            OK
          </Button>
        </Box>
      }
    >
      <SpaceBetween size="m">
        {CONSENT_TEXT.split("\n\n").map((para) => (
          <Box key={para.slice(0, 40)} variant="p">
            {para}
          </Box>
        ))}
      </SpaceBetween>
    </Modal>
  );
}
