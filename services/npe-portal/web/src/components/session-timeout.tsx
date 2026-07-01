import { useEffect, useRef, useState } from "react";
import { Box, Button, Modal, SpaceBetween } from "@cloudscape-design/components";

import { config } from "@/lib/config";
import { fetchSession, logout } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";

// The server signs the user out after this much inactivity (NIAP FTA_SSL.1);
// warn a couple of minutes before, so a half-filled form isn't lost silently.
const IDLE_SECONDS = config.sessionIdleSeconds > 0 ? config.sessionIdleSeconds : 1800;
const WARN_SECONDS = Math.min(120, Math.max(30, Math.floor(IDLE_SECONDS / 4)));
const ACTIVITY_EVENTS = ["mousemove", "mousedown", "keydown", "scroll", "touchstart", "wheel"];

function mmss(total: number): string {
  const s = Math.max(0, total);
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}:${r.toString().padStart(2, "0")}`;
}

/**
 * Watches for user inactivity and, `WARN_SECONDS` before the server's idle
 * timeout, shows a modal with a live countdown. "Stay signed in" pings the
 * server (resetting its last-activity); ignoring it signs the user out.
 *
 * While the warning is open, passive activity does NOT extend the session — the
 * user must explicitly choose, so a stray mouse movement can't silently keep a
 * session alive without the server-side keepalive request.
 */
export function SessionTimeout() {
  const { refresh } = useAuth();
  const [open, setOpen] = useState(false);
  const [remaining, setRemaining] = useState(WARN_SECONDS);
  const lastActivity = useRef(Date.now());
  const openRef = useRef(false);
  const busy = useRef(false);

  async function stay() {
    if (busy.current) return;
    busy.current = true;
    try {
      await fetchSession(); // GET /auth/login refreshes the server session
    } finally {
      lastActivity.current = Date.now();
      openRef.current = false;
      setOpen(false);
      refresh();
      busy.current = false;
    }
  }

  async function signOut() {
    openRef.current = false;
    setOpen(false);
    await logout();
    refresh(); // clears the user → falls back to the identity screen
  }

  useEffect(() => {
    const onActivity = () => {
      if (!openRef.current) lastActivity.current = Date.now();
    };
    for (const e of ACTIVITY_EVENTS) {
      globalThis.addEventListener(e, onActivity, { passive: true });
    }
    const tick = globalThis.setInterval(() => {
      const idleFor = (Date.now() - lastActivity.current) / 1000;
      if (idleFor >= IDLE_SECONDS) {
        void signOut();
        return;
      }
      if (idleFor >= IDLE_SECONDS - WARN_SECONDS) {
        openRef.current = true;
        setOpen(true);
        setRemaining(Math.ceil(IDLE_SECONDS - idleFor));
      }
    }, 1000);
    return () => {
      for (const e of ACTIVITY_EVENTS) globalThis.removeEventListener(e, onActivity);
      globalThis.clearInterval(tick);
    };
    // Mount-once: handlers read refs, not stale state.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <Modal
      visible={open}
      onDismiss={() => void stay()}
      header="Session about to expire"
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            <Button onClick={() => void signOut()}>Sign out now</Button>
            <Button variant="primary" onClick={() => void stay()}>
              Stay signed in
            </Button>
          </SpaceBetween>
        </Box>
      }
    >
      For your security you will be signed out after {Math.round(IDLE_SECONDS / 60)} minutes of
      inactivity. You will be signed out in <strong>{mmss(remaining)}</strong> unless you continue.
    </Modal>
  );
}
