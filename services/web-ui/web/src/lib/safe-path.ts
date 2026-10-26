// Same-origin path guard for client-side navigation targets that are not
// compile-time literals (Cloudscape `onFollow` hrefs, server-derived paths).
//
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation); supports SI-2 (defence
//   in depth for GHSA-wrjc-x8rr-h8h6, remediated by react-router >= 7.18)
// - CWE-601 (Open Redirect)

// One leading "/", not followed by "/" or "\" (protocol-relative `//evil`,
// `/\evil`). Rejects absolute URLs and schemes (`https:`, `javascript:`) because
// they do not start with "/".
const LEADING = /^\/(?![\\/])/;
// Backslashes anywhere (browsers treat "\" as "/" in special-scheme URLs) and
// C0 control / DEL characters (the URL parser strips \t \n \r, so `/\t/evil`
// would otherwise collapse to `//evil`).
// eslint-disable-next-line no-control-regex
const FORBIDDEN = /[\\\u0000-\u001f\u007f]/;
// Empty segments (`//` anywhere) and `.` / `..` segments: they resolve
// same-origin today, but `/..//evil` normalises to a `//evil` pathname.
const BAD_SEGMENT = /\/\/|(^|\/)\.{1,2}(\/|$)/;
// Fixed, unroutable base so the origin check does not depend on `window`.
const PROBE_ORIGIN = "https://ostrich.invalid";

/** True if `p` is a same-origin absolute path safe to hand to `navigate()`. */
export function isSafeInternalPath(p: string): boolean {
  if (typeof p !== "string" || !LEADING.test(p) || FORBIDDEN.test(p) || BAD_SEGMENT.test(p)) {
    return false;
  }
  // Belt and braces: the WHATWG URL parser must agree it stays same-origin.
  try {
    return new URL(p, PROBE_ORIGIN).origin === PROBE_ORIGIN;
  } catch {
    return false;
  }
}

/** `p` if it passes {@link isSafeInternalPath}, otherwise `fallback`. */
export function safeInternalPath(p: string, fallback = "/dashboard"): string {
  return isSafeInternalPath(p) ? p : fallback;
}
