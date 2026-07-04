// Helpers for working with X.500 / RFC 4514 Distinguished Names on the client.

/**
 * Extract the Common Name (CN) from an RFC 4514 subject DN, falling back to the
 * full DN when there is no CN. Handles backslash-escaped characters in the value
 * (e.g. `CN=Doe\, John,O=Acme` → `Doe, John`) so an escaped comma doesn't
 * truncate the name.
 */
export function commonName(subjectDn: string): string {
  // Match `CN=` then a value made of escaped pairs (\X) or any char that isn't
  // an unescaped comma/backslash — i.e. stop at the first UNescaped comma.
  const match = /CN=((?:\\.|[^,\\])*)/i.exec(subjectDn);
  if (!match) return subjectDn;
  // Unescape `\X` → `X` (RFC 4514 §2.4).
  return match[1].replace(/\\(.)/g, "$1").trim();
}
