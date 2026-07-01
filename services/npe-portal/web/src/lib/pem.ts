// Shared PEM / DER / hex helpers, so the CSR generator, certificate downloads,
// and the OCSP checker don't each re-implement (subtly differently) the
// armor-strip + base64 conversion.

/** Decode standard base64 to DER bytes. */
export function base64ToDer(b64: string): ArrayBuffer {
  const clean = b64.replace(/\s+/g, "");
  const bin = atob(clean);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

/**
 * Extract the DER of the FIRST PEM block of `label` (default CERTIFICATE). Only
 * the first block is taken, so pasting a full chain (leaf + intermediates)
 * reliably yields the leaf rather than concatenating every cert into one blob.
 * Falls back to treating the whole input as bare base64 when no armor is found.
 */
export function firstPemBlockToDer(pem: string, label = "CERTIFICATE"): ArrayBuffer {
  const re = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`);
  const match = re.exec(pem);
  const body = match ? match[1] : pem;
  return base64ToDer(body);
}

/** Wrap DER bytes as a PEM block (64-char lines). */
export function derToPem(der: ArrayBuffer, label: string): string {
  const bytes = new Uint8Array(der);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  const b64 = btoa(binary);
  const wrapped = b64.match(/.{1,64}/g)?.join("\n") ?? b64;
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----\n`;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Parse a hex string (any non-hex separators ignored) into bytes. */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
