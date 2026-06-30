// Shared browser-download helpers. Centralized so every download (PEM chain,
// PKCS#12 bundle, etc.) uses one correct anchor-click + object-URL-revocation
// implementation rather than re-deriving it per page.

/** Save a Blob to the user's machine via a synthetic anchor click. */
export function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  // The anchor must be in the DOM for a synthetic click to trigger a download
  // in some browsers; revoke the object URL only after the click is dispatched.
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** Save raw text (PEM, etc.) as a download. */
export function downloadText(text: string, filename: string, mimeType: string) {
  triggerDownload(new Blob([text], { type: mimeType }), filename);
}

/**
 * Save a PEM certificate's raw DER bytes as a binary download. Strips the PEM
 * armor (`-----BEGIN/END …-----`) and whitespace, leaving the base64 DER body.
 */
export function downloadPemAsDer(pem: string, filename: string) {
  const body = pem
    .replace(/-----BEGIN[^-]+-----/g, "")
    .replace(/-----END[^-]+-----/g, "")
    .replace(/\s+/g, "");
  downloadBase64(body, filename, "application/pkix-cert");
}

/** Decode standard base64 into bytes and save them as a binary download. */
export function downloadBase64(base64: string, filename: string, mimeType: string) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  // atob yields a binary string whose chars are all 0-255 (no surrogate pairs),
  // so codePointAt and charCodeAt are equivalent here — both give the raw byte.
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.codePointAt(i) ?? 0;
  triggerDownload(new Blob([bytes], { type: mimeType }), filename);
}
