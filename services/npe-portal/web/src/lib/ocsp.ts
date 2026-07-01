// Live OCSP (RFC 6960) revocation-status check, performed in the browser and
// proxied through the BFF to the OCSP responder. pkijs builds the request and
// parses the signed response; it is lazily imported so it stays out of the main
// bundle (shared with the CSR generator's pkijs chunk).

export type OcspStatus = "good" | "revoked" | "unknown";

export interface OcspResult {
  status: OcspStatus;
  /** Hex serial of the certificate that was checked. */
  serial: string;
  producedAt?: string;
  thisUpdate?: string;
  nextUpdate?: string;
  /** Present when status is "revoked" (best-effort). */
  revocationTime?: string;
  revocationReason?: string;
}

// RFC 5280 §5.3.1 CRL reason codes, by their numeric value.
const REVOCATION_REASONS: Record<number, string> = {
  0: "Unspecified",
  1: "Key compromise",
  2: "CA compromise",
  3: "Affiliation changed",
  4: "Superseded",
  5: "Cessation of operation",
  6: "Certificate hold",
  8: "Remove from CRL",
  9: "Privilege withdrawn",
  10: "AA compromise",
};

function iso(d: Date | undefined): string | undefined {
  return d ? d.toISOString().replace("T", " ").slice(0, 19) + " UTC" : undefined;
}

/**
 * Query the OCSP responder for the revocation status of `certPem`, using
 * `issuerPem` (the issuing CA certificate) to build the RFC 6960 CertID.
 * Throws on a malformed input or a non-successful OCSP responseStatus.
 */
export async function checkOcsp(certPem: string, issuerPem: string): Promise<OcspResult> {
  const { Certificate, OCSPRequest, OCSPResponse, BasicOCSPResponse } = await import("pkijs");
  const asn1js = await import("asn1js");

  const cert = certFromPem(Certificate, asn1js, certPem, "certificate");
  const issuer = certFromPem(Certificate, asn1js, issuerPem, "issuer certificate");
  const serial = bytesToHex(new Uint8Array(cert.serialNumber.valueBlock.valueHexView));

  // Build and DER-encode the OCSP request (SHA-1 CertID per RFC 6960 §4.1.1).
  const ocspReq = new OCSPRequest();
  await ocspReq.createForCertificate(cert, { hashAlgorithm: "SHA-1", issuerCertificate: issuer });
  const requestDer = ocspReq.toSchema(true).toBER(false);

  const res = await fetch("/api/ocsp", {
    method: "POST",
    headers: { "Content-Type": "application/ocsp-request", Accept: "application/ocsp-response" },
    body: requestDer,
    credentials: "same-origin",
  });
  if (!res.ok) {
    throw new Error(`OCSP responder returned HTTP ${res.status}.`);
  }
  const responseDer = await res.arrayBuffer();

  const parsed = asn1js.fromBER(responseDer);
  if (parsed.offset === -1) throw new Error("Could not parse the OCSP response.");
  const ocspResp = new OCSPResponse({ schema: parsed.result });

  const responseStatus = ocspResp.responseStatus.valueBlock.valueDec;
  if (responseStatus !== 0) {
    const names: Record<number, string> = {
      1: "malformed request",
      2: "internal error",
      3: "try later",
      5: "signature required",
      6: "unauthorized",
    };
    throw new Error(`OCSP responder error: ${names[responseStatus] ?? `status ${responseStatus}`}.`);
  }
  if (!ocspResp.responseBytes) throw new Error("OCSP response carried no data.");

  const basic = new BasicOCSPResponse({
    schema: asn1js.fromBER(ocspResp.responseBytes.response.valueBlock.valueHexView).result,
  });
  const { status } = await basic.getCertificateStatus(cert, issuer);

  const single = basic.tbsResponseData.responses[0];
  const result: OcspResult = {
    status: status === 0 ? "good" : status === 1 ? "revoked" : "unknown",
    serial,
    producedAt: iso(basic.tbsResponseData.producedAt),
    thisUpdate: iso(single?.thisUpdate),
    nextUpdate: iso(single?.nextUpdate),
  };

  // Best-effort revocation detail: certStatus [1] RevokedInfo { revocationTime,
  // [0] revocationReason }.
  if (status === 1 && single) {
    try {
      const cs = single.certStatus as {
        valueBlock?: { value?: { toDate?: () => Date; valueBlock?: { valueDec?: number } }[] };
      };
      const parts = cs.valueBlock?.value ?? [];
      result.revocationTime = iso(parts[0]?.toDate?.());
      const reason = parts[1]?.valueBlock?.valueDec;
      if (reason != null) result.revocationReason = REVOCATION_REASONS[reason] ?? `Reason ${reason}`;
    } catch {
      // Leave revocation detail unset if the structure differs.
    }
  }
  return result;
}

function certFromPem(
  Certificate: typeof import("pkijs").Certificate,
  asn1js: typeof import("asn1js"),
  pem: string,
  label: string,
): InstanceType<typeof Certificate> {
  const b64 = pem
    .replace(/-----BEGIN[^-]+-----/g, "")
    .replace(/-----END[^-]+-----/g, "")
    .replace(/\s+/g, "");
  if (!b64) throw new Error(`Paste a PEM ${label}.`);
  let der: ArrayBuffer;
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    der = bytes.buffer;
  } catch {
    throw new Error(`The ${label} is not valid base64/PEM.`);
  }
  const asn = asn1js.fromBER(der);
  if (asn.offset === -1) throw new Error(`The ${label} is not a valid DER certificate.`);
  return new Certificate({ schema: asn.result });
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
