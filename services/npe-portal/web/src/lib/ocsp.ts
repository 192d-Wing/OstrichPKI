// Live OCSP (RFC 6960) revocation-status check, performed in the browser and
// proxied through the BFF to the OCSP responder. pkijs builds the request and
// parses the response; it is lazily imported so it stays out of the main bundle
// (shared with the CSR generator's pkijs chunk).
//
// The responder's signature is verified against the issuing CA's public key
// (the OstrichPKI responder signs directly with the CA key), so a tampered or
// forged response cannot report a false status.

import { bytesToHex, firstPemBlockToDer, hexToBytes } from "@/lib/pem";
import { revocationReasonLabel } from "@/lib/revocation";

export type OcspStatus = "good" | "revoked" | "unknown";

export interface OcspResult {
  status: OcspStatus;
  /** Hex serial of the certificate that was checked. */
  serial: string;
  producedAt?: string;
  thisUpdate?: string;
  nextUpdate?: string;
  revocationTime?: string;
  revocationReason?: string;
}

/** Either a pasted certificate PEM or a hex serial number to check. */
export type OcspQuery = { certPem: string } | { serialHex: string };

// SHA-1 algorithm OID for the OCSP CertID (RFC 6960 default).
const SHA1_OID = "1.3.14.3.2.26";

function iso(d: Date | undefined): string | undefined {
  return d ? d.toISOString().replace("T", " ").slice(0, 19) + " UTC" : undefined;
}

function statusFromTag(tag: number): OcspStatus {
  if (tag === 0) return "good";
  if (tag === 1) return "revoked";
  return "unknown";
}

const RESPONSE_STATUS_NAMES: Record<number, string> = {
  1: "malformed request",
  2: "internal error",
  3: "try later",
  5: "signature required",
  6: "unauthorized",
};

type Pkijs = typeof import("pkijs");
type Asn1js = typeof import("asn1js");

let engineReady = false;
function ensureEngine(pkijs: Pkijs) {
  if (engineReady) return;
  const wc = globalThis.crypto;
  if (!wc?.subtle) throw new Error("Web Crypto API is unavailable (a secure context / HTTPS is required).");
  pkijs.setEngine("webcrypto", wc, wc.subtle);
  engineReady = true;
}

function parseCert(pkijs: Pkijs, asn1js: Asn1js, pem: string, label: string) {
  const der = firstPemBlockToDer(pem);
  const asn = asn1js.fromBER(der);
  if (asn.offset === -1) throw new Error(`The ${label} is not a valid PEM/DER certificate.`);
  return new pkijs.Certificate({ schema: asn.result });
}

async function certIdFromSerial(
  pkijs: Pkijs,
  asn1js: Asn1js,
  issuer: InstanceType<Pkijs["Certificate"]>,
  serialHex: string,
) {
  const subtle = globalThis.crypto.subtle;
  const cid = new pkijs.CertID();
  cid.hashAlgorithm = new pkijs.AlgorithmIdentifier({ algorithmId: SHA1_OID });
  cid.issuerNameHash = new asn1js.OctetString({
    valueHex: await subtle.digest("SHA-1", issuer.subject.toSchema().toBER(false)),
  });
  cid.issuerKeyHash = new asn1js.OctetString({
    valueHex: await subtle.digest(
      "SHA-1",
      issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView as BufferSource,
    ),
  });
  cid.serialNumber = new asn1js.Integer({ valueHex: hexToBytes(serialHex).buffer as ArrayBuffer });
  return cid;
}

/**
 * Query the OCSP responder for `query`'s revocation status, using `issuerPem`
 * (the issuing CA certificate) to build the RFC 6960 CertID and to verify the
 * response signature. Throws on bad input, a non-successful responseStatus, or a
 * response whose signature does not verify against the issuer.
 */
export async function checkOcsp(query: OcspQuery, issuerPem: string): Promise<OcspResult> {
  const pkijs = await import("pkijs");
  const asn1js = await import("asn1js");
  ensureEngine(pkijs);

  const issuer = parseCert(pkijs, asn1js, issuerPem, "issuing CA certificate");

  let certID: InstanceType<Pkijs["CertID"]>;
  let serial: string;
  if ("certPem" in query) {
    const cert = parseCert(pkijs, asn1js, query.certPem, "certificate");
    serial = bytesToHex(new Uint8Array(cert.serialNumber.valueBlock.valueHexView));
    certID = new pkijs.CertID();
    await certID.createForCertificate(cert, { hashAlgorithm: "SHA-1", issuerCertificate: issuer });
  } else {
    serial = query.serialHex.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
    if (!serial) throw new Error("Enter a hex serial number.");
    certID = await certIdFromSerial(pkijs, asn1js, issuer, serial);
  }

  const ocspReq = new pkijs.OCSPRequest();
  ocspReq.tbsRequest.requestList = [new pkijs.Request({ reqCert: certID })];
  const requestDer = ocspReq.toSchema(true).toBER(false);

  const res = await fetch("/api/ocsp", {
    method: "POST",
    headers: { "Content-Type": "application/ocsp-request", Accept: "application/ocsp-response" },
    body: requestDer,
    credentials: "same-origin",
  });
  if (!res.ok) throw new Error(`OCSP responder returned HTTP ${res.status}.`);

  const parsed = asn1js.fromBER(await res.arrayBuffer());
  if (parsed.offset === -1) throw new Error("Could not parse the OCSP response.");
  const ocspResp = new pkijs.OCSPResponse({ schema: parsed.result });

  const responseStatus = ocspResp.responseStatus.valueBlock.valueDec;
  if (responseStatus !== 0) {
    const name = RESPONSE_STATUS_NAMES[responseStatus] ?? `status ${responseStatus}`;
    throw new Error(`OCSP responder error: ${name}.`);
  }
  if (!ocspResp.responseBytes) throw new Error("OCSP response carried no data.");

  const basic = new pkijs.BasicOCSPResponse({
    schema: asn1js.fromBER(ocspResp.responseBytes.response.valueBlock.valueHexView).result,
  });

  // Verify the responder's signature against the issuing CA's public key. The
  // OstrichPKI responder signs directly with the CA key, so a valid signature
  // here means the CA vouches for this status — a tampered response is rejected.
  const crypto = pkijs.getCrypto(true);
  const tbs = basic.tbsResponseData.toSchema().toBER(false);
  const sigOk = await crypto.verifyWithPublicKey(
    tbs,
    basic.signature,
    issuer.subjectPublicKeyInfo,
    basic.signatureAlgorithm,
  );
  if (!sigOk) {
    throw new Error(
      "The OCSP response signature did not verify against the issuing CA — the status is not trustworthy.",
    );
  }

  const single = basic.tbsResponseData.responses.find(
    (r) => bytesToHex(new Uint8Array(r.certID.serialNumber.valueBlock.valueHexView)) === serial,
  );
  if (!single) throw new Error("The responder returned no status for this certificate/serial.");

  const tag = single.certStatus.idBlock.tagNumber; // 0 good, 1 revoked, 2 unknown
  const result: OcspResult = {
    status: statusFromTag(tag),
    serial,
    producedAt: iso(basic.tbsResponseData.producedAt),
    thisUpdate: iso(single.thisUpdate),
    nextUpdate: iso(single.nextUpdate),
  };

  if (tag === 1) {
    // RevokedInfo [1] IMPLICIT SEQUENCE { revocationTime GeneralizedTime,
    //   revocationReason [0] EXPLICIT CRLReason OPTIONAL }
    const parts = (single.certStatus as { valueBlock: { value: unknown[] } }).valueBlock.value;
    const timeBlock = parts[0] as { toDate?: () => Date } | undefined;
    result.revocationTime = iso(timeBlock?.toDate?.());
    // reason is EXPLICITly [0]-tagged, so the ENUMERATED is nested one level.
    const reasonWrap = parts[1] as { valueBlock?: { value?: { valueBlock?: { valueDec?: number } }[] } } | undefined;
    const code = reasonWrap?.valueBlock?.value?.[0]?.valueBlock?.valueDec;
    if (code != null) result.revocationReason = revocationReasonLabel(code);
  }
  return result;
}
