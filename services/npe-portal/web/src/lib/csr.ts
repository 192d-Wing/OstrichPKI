// In-browser PKCS#10 CSR generation. The key pair is created with the Web
// Crypto API and the private key never leaves the browser — only the CSR is
// submitted. pkijs assembles and signs the CertificationRequest (subject,
// SubjectPublicKeyInfo, and a SAN extensionRequest attribute).

import * as asn1js from "asn1js";
import {
  Attribute,
  AttributeTypeAndValue,
  CertificationRequest,
  CryptoEngine,
  Extension,
  Extensions,
  GeneralName,
  GeneralNames,
  setEngine,
} from "pkijs";

export type CsrAlgorithm = "rsa-2048" | "rsa-3072" | "ecdsa-p256" | "ecdsa-p384";

export interface CsrSubject {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
}

export interface GeneratedCsr {
  /** PEM-encoded PKCS#10 certificate request. */
  csrPem: string;
  /** PEM-encoded PKCS#8 private key — shown once, never sent to the server. */
  privateKeyPem: string;
}

// X.500 attribute type OIDs.
const OID_CN = "2.5.4.3";
const OID_O = "2.5.4.10";
const OID_OU = "2.5.4.11";
const OID_C = "2.5.4.6";
// pkcs-9-at-extensionRequest (RFC 2985) and id-ce-subjectAltName (RFC 5280).
const OID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14";
const OID_SUBJECT_ALT_NAME = "2.5.29.17";

let engineReady = false;
function ensureEngine() {
  if (engineReady) return;
  const webcrypto = globalThis.crypto;
  if (!webcrypto?.subtle) {
    throw new Error("Web Crypto API is unavailable (a secure context / HTTPS is required).");
  }
  setEngine(
    "webcrypto",
    new CryptoEngine({ name: "webcrypto", crypto: webcrypto, subtle: webcrypto.subtle }),
  );
  engineReady = true;
}

interface AlgSpec {
  keyGen: RsaHashedKeyGenParams | EcKeyGenParams;
  hash: "SHA-256" | "SHA-384";
}

function algSpec(alg: CsrAlgorithm): AlgSpec {
  switch (alg) {
    case "rsa-2048":
      return {
        keyGen: {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        hash: "SHA-256",
      };
    case "rsa-3072":
      return {
        keyGen: {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 3072,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        hash: "SHA-256",
      };
    case "ecdsa-p256":
      return { keyGen: { name: "ECDSA", namedCurve: "P-256" }, hash: "SHA-256" };
    case "ecdsa-p384":
      return { keyGen: { name: "ECDSA", namedCurve: "P-384" }, hash: "SHA-384" };
  }
}

/** Parse a dotted IPv4 string into its 4 octets, or null if not valid IPv4. */
function ipv4ToBytes(value: string): Uint8Array | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!/^\d+$/.test(parts[i])) return null;
    const n = Number(parts[i]);
    if (n > 255) return null;
    bytes[i] = n;
  }
  return bytes;
}

/** Parse an IPv6 string into 16 octets (supports `::` compression), or null. */
function ipv6ToBytes(value: string): Uint8Array | null {
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const toGroups = (s: string): number[] | null => {
    if (s === "") return [];
    const out: number[] = [];
    for (const g of s.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      const n = Number.parseInt(g, 16);
      out.push((n >> 8) & 0xff, n & 0xff);
    }
    return out;
  };
  const head = toGroups(halves[0]);
  const tail = halves.length === 2 ? toGroups(halves[1]) : [];
  if (head === null || tail === null) return null;
  if (halves.length === 2) {
    // `::` fills the gap with zero bytes; total must be < 16 to leave room.
    if (head.length + tail.length >= 16) return null;
    const gap = new Array<number>(16 - head.length - tail.length).fill(0);
    return new Uint8Array([...head, ...gap, ...tail]);
  }
  return head.length === 16 ? new Uint8Array(head) : null;
}

/** Parse an IP SAN value (v4 or v6) into its network-order octets, or null. */
function ipToBytes(value: string): Uint8Array | null {
  return value.includes(":") ? ipv6ToBytes(value) : ipv4ToBytes(value);
}

interface MappedSans {
  names: GeneralName[];
  /** SAN tokens that could not be encoded (unsupported kind or bad value). */
  unsupported: string[];
}

// Map "TYPE:value" SAN tokens (as the form emits them) to X.509 GeneralNames.
// DNS/email/URI/IP (v4 and v6) are supported. Anything else — UPN/otherName,
// unknown kinds, or an unparseable IP — is returned in `unsupported` so the
// caller can fail loudly rather than silently dropping a requested name.
function sansToGeneralNames(sans: string[]): MappedSans {
  const names: GeneralName[] = [];
  const unsupported: string[] = [];
  for (const raw of sans) {
    const idx = raw.indexOf(":");
    const kind = idx >= 0 ? raw.slice(0, idx) : "DNS";
    const value = idx >= 0 ? raw.slice(idx + 1) : raw;
    switch (kind.toUpperCase()) {
      case "DNS":
        names.push(new GeneralName({ type: 2, value }));
        break;
      case "EMAIL":
        names.push(new GeneralName({ type: 1, value }));
        break;
      case "URI":
        names.push(new GeneralName({ type: 6, value }));
        break;
      case "IP": {
        const bytes = ipToBytes(value);
        if (bytes) {
          names.push(
            new GeneralName({
              type: 7,
              value: new asn1js.OctetString({ valueHex: bytes.buffer as ArrayBuffer }),
            }),
          );
        } else {
          unsupported.push(raw);
        }
        break;
      }
      default:
        unsupported.push(raw);
        break;
    }
  }
  return { names, unsupported };
}

function addRdn(csr: CertificationRequest, type: string, value: string, printable = false) {
  csr.subject.typesAndValues.push(
    new AttributeTypeAndValue({
      type,
      value: printable
        ? new asn1js.PrintableString({ value })
        : new asn1js.Utf8String({ value }),
    }),
  );
}

function derToPem(der: ArrayBuffer, label: string): string {
  const bytes = new Uint8Array(der);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  const b64 = btoa(binary);
  const wrapped = b64.match(/.{1,64}/g)?.join("\n") ?? b64;
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----\n`;
}

/**
 * Generate an RSA/ECDSA key pair in the browser and return a signed PKCS#10 CSR
 * plus the PKCS#8 private key (PEM). The private key is generated locally and is
 * the caller's responsibility to save — it is never transmitted.
 */
export async function generateCsr(
  subject: CsrSubject,
  sans: string[],
  algorithm: CsrAlgorithm,
): Promise<GeneratedCsr> {
  ensureEngine();
  const subtle = globalThis.crypto.subtle;
  const { keyGen, hash } = algSpec(algorithm);

  const keys = (await subtle.generateKey(keyGen, true, ["sign", "verify"])) as CryptoKeyPair;

  const pkcs10 = new CertificationRequest();
  pkcs10.version = 0;
  addRdn(pkcs10, OID_CN, subject.commonName);
  if (subject.organization) addRdn(pkcs10, OID_O, subject.organization);
  if (subject.organizationalUnit) addRdn(pkcs10, OID_OU, subject.organizationalUnit);
  if (subject.country) addRdn(pkcs10, OID_C, subject.country, true);

  await pkcs10.subjectPublicKeyInfo.importKey(keys.publicKey);

  const { names: generalNames, unsupported } = sansToGeneralNames(sans);
  if (unsupported.length > 0) {
    // Fail loudly rather than issuing a CSR missing a requested name. UPN and
    // other otherName SANs aren't supported by the in-browser generator.
    throw new Error(
      `These Subject Alternative Names can't be included by the in-browser generator: ${unsupported.join(
        ", ",
      )}. Remove them, or paste a CSR generated with full tooling instead.`,
    );
  }
  if (generalNames.length > 0) {
    const altNames = new GeneralNames({ names: generalNames });
    const extensions = new Extensions({
      extensions: [
        new Extension({
          extnID: OID_SUBJECT_ALT_NAME,
          critical: false,
          extnValue: altNames.toSchema().toBER(false),
        }),
      ],
    });
    pkcs10.attributes = [
      new Attribute({ type: OID_EXTENSION_REQUEST, values: [extensions.toSchema()] }),
    ];
  }

  await pkcs10.sign(keys.privateKey, hash);

  const csrPem = derToPem(pkcs10.toSchema().toBER(false), "CERTIFICATE REQUEST");
  const pkcs8 = await subtle.exportKey("pkcs8", keys.privateKey);
  const privateKeyPem = derToPem(pkcs8, "PRIVATE KEY");
  return { csrPem, privateKeyPem };
}
